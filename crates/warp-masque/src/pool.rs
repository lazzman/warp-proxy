//! 多账号连接池。每个账号一条 MASQUE 隧道和一个出口地址，前面用同一入口做调度。
//!
//! 上游 SOCKS5、黏性、排空队列和保身份重启都发生在这个进程里。
//! 账号身份保存在各自的 WarpConfig 中；保身份重启只重连隧道，不重新注册。

use std::collections::hash_map::RandomState;
use std::collections::{HashSet, VecDeque};
use std::hash::BuildHasher;
use std::net::{Ipv4Addr, SocketAddr};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, RwLock, Weak};
use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};
use tokio::sync::{mpsc, oneshot, watch, Notify, Semaphore};

use crate::config::DEFAULT_ENDPOINT_H2_V4;
use crate::console::Console;
use crate::netstack::{self, NetHandle, ResolvePreference};
use crate::register::{RegisterOptions, RegistrationClient};
use crate::schedule::{PickFail, Policy, Scheduler};
use crate::trace::TraceInfo;
use crate::tunnel::{Transport, Tunnel};
use crate::upstream::{UpstreamProxy, UpstreamSet};
use crate::{DeviceKeypair, WarpConfig};

const MAX_BACKOFF: Duration = Duration::from_secs(30);
const CONNECT_CONCURRENCY: usize = 4;
// 精确去重身份需要内存；限制单实例的用户阈值以防长期运行时无限累积。
const MAX_RESTART_USERS: usize = 1_000_000;

#[cfg(test)]
mod deferred_start_tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::{TcpListener, TcpStream};

    async fn request(addr: SocketAddr, path: &str, token: Option<&str>) -> String {
        let mut connection = TcpStream::connect(addr).await.unwrap();
        let token = token
            .map(|token| format!("X-Warp-Token: {token}\r\n"))
            .unwrap_or_default();
        connection
            .write_all(format!("GET {path} HTTP/1.1\r\nHost: localhost\r\n{token}\r\n").as_bytes())
            .await
            .unwrap();
        let mut response = String::new();
        tokio::time::timeout(
            Duration::from_secs(1),
            connection.read_to_string(&mut response),
        )
        .await
        .unwrap()
        .unwrap();
        response
    }

    #[tokio::test]
    async fn panel_and_status_work_while_connections_are_waiting() {
        let pool = Pool::start_deferred(PoolOptions::basic(false), 2).unwrap();
        let permit = pool
            .connect_limit
            .acquire_many(CONNECT_CONCURRENCY as u32)
            .await
            .unwrap();
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let server = tokio::spawn(crate::control::serve(
            listener,
            pool.clone(),
            "secret".into(),
        ));

        assert!(request(addr, "/", None)
            .await
            .contains("<title>warp-proxy</title>"));
        let status = request(addr, "/api/status", Some("secret")).await;
        assert!(status.contains("\"initializing\":true"));
        assert!(status.contains("\"expected_accounts\":2"));

        pool.attach_base_account(1, WarpConfig::default())
            .await
            .unwrap();
        let current = pool.status();
        assert_eq!(current.accounts.len(), 1);
        assert_eq!(current.accounts[0].health, "connecting");
        assert!(!current.accounts[0].ready);
        let status = request(addr, "/api/status", Some("secret")).await;
        assert!(status.contains("\"health\":\"connecting\""));

        server.abort();
        drop(permit);
        drop(pool);
    }

    #[tokio::test]
    async fn pending_base_accounts_keep_their_restore_slots() {
        let dir = std::env::temp_dir().join(format!(
            "warp-proxy-pending-base-{}-{}",
            std::process::id(),
            crate::console::unix_ms()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        WarpConfig::default().save(account_path(&dir, 3)).unwrap();
        remember_saved_temporary(&dir, 3).unwrap();

        let mut options = PoolOptions::basic(false);
        options.state_dir = Some(dir.clone());
        options.auto_restore_limit = Some(2);
        let pool = Pool::start_deferred(options, 2).unwrap();
        pool.restore_temporary().await;
        assert!(pool.status().accounts.is_empty());
        pool.finish_initialization().await;
        assert!(pool.status().accounts.is_empty());
        pool.restore_temporary().await;
        assert_eq!(pool.status().accounts.len(), 1);

        drop(pool);
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[tokio::test]
    async fn initial_connection_failure_shows_retrying_status() {
        let pool = Pool::start_deferred(PoolOptions::basic(false), 1).unwrap();
        pool.attach_base_account(1, WarpConfig::default())
            .await
            .unwrap();
        tokio::time::timeout(Duration::from_secs(1), async {
            loop {
                if pool.status().accounts[0].health == "retrying" {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .unwrap();
        assert!(!pool.status().accounts[0].ready);
    }

    #[tokio::test]
    async fn background_accounts_keep_numeric_order() {
        let pool = Pool::start_deferred(PoolOptions::basic(false), 3).unwrap();
        for id in [3, 1, 2] {
            pool.attach_base_account(id, WarpConfig::default())
                .await
                .unwrap();
        }
        let ids: Vec<_> = pool
            .status()
            .accounts
            .iter()
            .map(|account| account.id)
            .collect();
        assert_eq!(ids, [1, 2, 3]);
    }
}
const MIN_ROTATE_SECS: u64 = 60;

/// 入口代理的用户名密码。SOCKS5 和 HTTP 共用。
#[derive(Clone)]
pub struct ProxyAuth {
    pub username: String,
    pub password: String,
}

/// 三种自动重启触发条件可以同时启用，0 表示禁用该条件。
/// 自动排空等待已有连接自然结束，只有实际重连和探测受并发名额限制。
#[derive(Clone, Debug)]
pub struct RestartConfig {
    pub max_uptime: Duration,
    pub max_users: usize,
    pub max_connections: u64,
    pub drain_check_interval: Duration,
    pub probe_timeout: Duration,
    pub concurrency: usize,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct RestartPolicy {
    max_uptime: Duration,
    max_users: usize,
    max_connections: u64,
}

impl RestartPolicy {
    fn from_config(config: &RestartConfig) -> Self {
        Self {
            max_uptime: config.max_uptime,
            max_users: config.max_users,
            max_connections: config.max_connections,
        }
    }

    fn is_disabled(self) -> bool {
        self.max_uptime.is_zero() && self.max_users == 0 && self.max_connections == 0
    }
}

impl Default for RestartConfig {
    fn default() -> Self {
        Self {
            max_uptime: Duration::ZERO,
            max_users: 0,
            max_connections: 0,
            drain_check_interval: Duration::from_secs(10),
            probe_timeout: Duration::from_secs(90),
            concurrency: 1,
        }
    }
}

/// 建池参数。未设置上游时行为和原来的 Pool::new 一致。
#[derive(Clone)]
pub struct PoolOptions {
    pub http2: bool,
    pub upstream: UpstreamSet,
    pub upstream_probe_timeout: Duration,
    pub policy: Policy,
    pub resolve: ResolvePreference,
    pub auth: Option<ProxyAuth>,
    pub mixed: bool,
    pub access_log: bool,
    pub restart: RestartConfig,
    /// 经隧道访问 cdn-cgi/trace 的间隔。0 表示关闭。
    pub health_interval: Duration,
    /// 单次出口检查的最长时间。
    pub health_timeout: Duration,
    pub device_name: String,
    pub state_dir: Option<PathBuf>,
    /// 自动恢复实例的数量上限；手动添加账号不受影响。
    pub auto_restore_limit: Option<usize>,
}

impl PoolOptions {
    pub fn basic(http2: bool) -> Self {
        Self {
            http2,
            upstream: UpstreamSet::default(),
            upstream_probe_timeout: Duration::from_secs(8),
            policy: Policy::default(),
            resolve: ResolvePreference::Ipv4Only,
            auth: None,
            mixed: false,
            access_log: false,
            restart: RestartConfig::default(),
            health_interval: Duration::from_secs(60),
            health_timeout: Duration::from_secs(20),
            device_name: "warp-proxy".into(),
            state_dir: None,
            auto_restore_limit: None,
        }
    }
}

struct RestartJob {
    reply: oneshot::Sender<Result<(), String>>,
    probe_timeout: Duration,
}

/// 一个账号：配置、隧道、以及当前是否接新连接。
pub struct Worker {
    id: usize,
    rebuild: Notify,
    restart_tx: mpsc::UnboundedSender<RestartJob>,
    draining: AtomicBool,
    restart_pending: AtomicBool,
    restart_busy: AtomicBool,
    restart_attempted: AtomicBool,
    usage: Mutex<RestartUsage>,
    user_hash: RandomState,
    active: AtomicUsize,
    /// 人工停用后不再接新连接，已有连接继续走完。
    manual: AtomicBool,
    temporary: AtomicBool,
    /// 已从池中移除。监督任务看到后退出，避免同一身份再建一条隧道。
    stopped: AtomicBool,
    stop_notify: Notify,
    /// 曾经确认过 warp=on 或 warp=plus。之后的出口检查失败不会拆隧道。
    warp_ready: AtomicBool,
    /// 实例进入排空后冻结旧隧道：监督器不得执行其他主动重建操作。
    drain_finished: Notify,
    ready_since: Mutex<Option<Instant>>,
    stage: Mutex<String>,
    stage_at: Mutex<Option<Instant>>,
    last_action: Mutex<String>,
    upstream: Option<UpstreamProxy>,
    inner: Mutex<WorkerInner>,
}

#[derive(Default)]
struct RestartUsage {
    connections: u64,
    identities: HashSet<u64>,
}

impl RestartUsage {
    fn reached(&self, policy: RestartPolicy) -> bool {
        (policy.max_users > 0 && self.identities.len() >= policy.max_users)
            || (policy.max_connections > 0 && self.connections >= policy.max_connections)
    }
}

struct WorkerInner {
    config: WarpConfig,
    net: Option<NetHandle>,
    tunnel: Option<Tunnel>,
    dead: Option<watch::Receiver<bool>>,
    assigned_v4: Ipv4Addr,
    egress_v4: Option<TraceInfo>,
    egress_v6: Option<TraceInfo>,
}

impl Worker {
    fn new(
        id: usize,
        config: WarpConfig,
        upstream: Option<UpstreamProxy>,
    ) -> (Arc<Worker>, mpsc::UnboundedReceiver<RestartJob>) {
        let (restart_tx, restart_rx) = mpsc::unbounded_channel();
        let worker = Arc::new(Worker {
            id,
            rebuild: Notify::new(),
            restart_tx,
            draining: AtomicBool::new(false),
            restart_pending: AtomicBool::new(false),
            restart_busy: AtomicBool::new(false),
            restart_attempted: AtomicBool::new(false),
            usage: Mutex::new(RestartUsage::default()),
            user_hash: RandomState::new(),
            active: AtomicUsize::new(0),
            manual: AtomicBool::new(true),
            temporary: AtomicBool::new(false),
            stopped: AtomicBool::new(false),
            stop_notify: Notify::new(),
            warp_ready: AtomicBool::new(false),
            drain_finished: Notify::new(),
            ready_since: Mutex::new(None),
            stage: Mutex::new(String::new()),
            stage_at: Mutex::new(None),
            last_action: Mutex::new(String::new()),
            upstream,
            inner: Mutex::new(WorkerInner {
                config,
                net: None,
                tunnel: None,
                dead: None,
                assigned_v4: Ipv4Addr::UNSPECIFIED,
                egress_v4: None,
                egress_v6: None,
            }),
        });
        (worker, restart_rx)
    }

    pub fn net(&self) -> Option<NetHandle> {
        self.inner.lock().unwrap().net.clone()
    }

    fn dead_signal(&self) -> Option<watch::Receiver<bool>> {
        self.inner.lock().unwrap().dead.clone()
    }

    fn clear_net(&self) {
        self.warp_ready.store(false, Ordering::Relaxed);
        let mut inner = self.inner.lock().unwrap();
        inner.net = None;
        inner.dead = None;
        inner.egress_v4 = None;
        inner.egress_v6 = None;
    }

    fn retire(&self) {
        let mut inner = self.inner.lock().unwrap();
        self.retire_inner(&mut inner);
    }

    fn retire_if_not_pending(&self) {
        let mut inner = self.inner.lock().unwrap();
        if !self.restart_pending.load(Ordering::Acquire) {
            self.retire_inner(&mut inner);
        }
    }

    fn retire_inner(&self, inner: &mut WorkerInner) {
        self.warp_ready.store(false, Ordering::Relaxed);
        inner.net = None;
        inner.dead = None;
        inner.tunnel = None;
        inner.egress_v4 = None;
        inner.egress_v6 = None;
    }

    fn set_egress(&self, v4: TraceInfo, v6: TraceInfo) {
        if warp_confirmed(&v4) || warp_confirmed(&v6) {
            self.warp_ready.store(true, Ordering::Relaxed);
        }
        let mut inner = self.inner.lock().unwrap();
        inner.egress_v4 = Some(v4);
        inner.egress_v6 = Some(v6);
    }

    fn is_ready(&self) -> bool {
        self.manual.load(Ordering::Relaxed)
            && !self.stopped.load(Ordering::Relaxed)
            && !self.restart_pending.load(Ordering::Relaxed)
            && !self.draining.load(Ordering::Relaxed)
            && !self.restart_busy.load(Ordering::Relaxed)
            && self.inner.lock().unwrap().net.is_some()
    }

    fn user_identity(&self, username: Option<&str>, client_ip: &str) -> u64 {
        let (kind, user) = match username.filter(|user| !user.is_empty()) {
            Some(user) => ("user", user),
            None => ("ip", client_ip),
        };
        self.user_hash.hash_one((kind, user))
    }

    fn begin_draining(&self) {
        let _inner = self.inner.lock().unwrap();
        self.draining.store(true, Ordering::Relaxed);
    }

    fn uptime(&self) -> Duration {
        self.ready_since
            .lock()
            .unwrap()
            .map(|started| started.elapsed())
            .unwrap_or_default()
    }

    fn mark_initial_ready(&self) {
        let mut started = self.ready_since.lock().unwrap();
        if started.is_none() {
            *started = Some(Instant::now());
        }
    }

    fn queue_if_reached(&self, usage: &RestartUsage, policy: RestartPolicy) -> bool {
        if self.restart_pending.load(Ordering::Relaxed)
            || self.restart_busy.load(Ordering::Relaxed)
            || self.draining.load(Ordering::Relaxed)
            || self.stopped.load(Ordering::Relaxed)
            || !(usage.reached(policy)
                || (!policy.max_uptime.is_zero()
                    && self.ready_since.lock().unwrap().is_some()
                    && self.uptime() >= policy.max_uptime))
        {
            return false;
        }
        self.restart_pending.store(true, Ordering::Relaxed);
        self.draining.store(true, Ordering::Relaxed);
        self.set_stage("等待现有连接排空");
        self.note("达到重启条件，停止接入新连接");
        true
    }

    fn reset_usage(&self) {
        let _inner = self.inner.lock().unwrap();
        *self.usage.lock().unwrap() = RestartUsage::default();
        *self.ready_since.lock().unwrap() = Some(Instant::now());
        self.restart_pending.store(false, Ordering::Relaxed);
        self.restart_attempted.store(false, Ordering::Relaxed);
        self.draining.store(false, Ordering::Relaxed);
        self.drain_finished.notify_one();
    }

    /// 只取消尚未取得执行权的自动重启；保留手动重启和已经开始的重连。
    fn cancel_queued_restart(&self) -> bool {
        let inner = self.inner.lock().unwrap();
        let mut usage = self.usage.lock().unwrap();
        if !self.restart_pending.load(Ordering::Acquire)
            || self.restart_busy.load(Ordering::Acquire)
            || self.restart_attempted.load(Ordering::Acquire)
            || self.stopped.load(Ordering::Relaxed)
        {
            return false;
        }
        // 旧隧道仍可用才恢复接入；隧道已断开或尚未验证时交给监督器恢复。
        let reusable = inner.net.is_some()
            && self.warp_ready.load(Ordering::Relaxed)
            && !inner.dead.as_ref().is_some_and(|dead| *dead.borrow());
        // 取消一次排队意味着结束这一轮计数；否则重新开启旧阈值会立即再次摘流。
        *usage = RestartUsage::default();
        *self.ready_since.lock().unwrap() = reusable.then(Instant::now);
        self.restart_pending.store(false, Ordering::Release);
        self.draining.store(!reusable, Ordering::Release);
        self.clear_stage();
        self.note("已取消待执行的自动重启");
        self.drain_finished.notify_one();
        true
    }

    fn set_stage(&self, stage: &str) {
        *self.stage.lock().unwrap() = stage.to_string();
        *self.stage_at.lock().unwrap() = Some(Instant::now());
    }

    fn clear_stage(&self) {
        self.stage.lock().unwrap().clear();
        *self.stage_at.lock().unwrap() = None;
    }

    fn note(&self, action: &str) {
        *self.last_action.lock().unwrap() = action.to_string();
    }
}

/// 已经分配到某个账号的入口连接。丢弃时减少该账号的活跃计数。
pub struct ConnLease {
    pub worker_id: usize,
    /// 地址族还没确定时的出口，优先 IPv4。
    pub egress: String,
    egress_v4: String,
    egress_v6: String,
    net: NetHandle,
    worker: Arc<Worker>,
}

impl ConnLease {
    pub fn net(&self) -> &NetHandle {
        &self.net
    }

    /// 按这次连接实际走到的地址族选择出口。
    pub fn egress_for(&self, family: &str) -> &str {
        egress_for_family(family, &self.egress_v4, &self.egress_v6, &self.egress)
    }

    pub(crate) fn egress_v4(&self) -> &str {
        &self.egress_v4
    }

    pub(crate) fn egress_v6(&self) -> &str {
        &self.egress_v6
    }
}

#[cfg(test)]
pub(crate) fn test_lease(fallback: &str, v4: &str, v6: &str) -> ConnLease {
    let (worker, _restart) = Worker::new(1, WarpConfig::default(), None);
    worker.active.fetch_add(1, Ordering::Relaxed);
    ConnLease {
        worker_id: 1,
        egress: fallback.to_string(),
        egress_v4: v4.to_string(),
        egress_v6: v6.to_string(),
        net: NetHandle::test_handle(),
        worker,
    }
}

impl Drop for ConnLease {
    fn drop(&mut self) {
        self.worker.active.fetch_sub(1, Ordering::Relaxed);
    }
}

#[derive(Default)]
struct RestartQueues {
    draining: VecDeque<usize>,
    ready: VecDeque<usize>,
}

/// 账号池和入口调度状态。
pub struct Pool {
    workers: Mutex<Vec<Arc<Worker>>>,
    initializing: AtomicBool,
    expected_accounts: usize,
    enabled: AtomicBool,
    http2: AtomicBool,
    next_id: AtomicUsize,
    rotate_secs: AtomicU64,
    device_name: String,
    upstream: UpstreamSet,
    resolve: ResolvePreference,
    auth: Option<ProxyAuth>,
    mixed: bool,
    access_log: bool,
    policy: Policy,
    scheduler: Scheduler,
    restart: RestartConfig,
    restart_policy: RwLock<RestartPolicy>,
    restart_queues: Mutex<RestartQueues>,
    health_interval: Duration,
    health_timeout: Duration,
    restart_limit: Arc<Semaphore>,
    connect_limit: Arc<Semaphore>,
    restart_wake: Arc<Notify>,
    console: Console,
    listen: Mutex<String>,
    state_dir: Option<PathBuf>,
    auto_restore_limit: Option<usize>,
    /// 启动时由 INSTANCE_COUNT 加载的账号。这些身份不会被临时实例重复占用。
    base_ids: Mutex<Vec<usize>>,
    /// 正在添加、尚未进入 workers 的编号，避免并发添加用到同一个已保存身份。
    reserved_ids: Mutex<Vec<usize>>,
}

impl Pool {
    /// 用默认策略建立连接池。不会配置上游。
    pub async fn new(configs: Vec<WarpConfig>, http2: bool) -> Arc<Pool> {
        match Self::start(configs, PoolOptions::basic(http2)).await {
            Ok(pool) => pool,
            Err(err) => panic!("基础连接池启动失败: {err}"),
        }
    }

    /// 按 opts 建池。配置了上游时先探测 SOCKS5 CONNECT，失败则直接返回，不改走直连。
    pub async fn start(configs: Vec<WarpConfig>, opts: PoolOptions) -> crate::Result<Arc<Pool>> {
        if !opts.upstream.is_empty() && !opts.http2 {
            return Err(crate::Error::Config(
                "上游 SOCKS5 只支持 TCP，必须使用 HTTP/2（--http2）".into(),
            ));
        }
        if !opts.upstream.is_empty() {
            opts.upstream
                .probe(probe_target(&configs), opts.upstream_probe_timeout)
                .await
                .map_err(crate::Error::Config)?;
        }
        let pool = Self::create(opts, configs.len())?;
        for cfg in configs {
            let id = pool.next_id.fetch_add(1, Ordering::Relaxed);
            let upstream = pool.upstream.for_index(id.saturating_sub(1));
            let (worker, jobs) = Worker::new(id, cfg, upstream);
            pool.workers.lock().unwrap().push(worker.clone());
            if let Err(err) = pool.build_tunnel(&worker).await {
                let text = format!("[pool] 账号 {id} 初次连接失败: {err}");
                eprintln!("{text}");
                pool.console.log("account", text);
            } else {
                let (v4, v6) = {
                    let inner = worker.inner.lock().unwrap();
                    (inner.assigned_v4.to_string(), inner.config.ipv6.clone())
                };
                pool.console.log(
                    "account",
                    format!("[pool] 账号 {id} 隧道已连接，IPv4 {v4}，IPv6 {v6}"),
                );
            }
            Pool::spawn_supervisor(pool.clone(), worker, jobs);
        }
        {
            let ids: Vec<usize> = pool.snapshot().iter().map(|worker| worker.id).collect();
            *pool.base_ids.lock().unwrap() = ids;
        }
        pool.restore_temporary().await;
        Self::spawn_tasks(&pool);
        Ok(pool)
    }

    /// 先建立可用的控制面，账号可随后逐个加载并在后台并发拨号。
    pub fn start_deferred(opts: PoolOptions, base_count: usize) -> crate::Result<Arc<Pool>> {
        let pool = Self::create(opts, base_count)?;
        *pool.base_ids.lock().unwrap() = (1..=base_count).collect();
        pool.next_id
            .store(base_count.saturating_add(1), Ordering::Relaxed);
        pool.initializing.store(true, Ordering::Relaxed);
        Self::spawn_tasks(&pool);
        Ok(pool)
    }

    pub async fn attach_base_account(
        self: &Arc<Self>,
        id: usize,
        config: WarpConfig,
    ) -> crate::Result<()> {
        let is_base = self.base_ids.lock().unwrap().contains(&id);
        if !is_base || self.snapshot().iter().any(|worker| worker.id == id) {
            return Err(crate::Error::Config(format!("无效或重复的基础账号 {id}")));
        }
        self.attach_account(
            id,
            config,
            false,
            "加载已保存的账号",
            &format!("已加载账号 {id}"),
        )
        .await
    }

    pub async fn finish_initialization(self: &Arc<Self>) {
        self.restore_temporary().await;
        self.initializing.store(false, Ordering::Relaxed);
        self.console
            .log("account", "初始账号加载完成，连接在后台继续进行");
    }

    pub fn log_initialization(&self, message: impl Into<String>) {
        let message = message.into();
        eprintln!("[warp-proxy] {message}");
        self.console.log("account", message);
    }

    fn create(opts: PoolOptions, expected_accounts: usize) -> crate::Result<Arc<Pool>> {
        if opts.restart.max_users > MAX_RESTART_USERS {
            return Err(crate::Error::Config(format!(
                "单实例累计用户阈值不能超过 {MAX_RESTART_USERS}，以限制内存占用"
            )));
        }
        if opts.restart.drain_check_interval.is_zero() {
            return Err(crate::Error::Config("排空检测间隔必须大于 0".into()));
        }
        if !opts.upstream.is_empty() && !opts.http2 {
            return Err(crate::Error::Config(
                "上游 SOCKS5 只支持 TCP，必须使用 HTTP/2（--http2）".into(),
            ));
        }
        let pool = Arc::new(Pool {
            workers: Mutex::new(Vec::new()),
            initializing: AtomicBool::new(false),
            expected_accounts,
            enabled: AtomicBool::new(true),
            http2: AtomicBool::new(opts.http2),
            next_id: AtomicUsize::new(1),
            rotate_secs: AtomicU64::new(0),
            device_name: opts.device_name,
            upstream: opts.upstream,
            resolve: opts.resolve,
            auth: opts.auth,
            mixed: opts.mixed,
            access_log: opts.access_log,
            policy: opts.policy,
            scheduler: Scheduler::new(),
            restart: opts.restart.clone(),
            restart_policy: RwLock::new(RestartPolicy::from_config(&opts.restart)),
            restart_queues: Mutex::new(RestartQueues::default()),
            health_interval: opts.health_interval,
            health_timeout: opts.health_timeout,
            restart_limit: Arc::new(Semaphore::new(opts.restart.concurrency.max(1))),
            connect_limit: Arc::new(Semaphore::new(CONNECT_CONCURRENCY)),
            restart_wake: Arc::new(Notify::new()),
            console: Console::new(),
            listen: Mutex::new(String::new()),
            state_dir: opts.state_dir.clone(),
            auto_restore_limit: opts.auto_restore_limit,
            base_ids: Mutex::new(Vec::new()),
            reserved_ids: Mutex::new(Vec::new()),
        });
        Ok(pool)
    }

    fn spawn_tasks(pool: &Arc<Pool>) {
        Pool::spawn_rotator(pool.clone());
        Pool::spawn_restarter(pool.clone());
    }

    fn transport(&self) -> Transport {
        if self.http2.load(Ordering::Relaxed) {
            Transport::Http2
        } else {
            Transport::Http3
        }
    }

    fn snapshot(&self) -> Vec<Arc<Worker>> {
        self.workers.lock().unwrap().clone()
    }

    async fn build_tunnel(&self, worker: &Arc<Worker>) -> crate::Result<()> {
        let config = worker.inner.lock().unwrap().config.clone();
        let key = DeviceKeypair::from_private_b64(&config.private_key)?;
        let tunnel =
            Tunnel::connect_via(&config, &key, self.transport(), worker.upstream.as_ref()).await?;
        let v4 = tunnel.assigned_v4();
        let dead = tunnel.dead_signal();
        let net = netstack::spawn_with(tunnel.io(), v4, tunnel.assigned_v6(), self.resolve);
        let mut inner = worker.inner.lock().unwrap();
        inner.tunnel = Some(tunnel);
        inner.net = Some(net);
        inner.assigned_v4 = v4;
        inner.dead = Some(dead);
        Ok(())
    }

    fn spawn_supervisor(
        pool: Arc<Pool>,
        worker: Arc<Worker>,
        jobs: mpsc::UnboundedReceiver<RestartJob>,
    ) {
        let weak = Arc::downgrade(&pool);
        drop(pool);
        tokio::spawn(async move {
            supervise(weak, worker, jobs).await;
        });
    }

    fn spawn_rotator(pool: Arc<Pool>) {
        let weak = Arc::downgrade(&pool);
        drop(pool);
        tokio::spawn(async move {
            let mut index = 0usize;
            loop {
                let secs = match weak.upgrade() {
                    Some(pool) => pool.rotate_secs.load(Ordering::Relaxed),
                    None => return,
                };
                if secs == 0 {
                    tokio::time::sleep(Duration::from_secs(5)).await;
                    continue;
                }
                tokio::time::sleep(Duration::from_secs(secs)).await;
                let Some(pool) = weak.upgrade() else { return };
                if pool.rotate_secs.load(Ordering::Relaxed) == 0 {
                    continue;
                }
                let ids: Vec<usize> = pool.snapshot().iter().map(|worker| worker.id).collect();
                if ids.is_empty() {
                    continue;
                }
                let id = ids[index % ids.len()];
                index += 1;
                eprintln!("[pool] 重新注册账号 {id} 以更换出口");
                if let Err(err) = pool.rotate(id).await {
                    eprintln!("[pool] 账号 {id} 换出口失败: {err}");
                }
            }
        });
    }

    fn spawn_restarter(pool: Arc<Pool>) {
        let weak = Arc::downgrade(&pool);
        let wake = Arc::clone(&pool.restart_wake);
        let interval = pool.restart.drain_check_interval;
        drop(pool);
        tokio::spawn(async move {
            let mut ticker = tokio::time::interval(interval);
            ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
            loop {
                tokio::select! {
                    _ = ticker.tick() => {},
                    _ = wake.notified() => {},
                }
                let Some(pool) = weak.upgrade() else { return };
                pool.inspect_restart_queues();
            }
        });
    }

    fn queue_threshold_restart(&self, id: usize) {
        let mut queues = self.restart_queues.lock().unwrap();
        if !queues.draining.contains(&id) && !queues.ready.contains(&id) {
            queues.draining.push_back(id);
        }
        drop(queues);
        self.scheduler.forget_users(id);
        let text = format!("[pool] 账号 {id} 达到重启条件，停止接入新连接并进入排空队列");
        eprintln!("{text}");
        self.console.log("plan", text);
        if let Some(worker) = self.snapshot().into_iter().find(|worker| worker.id == id) {
            worker.drain_finished.notify_one();
        }
        self.restart_wake.notify_one();
    }

    /// 外部操作要触碰隧道时先判断是否处于自动排空，避免打断已有连接。
    fn may_rebuild(&self, id: usize) -> bool {
        self.snapshot().into_iter().any(|worker| {
            worker.id == id
                && !worker.stopped.load(Ordering::Relaxed)
                && !worker.restart_pending.load(Ordering::Relaxed)
        })
    }

    fn inspect_restart_queues(self: &Arc<Self>) {
        // 修改阈值、取消待执行任务与取得重启名额必须串行。
        let policy_guard = self.restart_policy.read().unwrap();
        let workers = self.snapshot();
        // 持有策略读锁直至队列调度结束，避免关闭阈值和领取名额交错。
        let policy = *policy_guard;
        for worker in &workers {
            let inner = worker.inner.lock().unwrap();
            let usage = worker.usage.lock().unwrap();
            let queued = inner.net.is_some() && worker.queue_if_reached(&usage, policy);
            drop(usage);
            drop(inner);
            if queued {
                self.queue_threshold_restart(worker.id);
            }
        }
        let mut queues = self.restart_queues.lock().unwrap();
        let draining = queues.draining.len();
        for _ in 0..draining {
            let id = queues.draining.pop_front().unwrap();
            let worker = workers.iter().find(|worker| worker.id == id);
            match worker {
                Some(worker)
                    if worker.restart_pending.load(Ordering::Relaxed)
                        && !worker.stopped.load(Ordering::Relaxed)
                        && !worker.restart_attempted.load(Ordering::Relaxed) =>
                {
                    if worker.active.load(Ordering::Relaxed) == 0
                        && !worker.restart_busy.load(Ordering::Relaxed)
                    {
                        worker.set_stage("等待重启名额");
                        queues.ready.push_back(id);
                    } else {
                        queues.draining.push_back(id);
                    }
                }
                _ => {}
            }
        }

        let mut jobs = Vec::new();
        let ready_count = queues.ready.len();
        for _ in 0..ready_count {
            let Ok(permit) = self.restart_limit.clone().try_acquire_owned() else {
                break;
            };
            let id = queues.ready.pop_front().unwrap();
            let Some(worker) = workers.iter().find(|worker| worker.id == id) else {
                continue;
            };
            if !worker.restart_pending.load(Ordering::Relaxed)
                || worker.stopped.load(Ordering::Relaxed)
                || worker.restart_attempted.load(Ordering::Relaxed)
            {
                continue;
            }
            if worker.restart_busy.swap(true, Ordering::AcqRel) {
                queues.ready.push_back(id);
                continue;
            }
            // 自动重启无论排队多久，都必须在执行前再次核对没有活跃连接。
            if worker.active.load(Ordering::Acquire) != 0 {
                worker.restart_busy.store(false, Ordering::Release);
                queues.draining.push_back(id);
                continue;
            }
            jobs.push((worker.clone(), permit));
        }
        drop(queues);
        drop(policy_guard);

        for (worker, permit) in jobs {
            let pool = Arc::clone(self);
            tokio::spawn(async move {
                let id = worker.id;
                if let Err(err) = pool.restart_one_permitted(&worker).await {
                    pool.console
                        .log("plan", format!("账号 {id} 重启失败: {err}"));
                }
                worker.restart_busy.store(false, Ordering::Release);
                drop(permit);
                pool.restart_wake.notify_one();
            });
        }
    }

    pub fn enabled(&self) -> bool {
        self.enabled.load(Ordering::Relaxed)
    }

    pub fn set_enabled(&self, on: bool) {
        self.enabled.store(on, Ordering::Relaxed);
    }

    pub fn mixed(&self) -> bool {
        self.mixed
    }

    pub fn access_log(&self) -> bool {
        self.access_log
    }

    pub fn proxy_auth(&self) -> Option<(String, String)> {
        self.auth
            .as_ref()
            .map(|auth| (auth.username.clone(), auth.password.clone()))
    }

    /// 为新连接选择账号。排空实例不能再获得新请求，旧黏性关系自动迁往其他可用实例。
    pub fn checkout(&self, username: Option<&str>, client_ip: &str) -> Result<ConnLease, PickFail> {
        let workers = self.snapshot();
        let mut eligible: Vec<usize> = workers
            .iter()
            .filter(|worker| worker.is_ready())
            .map(|worker| worker.id)
            .collect();
        let alive: Vec<usize> = workers.iter().map(|worker| worker.id).collect();
        // 选路与真正取得准入锁之间可能刚好触发排空。排除失效目标再选，
        // 而不是让这个本可以迁往其他实例的请求直接失败。
        while !eligible.is_empty() {
            let id = self.scheduler.pick(
                &self.policy,
                &eligible,
                &alive,
                username,
                client_ip,
                |id| {
                    workers
                        .iter()
                        .find(|worker| worker.id == id)
                        .map(|worker| worker.active.load(Ordering::Relaxed))
                        .unwrap_or(0)
                },
            )?;
            if let Some(worker) = workers.iter().find(|worker| worker.id == id) {
                if let Some(lease) = self.lease(worker.clone(), username, client_ip) {
                    return Ok(lease);
                }
            }
            eligible.retain(|candidate| *candidate != id);
            self.scheduler.forget_users(id);
        }
        Err(PickFail::NoWorker)
    }

    /// 兼容旧调用：匿名轮询，不计入活跃连接。
    pub fn pick(&self) -> Option<NetHandle> {
        let lease = self.checkout(None, "").ok()?;
        let net = lease.net.clone();
        drop(lease);
        Some(net)
    }

    fn lease(
        &self,
        worker: Arc<Worker>,
        username: Option<&str>,
        client_ip: &str,
    ) -> Option<ConnLease> {
        // 与运行时关闭阈值同步，避免使用旧策略在取消队列后再次触发排空。
        let policy_guard = self.restart_policy.read().unwrap();
        let policy = *policy_guard;
        let identity = worker.user_identity(username, client_ip);
        let inner = worker.inner.lock().unwrap();
        if !worker.manual.load(Ordering::Relaxed)
            || worker.stopped.load(Ordering::Relaxed)
            || worker.restart_pending.load(Ordering::Relaxed)
            || worker.draining.load(Ordering::Relaxed)
            || worker.restart_busy.load(Ordering::Relaxed)
        {
            return None;
        }
        let net = inner.net.clone()?;
        let mut usage = worker.usage.lock().unwrap();
        if worker.restart_pending.load(Ordering::Relaxed)
            || worker.draining.load(Ordering::Relaxed)
            || worker.restart_busy.load(Ordering::Relaxed)
        {
            return None;
        }
        let assigned_v6 = crate::tunnel::parse_assigned_v6(&inner.config.ipv6)
            .map(|ip| ip.to_string())
            .unwrap_or_default();
        let shown = shown_egress(
            &observed_ip(&inner.egress_v4),
            &observed_ip(&inner.egress_v6),
            &inner.assigned_v4.to_string(),
            &assigned_v6,
        );
        worker.active.fetch_add(1, Ordering::Relaxed);
        usage.connections = usage.connections.saturating_add(1);
        // 仅在开启用户阈值时保存去重身份，避免关闭该条件时内存随累计用户持续增长。
        if policy.max_users > 0 {
            usage.identities.insert(identity);
        }
        let queued = worker.queue_if_reached(&usage, policy);
        drop(usage);
        drop(inner);
        if queued {
            self.queue_threshold_restart(worker.id);
        }
        drop(policy_guard);
        Some(ConnLease {
            worker_id: worker.id,
            egress: shown.fallback,
            egress_v4: shown.v4,
            egress_v6: shown.v6,
            net,
            worker,
        })
    }

    pub fn reconnect(&self, id: usize) {
        for worker in self.snapshot() {
            if (id == 0 || worker.id == id)
                && !worker.restart_pending.load(Ordering::Relaxed)
                && !worker.restart_busy.load(Ordering::Relaxed)
            {
                // 与阈值准入使用同一把锁，消除“检查后刚排空”的窗口。
                let _inner = worker.inner.lock().unwrap();
                if !worker.restart_pending.load(Ordering::Relaxed) {
                    worker.rebuild.notify_one();
                }
            }
        }
    }

    /// 手动强制保身份重启一个账号；id 为 0 时按顺序逐个重启。
    pub async fn restart(&self, id: usize) -> Result<(), String> {
        if id == 0 {
            let ids: Vec<usize> = self.snapshot().iter().map(|worker| worker.id).collect();
            for id in ids {
                self.restart_one(id).await?;
            }
            Ok(())
        } else {
            self.restart_one(id).await
        }
    }

    pub async fn restart_one(&self, id: usize) -> Result<(), String> {
        let worker = self
            .snapshot()
            .into_iter()
            .find(|worker| worker.id == id)
            .ok_or_else(|| format!("没有账号 {id}"))?;
        if worker.restart_busy.swap(true, Ordering::AcqRel) {
            return Err(format!("账号 {id} 已在重启中"));
        }
        // 手动强制重启立即摘流，不等待连接排空；实际重连仍受并发名额限制。
        worker.begin_draining();
        worker.restart_pending.store(true, Ordering::Relaxed);
        self.scheduler.forget_users(id);
        {
            let mut queues = self.restart_queues.lock().unwrap();
            queues.draining.retain(|queued| *queued != id);
            queues.ready.retain(|queued| *queued != id);
        }
        worker.set_stage("等待手动重启名额");
        let result = tokio::select! {
            biased;
            _ = wait_stopped(&worker) => Err(format!("账号 {id} 已移除")),
            acquired = self.restart_limit.clone().acquire_owned() => match acquired {
                Ok(permit) => {
                    let result = self.restart_one_permitted(&worker).await;
                    drop(permit);
                    result
                }
                Err(_) => Err("重启已取消".into()),
            },
        };
        worker.restart_busy.store(false, Ordering::Release);
        // 手动任务排队时可能被管理员移除，等待者退出后仍需唤醒自动队列。
        self.restart_wake.notify_one();
        result
    }

    /// 调度器已经占有名额；自动路径还须先检查该实例的活跃连接数为零。
    async fn restart_one_permitted(&self, worker: &Arc<Worker>) -> Result<(), String> {
        if worker.stopped.load(Ordering::Acquire) {
            return Err(format!("账号 {} 已移除", worker.id));
        }
        worker.restart_attempted.store(true, Ordering::Relaxed);
        worker.set_stage("重连并验证出口");
        let (reply_tx, reply_rx) = oneshot::channel();
        worker
            .restart_tx
            .send(RestartJob {
                reply: reply_tx,
                probe_timeout: self.restart.probe_timeout,
            })
            .map_err(|_| "账号监督任务已退出".to_string())?;
        tokio::select! {
            biased;
            _ = wait_stopped(worker) => Err(format!("账号 {} 已移除", worker.id)),
            result = reply_rx => result.map_err(|_| "重启任务中断".to_string())?,
        }
    }

    fn finish_reconnect(&self, worker: &Worker) {
        self.scheduler.forget_users(worker.id);
        worker.reset_usage();
    }

    /// 运行中修改任意重启条件；未指定的阈值保持原值，0 表示关闭。
    pub fn set_restart_policy(
        &self,
        max_uptime: Option<Duration>,
        max_users: Option<usize>,
        max_connections: Option<u64>,
    ) -> Result<(), String> {
        let mut policy = self.restart_policy.write().unwrap();
        let next = RestartPolicy {
            max_uptime: max_uptime.unwrap_or(policy.max_uptime),
            max_users: max_users.unwrap_or(policy.max_users),
            max_connections: max_connections.unwrap_or(policy.max_connections),
        };
        if next.max_users > MAX_RESTART_USERS {
            return Err(format!("单实例累计用户阈值不能超过 {MAX_RESTART_USERS}"));
        }
        if next == *policy {
            return Ok(());
        }
        let users_enabled = policy.max_users == 0 && next.max_users > 0;
        *policy = next;
        let workers = self.snapshot();
        for worker in &workers {
            let inner = worker.inner.lock().unwrap();
            let mut usage = worker.usage.lock().unwrap();
            if users_enabled || next.max_users == 0 {
                // 仅启用用户阈值时保存去重身份，重新启用从此刻开始计数。
                usage.identities.clear();
            }
            let queued = inner.net.is_some() && worker.queue_if_reached(&usage, next);
            drop(usage);
            drop(inner);
            if queued {
                self.queue_threshold_restart(worker.id);
            }
        }
        if next.is_disabled() {
            // 排空、待重启队列中的自动任务可以取消；已占名额、正在重试和手动任务继续完成。
            let mut queues = self.restart_queues.lock().unwrap();
            let queued: HashSet<usize> = queues
                .draining
                .iter()
                .chain(queues.ready.iter())
                .copied()
                .collect();
            let mut cancelled = HashSet::new();
            for worker in &workers {
                if queued.contains(&worker.id) && worker.cancel_queued_restart() {
                    cancelled.insert(worker.id);
                }
            }
            queues.draining.retain(|id| !cancelled.contains(id));
            queues.ready.retain(|id| !cancelled.contains(id));
            drop(queues);
            for id in cancelled {
                self.console.log(
                    "plan",
                    format!("账号 {id} 取消尚未执行的自动重启，等待正常接入或故障恢复"),
                );
            }
        }
        drop(policy);
        self.restart_wake.notify_one();
        Ok(())
    }

    pub async fn rotate(&self, id: usize) -> crate::Result<()> {
        let workers = self.snapshot();
        let target = if id != 0 {
            workers.into_iter().find(|worker| worker.id == id)
        } else {
            workers.first().cloned()
        };
        let Some(worker) = target else {
            return Err(crate::Error::Config("没有这个账号".into()));
        };
        if !self.may_rebuild(worker.id) {
            return Err(crate::Error::Config(format!(
                "账号 {} 正在排空或等待重启，不能换出口",
                worker.id
            )));
        }
        let opts = RegisterOptions {
            device_name: Some(format!("{}-{}", self.device_name, worker.id)),
            ..Default::default()
        };
        let fresh = register_with(worker.upstream.as_ref(), &opts).await?;
        // 账号注册可能较慢，再次确认期间没有进入排空。
        let mut inner = worker.inner.lock().unwrap();
        if worker.restart_pending.load(Ordering::Relaxed) {
            return Err(crate::Error::Config(format!(
                "账号 {} 已开始排空，取消换出口",
                worker.id
            )));
        }
        inner.config = fresh;
        drop(inner);
        worker.rebuild.notify_one();
        Ok(())
    }

    pub fn set_http2(&self, on: bool) {
        if !on && !self.upstream.is_empty() {
            eprintln!("[pool] 已配置上游 SOCKS5，不能切回 HTTP/3");
            return;
        }
        self.http2.store(on, Ordering::Relaxed);
        self.reconnect(0);
    }

    pub fn set_listen(&self, addr: impl Into<String>) {
        *self.listen.lock().unwrap() = addr.into();
    }

    pub fn set_manual(&self, id: usize, on: bool) -> crate::Result<()> {
        let worker = self
            .snapshot()
            .into_iter()
            .find(|worker| worker.id == id)
            .ok_or_else(|| crate::Error::Config(format!("没有账号 {id}")))?;
        worker.manual.store(on, Ordering::Relaxed);
        worker.note(if on { "已启用" } else { "已停用" });
        // 手动停用和排空都不能保留旧用户名绑定；下一次请求会迁往可用实例。
        if !on {
            self.scheduler.forget_users(id);
        }
        self.console.log(
            "account",
            format!("账号 {id} {}", if on { "已启用" } else { "已停用" }),
        );
        Ok(())
    }

    pub fn set_rotate_interval(&self, secs: u64) {
        let secs = if secs == 0 {
            0
        } else {
            secs.max(MIN_ROTATE_SECS)
        };
        self.rotate_secs.store(secs, Ordering::Relaxed);
    }

    pub async fn add_account(self: &Arc<Self>) -> crate::Result<usize> {
        self.add_account_kind(false).await
    }

    /// 按数量添加账号。临时账号会记下身份；已移除但还留在磁盘上的身份会优先用回来，不再重新注册。
    pub async fn add_accounts(
        self: &Arc<Self>,
        temporary: bool,
        count: usize,
    ) -> crate::Result<Vec<usize>> {
        if count == 0 {
            return Err(crate::Error::Config("添加数量至少为 1".into()));
        }
        if count > MAX_ADD_COUNT {
            return Err(crate::Error::Config(format!(
                "一次最多添加 {MAX_ADD_COUNT} 个"
            )));
        }
        let mut ids = Vec::with_capacity(count);
        for _ in 0..count {
            ids.push(self.add_account_kind(temporary).await?);
        }
        Ok(ids)
    }

    /// 添加一个账号。临时账号写入 STATE_DIR，重启时按 temporary.json 加载，不重新注册。
    pub async fn add_account_kind(self: &Arc<Self>, temporary: bool) -> crate::Result<usize> {
        let claim = self.claim_account(temporary);
        let id = claim.id();
        match self.finish_add(claim, temporary).await {
            Ok(id) => Ok(id),
            Err(err) => {
                self.release_reserved(id);
                Err(err)
            }
        }
    }

    fn claim_account(&self, temporary: bool) -> AccountClaim {
        let mut reserved = self.reserved_ids.lock().unwrap();
        if temporary {
            if let Some((id, config)) = self.find_spare(&reserved) {
                reserved.push(id);
                return AccountClaim::Saved { id, config };
            }
        }
        let id = self.allocate_id(&reserved);
        reserved.push(id);
        AccountClaim::Fresh { id }
    }

    async fn finish_add(
        self: &Arc<Self>,
        claim: AccountClaim,
        temporary: bool,
    ) -> crate::Result<usize> {
        let id = claim.id();
        let (config, message, note) = match claim {
            AccountClaim::Saved { config, .. } => (
                config,
                format!("已添加临时账号 {id}，使用已保存身份"),
                "使用已保存身份".to_string(),
            ),
            AccountClaim::Fresh { .. } => {
                let opts = RegisterOptions {
                    device_name: Some(format!("{}-{id}", self.device_name)),
                    ..Default::default()
                };
                let upstream = self.upstream.for_index(id.saturating_sub(1));
                let config = register_with(upstream.as_ref(), &opts).await?;
                if let Some(dir) = &self.state_dir {
                    std::fs::create_dir_all(dir)
                        .map_err(|err| crate::Error::Config(err.to_string()))?;
                    config.save(account_path(dir, id))?;
                }
                let (message, note) = if temporary {
                    (format!("已添加临时账号 {id}"), "临时添加".to_string())
                } else {
                    (format!("已添加账号 {id}"), "添加账号".to_string())
                };
                (config, message, note)
            }
        };
        if temporary {
            if let Some(dir) = &self.state_dir {
                remember_saved_temporary(dir, id)?;
            }
        }
        self.attach_account(id, config, temporary, &note, &message)
            .await?;
        Ok(id)
    }

    async fn attach_account(
        self: &Arc<Self>,
        id: usize,
        config: WarpConfig,
        temporary: bool,
        note: &str,
        message: &str,
    ) -> crate::Result<()> {
        self.bump_next_id(id);
        let upstream = self.upstream.for_index(id.saturating_sub(1));
        let (worker, jobs) = Worker::new(id, config, upstream);
        worker.temporary.store(temporary, Ordering::Relaxed);
        worker.note(note);
        worker.set_stage("连接中");
        {
            let mut workers = self.workers.lock().unwrap();
            let position = workers.partition_point(|existing| existing.id < id);
            workers.insert(position, worker.clone());
        }
        self.release_reserved(id);
        Pool::spawn_supervisor(self.clone(), worker, jobs);
        self.console.log("account", message.to_string());
        Ok(())
    }

    async fn restore_temporary(self: &Arc<Self>) {
        let Some(dir) = self.state_dir.clone() else {
            return;
        };
        let active = match read_temporary_active(&dir) {
            Ok(active) => active,
            Err(err) => {
                eprintln!("[pool] 无法读取临时实例名单: {err}");
                return;
            }
        };
        for id in active {
            let should_load = {
                let mut reserved = self.reserved_ids.lock().unwrap();
                let workers = self.workers.lock().unwrap();
                let pending_bases = if self.initializing.load(Ordering::Relaxed) {
                    self.base_ids
                        .lock()
                        .unwrap()
                        .iter()
                        .filter(|base_id| !workers.iter().any(|worker| worker.id == **base_id))
                        .count()
                } else {
                    0
                };
                let at_limit = self.auto_restore_limit.is_some_and(|limit| {
                    workers
                        .len()
                        .saturating_add(reserved.len())
                        .saturating_add(pending_bases)
                        >= limit
                });
                if reserved.contains(&id)
                    || workers.iter().any(|worker| worker.id == id)
                    || at_limit
                {
                    false
                } else {
                    reserved.push(id);
                    true
                }
            };
            if !should_load {
                continue;
            }
            let config = match WarpConfig::load(account_path(&dir, id)) {
                Ok(config) => config,
                Err(err) => {
                    self.release_reserved(id);
                    eprintln!("[pool] 临时账号 {id} 的配置还在，但暂时无法加载: {err}");
                    continue;
                }
            };
            if let Err(err) = self
                .attach_account(
                    id,
                    config,
                    true,
                    "加载已保存的临时实例",
                    &format!("已加载临时账号 {id}，使用已保存身份"),
                )
                .await
            {
                self.release_reserved(id);
                eprintln!("[pool] 加载临时账号 {id} 失败: {err}");
            }
        }
    }

    /// 运行时导入新发现的 MicroWARP 身份，并启动迁移名单中的实例。
    pub async fn scan_microwarp(self: &Arc<Self>, source_dir: &Path) -> crate::Result<usize> {
        let imported = self.import_microwarp(source_dir)?;
        self.restore_temporary().await;
        if imported > 0 {
            self.console
                .log("account", format!("已迁移 {imported} 个 MicroWARP 账号"));
        }
        Ok(imported)
    }

    /// 仅导入磁盘身份；适合启动阶段在阻塞线程执行，避免占用控制面的运行线程。
    pub fn import_microwarp(&self, source_dir: &Path) -> crate::Result<usize> {
        let Some(dir) = &self.state_dir else {
            return Err(crate::Error::Config("迁移 MicroWARP 需要 STATE_DIR".into()));
        };
        let base_ids = self.base_ids.lock().unwrap().clone();
        let pending_bases = if self.initializing.load(Ordering::Relaxed) {
            let workers = self.snapshot();
            base_ids
                .iter()
                .filter(|id| !workers.iter().any(|worker| worker.id == **id))
                .copied()
                .collect::<Vec<_>>()
        } else {
            Vec::new()
        };
        {
            let reserved = self.reserved_ids.lock().unwrap();
            let mut excluded = reserved.clone();
            excluded.extend(pending_bases);
            crate::migration::migrate_excluding(dir, source_dir, base_ids.len(), &excluded)
        }
    }

    fn find_spare(&self, reserved: &[usize]) -> Option<(usize, WarpConfig)> {
        let dir = self.state_dir.as_ref()?;
        let running: Vec<usize> = self.snapshot().iter().map(|worker| worker.id).collect();
        let base = self.base_ids.lock().unwrap().clone();
        for id in saved_account_ids(dir) {
            if running.contains(&id) || base.contains(&id) || reserved.contains(&id) {
                continue;
            }
            match WarpConfig::load(account_path(dir, id)) {
                Ok(config) => return Some((id, config)),
                Err(err) => eprintln!("[pool] 跳过无法读取的账号 {id}: {err}"),
            }
        }
        None
    }

    fn allocate_id(&self, reserved: &[usize]) -> usize {
        if let Some(dir) = &self.state_dir {
            for id in saved_account_ids(dir) {
                self.bump_next_id(id);
            }
        }
        for worker in self.snapshot() {
            self.bump_next_id(worker.id);
        }
        for id in reserved {
            self.bump_next_id(*id);
        }
        self.next_id.fetch_add(1, Ordering::Relaxed)
    }

    fn bump_next_id(&self, id: usize) {
        let next = id.saturating_add(1);
        let mut current = self.next_id.load(Ordering::Relaxed);
        while current < next {
            match self.next_id.compare_exchange_weak(
                current,
                next,
                Ordering::Relaxed,
                Ordering::Relaxed,
            ) {
                Ok(_) => break,
                Err(actual) => current = actual,
            }
        }
    }

    fn release_reserved(&self, id: usize) {
        self.reserved_ids
            .lock()
            .unwrap()
            .retain(|existing| *existing != id);
    }

    /// 移出运行中的账号。临时实例只从名单里去掉，不删除已保存的身份。
    pub fn remove_account(&self, id: usize) -> crate::Result<()> {
        let mut workers = self.workers.lock().unwrap();
        if workers.len() <= 1 {
            return Err(crate::Error::Config("不能删除最后一个账号".into()));
        }
        let Some(index) = workers.iter().position(|worker| worker.id == id) else {
            return Err(crate::Error::Config(format!("没有账号 {id}")));
        };
        let worker = workers.remove(index);
        let temporary = worker.temporary.load(Ordering::Relaxed);
        // 摘出实例与阻止新租约连续完成；持有旧快照的请求也必须看到停止状态。
        worker.begin_draining();
        worker.stopped.store(true, Ordering::Release);
        drop(workers);
        worker.stop_notify.notify_waiters();
        worker.retire();
        worker.rebuild.notify_one();
        self.scheduler.forget(id);
        let mut queues = self.restart_queues.lock().unwrap();
        queues.draining.retain(|queued| *queued != id);
        queues.ready.retain(|queued| *queued != id);
        drop(queues);
        if temporary {
            if let Some(dir) = &self.state_dir {
                if let Err(err) = forget_saved_temporary(dir, id) {
                    eprintln!("[pool] 账号 {id} 已移出运行，但名单没有更新: {err}");
                }
            }
            self.console
                .log("account", format!("已移除临时账号 {id}，保留已保存身份"));
        }
        Ok(())
    }

    pub async fn refresh_trace(&self, id: usize) {
        for worker in self.snapshot() {
            if id != 0 && worker.id != id {
                continue;
            }
            let text = match probe_egress(&worker, self.health_timeout).await {
                Ok(egress) => format!(
                    "[pool] 账号 {} 出口 {}",
                    worker.id,
                    egress_summary(&egress.v4, &egress.v6)
                ),
                Err(err) => format!("[pool] 账号 {} 出口探测失败: {err}", worker.id),
            };
            eprintln!("{text}");
            self.console.log("account", text);
        }
    }

    pub fn status(&self) -> PoolStatus {
        let policy = *self.restart_policy.read().unwrap();
        let queues = self.restart_queues.lock().unwrap();
        let drain_queue = queues.draining.iter().copied().collect();
        let restart_queue = queues.ready.iter().copied().collect();
        drop(queues);
        let users = self.scheduler.user_counts();
        let mut ready_n = 0usize;
        let mut attention = 0usize;
        let mut maintenance = 0usize;
        let mut unknown = 0usize;
        let mut tasks = Vec::new();
        let accounts = self
            .snapshot()
            .iter()
            .map(|worker| {
                let draining = worker.draining.load(Ordering::Relaxed);
                let active = worker.active.load(Ordering::Relaxed);
                let manual = worker.manual.load(Ordering::Relaxed);
                let inner = worker.inner.lock().unwrap();
                let usage = worker.usage.lock().unwrap();
                let egress_v4 = inner.egress_v4.clone();
                let egress_v6 = inner.egress_v6.clone();
                let (ipv4, ipv6, country, colo, warp) =
                    egress_parts(egress_v4.as_ref(), egress_v6.as_ref());
                let trace = preferred_trace(egress_v4.as_ref(), egress_v6.as_ref()).cloned();
                let stage = worker.stage.lock().unwrap().clone();
                let health = if !manual {
                    "disabled"
                } else if stage == "连接中" {
                    "connecting"
                } else if stage == "连接失败，重试中" {
                    "retrying"
                } else if draining {
                    "maintenance"
                } else if inner.net.is_none() {
                    "down"
                } else if warp == "on"
                    || warp == "plus"
                    || (warp.is_empty() && worker.warp_ready.load(Ordering::Relaxed))
                {
                    "healthy"
                } else if warp.is_empty() {
                    "unknown"
                } else {
                    "attention"
                };
                match health {
                    "healthy" => ready_n += 1,
                    "maintenance" | "disabled" => maintenance += 1,
                    "unknown" => unknown += 1,
                    _ => attention += 1,
                }
                let stage_at = *worker.stage_at.lock().unwrap();
                if !stage.is_empty() {
                    tasks.push(TaskStatus {
                        id: worker.id,
                        stage: stage.clone(),
                        active,
                        elapsed_seconds: stage_at.map(|at| at.elapsed().as_secs()).unwrap_or(0),
                    });
                }
                let ready = manual
                    && !draining
                    && !worker.stopped.load(Ordering::Relaxed)
                    && !worker.restart_pending.load(Ordering::Relaxed)
                    && !worker.restart_busy.load(Ordering::Relaxed)
                    && inner.net.is_some();
                AccountStatus {
                    id: worker.id,
                    ready,
                    tunnel: inner.net.is_some(),
                    draining,
                    manual,
                    temporary: worker.temporary.load(Ordering::Relaxed),
                    active,
                    health: health.to_string(),
                    warp,
                    ipv4,
                    ipv6,
                    country,
                    colo,
                    pooled: ready,
                    users: users.get(&worker.id).copied().unwrap_or(0),
                    restart_users: usage.identities.len(),
                    restart_connections: usage.connections,
                    restart_pending: worker.restart_pending.load(Ordering::Relaxed),
                    uptime_seconds: worker.uptime().as_secs(),
                    last_action: worker.last_action.lock().unwrap().clone(),
                    ip: inner.assigned_v4.to_string(),
                    assigned_v6: inner.config.ipv6.clone(),
                    trace,
                }
            })
            .collect();
        let (bytes_up, bytes_down) = self.console.totals();
        PoolStatus {
            initializing: self.initializing.load(Ordering::Relaxed),
            expected_accounts: self.expected_accounts,
            enabled: self.enabled(),
            http2: self.http2.load(Ordering::Relaxed),
            mixed: self.mixed,
            listen: self.listen.lock().unwrap().clone(),
            rotate_seconds: self.rotate_secs.load(Ordering::Relaxed),
            restart_max_uptime_seconds: policy.max_uptime.as_secs(),
            restart_max_users: policy.max_users,
            restart_max_connections: policy.max_connections,
            restart_drain_check_seconds: self.restart.drain_check_interval.as_secs_f64(),
            restart_concurrency: self.restart.concurrency.max(1),
            drain_queue,
            restart_queue,
            health_seconds: self.health_interval.as_secs(),
            strategy: strategy_name(self.policy.strategy),
            sticky: sticky_name(self.policy.sticky),
            started_at: self.console.started_at(),
            active_connections: self.console.active_count(),
            bytes_up,
            bytes_down,
            ready: ready_n,
            attention,
            maintenance,
            unknown,
            tasks,
            accounts,
        }
    }

    pub fn sessions(&self) -> Vec<crate::console::SessionView> {
        self.console.sessions()
    }

    pub fn logs(&self) -> crate::console::LogPage {
        let status = self.status();
        self.console.logs(
            status.ready,
            status.attention,
            status.maintenance,
            status.unknown,
        )
    }

    pub fn track_session(&self, open: crate::console::SessionOpen) -> crate::console::SessionGuard {
        self.console.open_session(open)
    }

    pub fn record_access(&self, line: String) {
        if self.access_log {
            eprintln!("{line}");
        }
        self.console.log("access", line);
    }
}

const MAX_ADD_COUNT: usize = 100;

enum AccountClaim {
    Saved { id: usize, config: WarpConfig },
    Fresh { id: usize },
}

impl AccountClaim {
    fn id(&self) -> usize {
        match self {
            Self::Saved { id, .. } | Self::Fresh { id } => *id,
        }
    }
}

#[derive(Serialize, Deserialize, Default)]
struct TemporaryManifest {
    active: Vec<usize>,
}

pub(crate) fn account_path(dir: &Path, id: usize) -> PathBuf {
    dir.join(format!("account-{id}.json"))
}

pub(crate) fn saved_account_ids(dir: &Path) -> Vec<usize> {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return Vec::new();
    };
    let mut ids = Vec::new();
    for entry in entries.flatten() {
        let name = entry.file_name();
        let Some(name) = name.to_str() else {
            continue;
        };
        let Some(rest) = name.strip_prefix("account-") else {
            continue;
        };
        let Some(number) = rest.strip_suffix(".json") else {
            continue;
        };
        if let Ok(id) = number.parse::<usize>() {
            if id > 0 {
                ids.push(id);
            }
        }
    }
    ids.sort_unstable();
    ids.dedup();
    ids
}

pub(crate) fn read_temporary_active(dir: &Path) -> crate::Result<Vec<usize>> {
    let path = dir.join("temporary.json");
    if !path.exists() {
        return Ok(Vec::new());
    }
    let bytes = std::fs::read(&path).map_err(|err| crate::Error::Config(err.to_string()))?;
    let manifest: TemporaryManifest = serde_json::from_slice(&bytes)
        .map_err(|err| crate::Error::Config(format!("无法读取 {}: {err}", path.display())))?;
    let mut active = manifest.active;
    active.sort_unstable();
    active.dedup();
    Ok(active)
}

fn write_temporary_active(dir: &Path, active: &[usize]) -> crate::Result<()> {
    std::fs::create_dir_all(dir).map_err(|err| crate::Error::Config(err.to_string()))?;
    let manifest = TemporaryManifest {
        active: active.to_vec(),
    };
    crate::migration::write_json_atomic(&dir.join("temporary.json"), &manifest)
}

static TEMPORARY_MANIFEST_LOCK: Mutex<()> = Mutex::new(());

pub(crate) fn remember_saved_temporary(dir: &Path, id: usize) -> crate::Result<()> {
    let _guard = TEMPORARY_MANIFEST_LOCK.lock().unwrap();
    let mut active = read_temporary_active(dir)?;
    if !active.contains(&id) {
        active.push(id);
        active.sort_unstable();
    }
    write_temporary_active(dir, &active)
}

/// 只把编号移出正在使用的名单，不删除 account-{id}.json。
fn forget_saved_temporary(dir: &Path, id: usize) -> crate::Result<()> {
    let _guard = TEMPORARY_MANIFEST_LOCK.lock().unwrap();
    let mut active = read_temporary_active(dir)?;
    active.retain(|existing| *existing != id);
    write_temporary_active(dir, &active)
}

#[cfg(test)]
fn spare_account_id(saved: &[usize], running: &[usize], base: &[usize]) -> Option<usize> {
    saved
        .iter()
        .copied()
        .find(|id| !running.contains(id) && !base.contains(id))
}

async fn register_with(
    upstream: Option<&UpstreamProxy>,
    opts: &RegisterOptions,
) -> crate::Result<WarpConfig> {
    if let Some(upstream) = upstream {
        RegistrationClient::with_socks5(upstream)?
            .register(opts)
            .await
    } else {
        RegistrationClient::register_auto(opts).await
    }
}

fn probe_target(configs: &[WarpConfig]) -> SocketAddr {
    let host = configs
        .iter()
        .find_map(|cfg| {
            let value = cfg.endpoint_h2_v4.trim();
            (!value.is_empty()).then(|| value.to_string())
        })
        .unwrap_or_else(|| DEFAULT_ENDPOINT_H2_V4.to_string());
    let ip = host
        .parse::<Ipv4Addr>()
        .unwrap_or(Ipv4Addr::new(162, 159, 198, 2));
    SocketAddr::from((ip, 443))
}

async fn supervise(
    pool: Weak<Pool>,
    worker: Arc<Worker>,
    mut jobs: mpsc::UnboundedReceiver<RestartJob>,
) {
    loop {
        if worker.stopped.load(Ordering::Relaxed) {
            worker.retire();
            return;
        }
        let Some(current) = pool.upgrade() else {
            return;
        };
        let health_every = current.health_interval;
        drop(current);
        if !worker.restart_pending.load(Ordering::Acquire) && worker_needs_warp_check(&worker) {
            worker.begin_draining();
            let confirmed = tokio::select! {
                biased;
                _ = wait_stopped(&worker) => {
                    worker.retire();
                    return;
                }
                confirmed = confirm_warp(&pool, &worker) => confirmed,
            };
            if confirmed {
                // Pool::start() 的首次建链不经过 reconnect_loop，也必须开始运行计时。
                worker.mark_initial_ready();
            }
            {
                // 与 lease() 互斥，防止刚触发的排空被本次验证清除。
                let _inner = worker.inner.lock().unwrap();
                if !worker.restart_pending.load(Ordering::Acquire) && confirmed {
                    worker.draining.store(false, Ordering::Release);
                }
            }
            if !confirmed {
                worker.retire_if_not_pending();
            }
        }
        if worker.restart_pending.load(Ordering::Acquire) {
            // 等待排空时冻结健康检查和主动换出口，不触碰旧隧道。
            // 已执行过重启但失败时，改由后台重试循环取得新的并发名额。
            if worker.restart_attempted.load(Ordering::Acquire) {
                if !reconnect_loop(&pool, &worker, &mut jobs).await {
                    return;
                }
                continue;
            }
            tokio::select! {
                biased;
                _ = wait_stopped(&worker) => {
                    worker.retire();
                    return;
                },
                job = jobs.recv() => match job {
                    Some(job) => {
                        let result = graceful(&pool, &worker, &job).await;
                        let _ = job.reply.send(result);
                    }
                    None => return,
                },
                // 关闭阈值、移除实例时必须离开等待，重新核对 pending / stopped。
                _ = worker.drain_finished.notified() => {},
                _ = worker.rebuild.notified() => {},
            }
            continue;
        }
        let next_health = tokio::time::Instant::now() + health_every;
        if let Some(mut dead) = worker.dead_signal() {
            tokio::select! {
                biased;
                _ = wait_stopped(&worker) => {
                    worker.retire();
                    return;
                },
                job = jobs.recv() => {
                    match job {
                        Some(job) => {
                            let result = graceful(&pool, &worker, &job).await;
                            let _ = job.reply.send(result);
                            continue;
                        }
                        None => return,
                    }
                }
                _ = worker.drain_finished.notified() => continue,
                _ = wait_true(&mut dead) => worker.clear_net(),
                _ = worker.rebuild.notified() => worker.clear_net(),
                _ = tokio::time::sleep_until(next_health), if !health_every.is_zero() => {
                    egress_health(&pool, &worker).await;
                    continue;
                }
            }
        }
        if !reconnect_loop(&pool, &worker, &mut jobs).await {
            return;
        }
    }
}

/// 经隧道拉一次出口 trace。请求本身会在 HTTP/2 上产生数据，避免空闲断开。
async fn egress_health(pool: &Weak<Pool>, worker: &Worker) {
    let Some(current) = pool.upgrade() else {
        return;
    };
    let timeout = current.health_timeout;
    let previous = egress_snapshot(worker);
    match probe_egress(worker, timeout).await {
        Ok(egress) => {
            let changed =
                !same_egress(&previous.0, &egress.v4) || !same_egress(&previous.1, &egress.v6);
            if changed {
                let text = format!(
                    "[pool] 账号 {} 出口 {}",
                    worker.id,
                    egress_summary(&egress.v4, &egress.v6)
                );
                eprintln!("{text}");
                current.console.log("account", text);
            }
        }
        Err(err) => {
            let text = format!("[pool] 账号 {} 出口检查失败: {err}", worker.id);
            eprintln!("{text}");
            current.console.log("account", text);
        }
    }
}

async fn reconnect_loop(
    pool: &Weak<Pool>,
    worker: &Arc<Worker>,
    jobs: &mut mpsc::UnboundedReceiver<RestartJob>,
) -> bool {
    let mut backoff = Duration::from_secs(1);
    loop {
        if worker.stopped.load(Ordering::Relaxed) {
            worker.retire();
            return false;
        }
        // 手动或自动任务已占有实例的重启执行权时，监督器必须优先消费
        // 该任务，不能抢先自行连接并等待第二份名额，否则并发数为 1 会死锁。
        if worker.restart_busy.load(Ordering::Acquire) {
            tokio::select! {
                biased;
                _ = wait_stopped(worker) => {
                    worker.retire();
                    return false;
                },
                job = jobs.recv() => match job {
                    Some(job) => {
                        let result = graceful(pool, worker, &job).await;
                        let _ = job.reply.send(result);
                        return true;
                    }
                    None => return false,
                },
                _ = tokio::time::sleep(Duration::from_secs(1)) => {},
            }
            continue;
        }
        // 阈值已触发但排空/重启队列尚未放行时，故障恢复也不得抢先重连。
        if worker.restart_pending.load(Ordering::Relaxed)
            && !worker.restart_attempted.load(Ordering::Relaxed)
        {
            tokio::select! {
                biased;
                _ = wait_stopped(worker) => {
                    worker.retire();
                    return false;
                },
                job = jobs.recv() => match job {
                    Some(job) => {
                        let result = graceful(pool, worker, &job).await;
                        let _ = job.reply.send(result);
                        return true;
                    }
                    None => return false,
                },
                _ = worker.drain_finished.notified() => {},
                _ = worker.rebuild.notified() => {},
            }
            continue;
        }
        let Some(current) = pool.upgrade() else {
            return false;
        };
        let probe_timeout = current.restart.probe_timeout;
        worker.begin_draining();
        let initial_connect = matches!(
            worker.stage.lock().unwrap().as_str(),
            "连接中" | "连接失败，重试中"
        );
        if initial_connect {
            worker.set_stage("连接中");
        } else if worker.restart_pending.load(Ordering::Relaxed) {
            worker.set_stage("重启失败，后台重试中");
        } else {
            worker.set_stage("重连");
        }
        // 自动重启后的后台故障恢复也占用同一个并发名额。
        let restart_permit = if worker.restart_pending.load(Ordering::Relaxed) {
            let permit = tokio::select! {
                biased;
                _ = wait_stopped(worker) => {
                    worker.retire();
                    return false;
                },
                job = jobs.recv() => match job {
                    Some(job) => {
                        let result = graceful(pool, worker, &job).await;
                        let _ = job.reply.send(result);
                        return true;
                    }
                    None => return false,
                },
                permit = current.restart_limit.clone().acquire_owned() => permit,
            };
            match permit {
                Ok(permit) => Some(permit),
                Err(_) => return false,
            }
        } else {
            None
        };
        let connect = tokio::select! {
            biased;
            _ = wait_stopped(worker) => {
                worker.retire();
                return false;
            },
            job = jobs.recv() => match job {
                Some(job) => {
                    drop(restart_permit);
                    let result = graceful(pool, worker, &job).await;
                    let _ = job.reply.send(result);
                    return true;
                }
                None => return false,
            },
            permit = current.connect_limit.clone().acquire_owned() => permit,
        };
        let permit = match connect {
            Ok(permit) => permit,
            Err(_) => return false,
        };
        if worker.stopped.load(Ordering::Relaxed) {
            worker.retire();
            return false;
        }
        let built = tokio::select! {
            biased;
            _ = wait_stopped(worker) => {
                worker.retire();
                return false;
            },
            built = current.build_tunnel(worker) => built,
        };
        let failure = match built {
            Err(err) => Some(err.to_string()),
            Ok(()) => match tokio::select! {
                biased;
                _ = wait_stopped(worker) => {
                    worker.retire();
                    return false;
                },
                result = probe_egress(worker, probe_timeout) => result,
            } {
                Ok(egress) if egress_confirmed(&egress) => {
                    let text = format!(
                        "[pool] 账号 {} 隧道已重连，出口 {}",
                        worker.id,
                        egress_summary(&egress.v4, &egress.v6)
                    );
                    current.finish_reconnect(worker);
                    worker.clear_stage();
                    eprintln!("{text}");
                    current.console.log("account", text);
                    return true;
                }
                Ok(egress) => {
                    worker.retire();
                    Some(egress_summary(&egress.v4, &egress.v6))
                }
                Err(err) => {
                    worker.retire();
                    Some(err)
                }
            },
        };
        if let Some(err) = failure {
            if initial_connect {
                worker.set_stage("连接失败，重试中");
            }
            let text = format!(
                "[pool] 账号 {} 尚未就绪: {err}，{} 秒后重试",
                worker.id,
                backoff.as_secs()
            );
            eprintln!("{text}");
            current.console.log("account", text);
        }
        drop(permit);
        drop(restart_permit);
        drop(current);
        tokio::select! {
            biased;
            _ = wait_stopped(worker) => {
                worker.retire();
                return false;
            },
            _ = tokio::time::sleep(backoff) => {}
            _ = worker.rebuild.notified() => {}
            job = jobs.recv() => {
                match job {
                    Some(job) => {
                        let result = graceful(pool, worker, &job).await;
                        let _ = job.reply.send(result);
                        return true;
                    }
                    None => return false,
                }
            }
        }
        backoff = (backoff * 2).min(MAX_BACKOFF);
    }
}

async fn graceful(pool: &Weak<Pool>, worker: &Arc<Worker>, job: &RestartJob) -> Result<(), String> {
    if worker.stopped.load(Ordering::Acquire) {
        return Err(format!("账号 {} 已移除", worker.id));
    }
    account_log(pool, format!("[pool] 账号 {} 开始保身份重启", worker.id));
    worker.begin_draining();
    let result = tokio::select! {
        biased;
        _ = wait_stopped(worker) => {
            worker.retire();
            return Err(format!("账号 {} 已移除", worker.id));
        },
        result = restart_in_place(pool, worker, job) => result,
    };
    if result.is_ok() {
        if let Some(current) = pool.upgrade() {
            current.finish_reconnect(worker);
        } else {
            worker.reset_usage();
        }
    }
    if result.is_ok() {
        worker.clear_stage();
    } else {
        worker.set_stage("重启失败，后台重试中");
    }
    worker.note(if result.is_ok() {
        "保身份重启"
    } else {
        "重启失败"
    });
    result
}

async fn restart_in_place(
    pool: &Weak<Pool>,
    worker: &Arc<Worker>,
    job: &RestartJob,
) -> Result<(), String> {
    worker.set_stage("重连");
    worker.retire();
    let Some(current) = pool.upgrade() else {
        return Err("连接池已关闭".into());
    };
    if let Err(err) = current.build_tunnel(worker).await {
        drop(current);
        worker.retire();
        return Err(err.to_string());
    }
    drop(current);
    match probe_egress(worker, job.probe_timeout).await {
        Ok(egress) if egress_confirmed(&egress) => {
            account_log(
                pool,
                format!(
                    "[pool] 账号 {} 保身份重启完成，出口 {}",
                    worker.id,
                    egress_summary(&egress.v4, &egress.v6)
                ),
            );
            Ok(())
        }
        Ok(egress) => {
            let err = egress_summary(&egress.v4, &egress.v6);
            account_log(
                pool,
                format!(
                    "[pool] 账号 {} 保身份重启未通过: {err}，将继续重试",
                    worker.id
                ),
            );
            worker.retire();
            Err(err)
        }
        Err(err) => {
            account_log(
                pool,
                format!(
                    "[pool] 账号 {} 保身份重启未通过: {err}，将继续重试",
                    worker.id
                ),
            );
            worker.retire();
            Err(err)
        }
    }
}

async fn wait_true(rx: &mut watch::Receiver<bool>) {
    loop {
        if *rx.borrow_and_update() {
            return;
        }
        if rx.changed().await.is_err() {
            return;
        }
    }
}

async fn wait_stopped(worker: &Worker) {
    loop {
        let notified = worker.stop_notify.notified();
        tokio::pin!(notified);
        // 注册在状态检查之前，避免在两者之间移除实例时遗漏退出通知。
        notified.as_mut().enable();
        if worker.stopped.load(Ordering::Acquire) {
            return;
        }
        notified.await;
    }
}

/// 隧道还在，但还没确认 warp=on / warp=plus。
fn worker_needs_warp_check(worker: &Worker) -> bool {
    worker.inner.lock().unwrap().net.is_some() && !worker.warp_ready.load(Ordering::Relaxed)
}

async fn confirm_warp(pool: &Weak<Pool>, worker: &Worker) -> bool {
    let Some(current) = pool.upgrade() else {
        return false;
    };
    let timeout = current.restart.probe_timeout;
    match probe_egress(worker, timeout).await {
        Ok(egress) if egress_confirmed(&egress) => {
            let text = format!(
                "[pool] 账号 {} 出口 {}",
                worker.id,
                egress_summary(&egress.v4, &egress.v6)
            );
            eprintln!("{text}");
            current.console.log("account", text);
            true
        }
        Ok(egress) => {
            let text = format!(
                "[pool] 账号 {} 出口未确认: {}，准备重连",
                worker.id,
                egress_summary(&egress.v4, &egress.v6)
            );
            eprintln!("{text}");
            current.console.log("account", text);
            false
        }
        Err(err) => {
            let text = format!("[pool] 账号 {} 出口未确认: {err}，准备重连", worker.id);
            eprintln!("{text}");
            current.console.log("account", text);
            false
        }
    }
}

struct Egress {
    v4: TraceInfo,
    v6: TraceInfo,
}

async fn probe_egress(worker: &Worker, timeout: Duration) -> Result<Egress, String> {
    let Some(net) = worker.net() else {
        return Err("隧道没有就绪".into());
    };
    let (v4, v6) = crate::trace::fetch_egress(&net, timeout).await;
    let egress = Egress { v4, v6 };
    worker.set_egress(egress.v4.clone(), egress.v6.clone());
    Ok(egress)
}

fn egress_confirmed(egress: &Egress) -> bool {
    warp_confirmed(&egress.v4) || warp_confirmed(&egress.v6)
}

fn egress_snapshot(worker: &Worker) -> (Option<TraceInfo>, Option<TraceInfo>) {
    let inner = worker.inner.lock().unwrap();
    (inner.egress_v4.clone(), inner.egress_v6.clone())
}

fn same_egress(previous: &Option<TraceInfo>, next: &TraceInfo) -> bool {
    match previous {
        Some(previous) => previous.ip == next.ip && previous.warp == next.warp,
        None => next.ip.is_empty() && next.warp.is_empty(),
    }
}

fn family_label(info: &TraceInfo) -> String {
    if !info.ip.is_empty() {
        let warp = if info.warp.is_empty() {
            "—"
        } else {
            info.warp.as_str()
        };
        format!("{} warp={warp}", info.ip)
    } else if let Some(err) = info.err.as_deref().filter(|err| !err.is_empty()) {
        err.to_string()
    } else if !info.warp.is_empty() {
        format!("warp={}", info.warp)
    } else {
        "未测到".into()
    }
}

fn account_log(pool: &Weak<Pool>, text: String) {
    eprintln!("{text}");
    if let Some(current) = pool.upgrade() {
        current.console.log("account", text);
    }
}

fn egress_summary(v4: &TraceInfo, v6: &TraceInfo) -> String {
    format!("v4={} · v6={}", family_label(v4), family_label(v6))
}

fn observed_ip(info: &Option<TraceInfo>) -> String {
    info.as_ref()
        .map(|trace| trace.ip.clone())
        .filter(|ip| !ip.is_empty())
        .unwrap_or_default()
}

struct ShownEgress {
    fallback: String,
    v4: String,
    v6: String,
}

/// 租约上记下两族出口。地址族未知时的 fallback 仍优先 IPv4；
/// IPv6 连接只用 IPv6 探测结果，没有时才用隧道分配的 IPv6。
fn shown_egress(
    v4_trace: &str,
    v6_trace: &str,
    assigned_v4: &str,
    assigned_v6: &str,
) -> ShownEgress {
    let v4 = if v4_trace.is_empty() {
        String::new()
    } else {
        v4_trace.to_string()
    };
    let v6 = if !v6_trace.is_empty() {
        v6_trace.to_string()
    } else {
        assigned_v6.to_string()
    };
    let fallback = if !v4.is_empty() {
        v4.clone()
    } else if !v6_trace.is_empty() {
        v6_trace.to_string()
    } else {
        assigned_v4.to_string()
    };
    ShownEgress { fallback, v4, v6 }
}

/// 连接走哪一族，访问日志就展示哪一族的出口。IPv6 没有测到时不回退到 IPv4。
pub(crate) fn egress_for_family<'a>(
    family: &str,
    v4: &'a str,
    v6: &'a str,
    fallback: &'a str,
) -> &'a str {
    let chosen = match family {
        "ipv6" => v6,
        "ipv4" => v4,
        _ => fallback,
    };
    if !chosen.is_empty() {
        chosen
    } else if family == "ipv6" {
        "-"
    } else if !fallback.is_empty() {
        fallback
    } else {
        "-"
    }
}

fn warp_confirmed(info: &crate::trace::TraceInfo) -> bool {
    info.warp == "on" || info.warp == "plus"
}

fn strategy_name(strategy: crate::schedule::Strategy) -> &'static str {
    use crate::schedule::Strategy;
    match strategy {
        Strategy::Round => "round",
        Strategy::Random => "random",
        Strategy::Hash => "hash",
        Strategy::Rotate => "rotate",
    }
}

fn sticky_name(sticky: crate::schedule::StickyMode) -> &'static str {
    use crate::schedule::StickyMode;
    match sticky {
        StickyMode::None => "none",
        StickyMode::UsernameRound => "username-round",
        StickyMode::UsernameLeast => "username-least",
        StickyMode::UsernameHash => "username-hash",
        StickyMode::IpHash => "ip-hash",
    }
}

/// 控制接口 /api/status 的返回体。
#[derive(Serialize)]
pub struct PoolStatus {
    pub initializing: bool,
    pub expected_accounts: usize,
    pub enabled: bool,
    pub http2: bool,
    pub mixed: bool,
    pub listen: String,
    pub rotate_seconds: u64,
    pub restart_max_uptime_seconds: u64,
    pub restart_max_users: usize,
    pub restart_max_connections: u64,
    pub restart_drain_check_seconds: f64,
    pub restart_concurrency: usize,
    pub drain_queue: Vec<usize>,
    pub restart_queue: Vec<usize>,
    pub health_seconds: u64,
    pub strategy: &'static str,
    pub sticky: &'static str,
    pub started_at: u64,
    pub active_connections: usize,
    pub bytes_up: u64,
    pub bytes_down: u64,
    pub ready: usize,
    pub attention: usize,
    pub maintenance: usize,
    pub unknown: usize,
    pub tasks: Vec<TaskStatus>,
    pub accounts: Vec<AccountStatus>,
}

#[derive(Serialize)]
pub struct TaskStatus {
    pub id: usize,
    pub stage: String,
    pub active: usize,
    pub elapsed_seconds: u64,
}

/// 单个账号的状态。
#[derive(Serialize)]
pub struct AccountStatus {
    pub id: usize,
    pub ready: bool,
    pub tunnel: bool,
    pub draining: bool,
    pub manual: bool,
    pub temporary: bool,
    pub active: usize,
    pub health: String,
    pub warp: String,
    pub ipv4: String,
    pub ipv6: String,
    pub country: String,
    pub colo: String,
    pub pooled: bool,
    pub users: usize,
    pub restart_users: usize,
    pub restart_connections: u64,
    pub restart_pending: bool,
    pub uptime_seconds: u64,
    pub last_action: String,
    pub ip: String,
    pub assigned_v6: String,
    pub trace: Option<TraceInfo>,
}

fn egress_parts(
    v4: Option<&TraceInfo>,
    v6: Option<&TraceInfo>,
) -> (String, String, String, String, String) {
    let ipv4 = v4.map(|info| info.ip.clone()).unwrap_or_default();
    let ipv6 = v6.map(|info| info.ip.clone()).unwrap_or_default();
    let place = [v4, v6]
        .into_iter()
        .flatten()
        .find(|info| !info.loc.is_empty() || !info.colo.is_empty());
    let (country, colo) = match place {
        Some(info) => (info.loc.clone(), info.colo.clone()),
        None => (String::new(), String::new()),
    };
    (ipv4, ipv6, country, colo, warp_label(v4, v6))
}

fn warp_label(v4: Option<&TraceInfo>, v6: Option<&TraceInfo>) -> String {
    for info in [v4, v6].into_iter().flatten() {
        if warp_confirmed(info) {
            return info.warp.clone();
        }
    }
    for info in [v4, v6].into_iter().flatten() {
        if !info.warp.is_empty() {
            return info.warp.clone();
        }
    }
    String::new()
}

fn preferred_trace<'a>(
    v4: Option<&'a TraceInfo>,
    v6: Option<&'a TraceInfo>,
) -> Option<&'a TraceInfo> {
    if v4.is_some_and(warp_confirmed) {
        return v4;
    }
    if v6.is_some_and(warp_confirmed) {
        return v6;
    }
    if v4.is_some_and(|info| !info.ip.is_empty() || !info.loc.is_empty() || !info.colo.is_empty()) {
        return v4;
    }
    v6.or(v4)
}

#[cfg(test)]
mod restart_queue_tests {
    use super::{Pool, PoolOptions, RestartPolicy, RestartUsage, WarpConfig, Worker};
    use crate::schedule::StickyMode;
    use std::sync::atomic::Ordering;
    use std::sync::Arc;
    use std::time::{Duration, Instant};
    use tokio::sync::{mpsc, watch};

    async fn mock_pool(
        users: usize,
        connections: u64,
        uptime: Duration,
        concurrency: usize,
    ) -> (
        Arc<Pool>,
        Vec<Arc<Worker>>,
        Vec<mpsc::UnboundedReceiver<super::RestartJob>>,
    ) {
        let mut options = PoolOptions::basic(true);
        options.policy.sticky = StickyMode::UsernameRound;
        options.restart.max_users = users;
        options.restart.max_connections = connections;
        options.restart.max_uptime = uptime;
        options.restart.concurrency = concurrency;
        options.restart.drain_check_interval = Duration::from_secs(3600);
        let pool = Pool::start(Vec::new(), options).await.unwrap();
        let mut workers = Vec::new();
        let mut jobs = Vec::new();
        for id in 1..=2 {
            let (worker, rx) = Worker::new(id, WarpConfig::default(), None);
            worker.inner.lock().unwrap().net = Some(crate::netstack::NetHandle::test_handle());
            *worker.ready_since.lock().unwrap() = Some(Instant::now());
            pool.workers.lock().unwrap().push(worker.clone());
            workers.push(worker);
            jobs.push(rx);
        }
        (pool, workers, jobs)
    }

    #[test]
    fn independent_triggers_and_disabled_policy() {
        let mut usage = RestartUsage::default();
        usage.connections = 4;
        usage.identities.insert(1);
        let mut policy = RestartPolicy {
            max_uptime: Duration::ZERO,
            max_users: 0,
            max_connections: 0,
        };
        assert!(!usage.reached(policy));
        policy.max_users = 1;
        assert!(usage.reached(policy));
        policy.max_users = 2;
        assert!(!usage.reached(policy));
        policy.max_connections = 4;
        assert!(usage.reached(policy));
    }

    #[tokio::test]
    async fn threshold_immediately_drains_and_existing_user_moves_without_moving_back() {
        let (pool, workers, _jobs) = mock_pool(2, 0, Duration::ZERO, 1).await;
        let first = pool.checkout(Some("alice"), "192.0.2.1").unwrap();
        assert_eq!(first.worker_id, 1);
        let trigger = pool
            .lease(workers[0].clone(), Some("bob"), "192.0.2.2")
            .unwrap();
        assert!(workers[0].draining.load(Ordering::Relaxed));
        assert_eq!(workers[0].active.load(Ordering::Relaxed), 2);
        assert_eq!(pool.status().drain_queue, vec![1]);
        let second = pool.checkout(Some("alice"), "192.0.2.1").unwrap();
        assert_eq!(second.worker_id, 2);
        assert_eq!(pool.status().accounts[0].restart_users, 2);
        assert_eq!(pool.status().accounts[0].restart_connections, 2);
        // 清空 A 的排空状态仅用于验证映射行为；B 的黏性不会自动迁回 A。
        workers[0].draining.store(false, Ordering::Relaxed);
        assert_eq!(pool.scheduler.user_counts().get(&2), Some(&1));
        assert_eq!(
            pool.checkout(Some("alice"), "192.0.2.1").unwrap().worker_id,
            2
        );
        // B 继续接收新用户后也达到上限：两个实例排空时才会拒绝请求。
        workers[0].draining.store(true, Ordering::Relaxed);
        let _other = pool
            .lease(workers[1].clone(), Some("carol"), "192.0.2.3")
            .unwrap();
        assert!(pool.checkout(Some("alice"), "192.0.2.1").is_err());
        drop((first, trigger, second));
    }

    #[tokio::test]
    async fn long_connections_keep_worker_draining_until_closed() {
        let (pool, workers, _jobs) = mock_pool(0, 1, Duration::ZERO, 1).await;
        let lease = pool.checkout(Some("alice"), "192.0.2.1").unwrap();
        pool.inspect_restart_queues();
        assert_eq!(pool.status().drain_queue, vec![1]);
        assert!(pool.status().restart_queue.is_empty());
        assert_eq!(workers[0].active.load(Ordering::Relaxed), 1);
        drop(lease);
        // 占住唯一重启名额，确认活跃数为零时只入队而不会直接发起重连。
        let permit = pool.restart_limit.clone().acquire_owned().await.unwrap();
        pool.inspect_restart_queues();
        assert!(pool.status().drain_queue.is_empty());
        assert_eq!(pool.status().restart_queue, vec![1]);
        drop(permit);
    }

    #[tokio::test]
    async fn pending_always_blocks_new_leases_even_if_draining_flag_is_cleared() {
        let (pool, workers, _jobs) = mock_pool(0, 0, Duration::ZERO, 1).await;
        workers[0].restart_pending.store(true, Ordering::Release);
        workers[0].draining.store(false, Ordering::Release);
        assert!(!workers[0].is_ready());
        assert!(pool
            .lease(workers[0].clone(), Some("alice"), "192.0.2.1")
            .is_none());
        workers[0].retire_if_not_pending();
        assert!(workers[0].net().is_some());
    }

    #[tokio::test]
    async fn concurrency_is_bounded_and_queue_is_deduplicated() {
        let (pool, workers, mut jobs) = mock_pool(0, 1, Duration::ZERO, 1).await;
        let first = pool.checkout(None, "192.0.2.1").unwrap();
        let second = pool.checkout(None, "192.0.2.2").unwrap();
        drop((first, second));
        pool.inspect_restart_queues();
        pool.inspect_restart_queues();
        tokio::task::yield_now().await;
        assert_eq!(
            pool.status().drain_queue.len() + pool.status().restart_queue.len(),
            1
        );
        assert!(workers[0].restart_busy.load(Ordering::Relaxed));
        let received = jobs[0].try_recv().unwrap();
        assert!(jobs[1].try_recv().is_err());
        let _ = received.reply.send(Ok(()));
        tokio::task::yield_now().await;
    }

    #[tokio::test]
    async fn manual_restart_drains_immediately_and_respects_concurrency() {
        let (pool, workers, mut jobs) = mock_pool(0, 2, Duration::ZERO, 1).await;
        let permit = pool.restart_limit.clone().acquire_owned().await.unwrap();
        let pending = tokio::spawn({
            let pool = pool.clone();
            async move { pool.restart_one(1).await }
        });
        tokio::task::yield_now().await;
        assert!(workers[0].draining.load(Ordering::Relaxed));
        assert!(workers[0].restart_busy.load(Ordering::Relaxed));
        assert!(jobs[0].try_recv().is_err());
        pool.set_restart_policy(None, None, Some(0)).unwrap();
        // 关闭自动阈值不能取消正在等待并发名额的手动强制重启。
        assert!(workers[0].restart_pending.load(Ordering::Relaxed));
        assert!(workers[0].restart_busy.load(Ordering::Relaxed));
        assert_eq!(pool.checkout(None, "192.0.2.1").unwrap().worker_id, 2);
        drop(permit);
        let job = tokio::time::timeout(Duration::from_secs(1), jobs[0].recv())
            .await
            .unwrap()
            .unwrap();
        let _ = job.reply.send(Err("模拟重连失败".into()));
        assert!(pending.await.unwrap().is_err());
        assert!(!workers[0].restart_busy.load(Ordering::Relaxed));
        assert!(workers[0].draining.load(Ordering::Relaxed));
    }

    #[tokio::test]
    async fn removing_worker_wakes_manual_restart_waiting_for_permit() {
        let (pool, workers, mut jobs) = mock_pool(0, 0, Duration::ZERO, 1).await;
        let permit = pool.restart_limit.clone().acquire_owned().await.unwrap();
        let task = tokio::spawn({
            let pool = pool.clone();
            async move { pool.restart_one(1).await }
        });
        tokio::time::timeout(Duration::from_secs(1), async {
            while !workers[0].restart_busy.load(Ordering::Acquire) {
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();
        assert!(jobs[0].try_recv().is_err());
        pool.remove_account(1).unwrap();
        let result = tokio::time::timeout(Duration::from_secs(1), task)
            .await
            .expect("实例被移除时不应继续等待重启名额")
            .unwrap();
        assert!(result.unwrap_err().contains("已移除"));
        drop(permit);
    }

    #[tokio::test]
    async fn reconnect_waiting_for_slot_prioritizes_manual_job() {
        let (pool, workers, _jobs) = mock_pool(0, 0, Duration::ZERO, 1).await;
        let worker = workers[0].clone();
        worker.restart_pending.store(true, Ordering::Relaxed);
        worker.restart_attempted.store(true, Ordering::Relaxed);
        let permit = pool.restart_limit.clone().acquire_owned().await.unwrap();
        let (tx, mut rx) = mpsc::unbounded_channel();
        let weak = Arc::downgrade(&pool);
        let task =
            tokio::spawn(async move { super::reconnect_loop(&weak, &worker, &mut rx).await });
        tokio::task::yield_now().await;
        workers[0].restart_busy.store(true, Ordering::Release);
        let (reply, result) = tokio::sync::oneshot::channel();
        tx.send(super::RestartJob {
            reply,
            probe_timeout: Duration::ZERO,
        })
        .unwrap();
        // 并发名额仍被测试持有，监督器也必须能直接执行已放行的手动任务。
        assert!(tokio::time::timeout(Duration::from_secs(1), result)
            .await
            .unwrap()
            .unwrap()
            .is_err());
        assert!(task.await.unwrap());
        drop(permit);
    }

    #[tokio::test]
    async fn runtime_changes_apply_to_current_usage() {
        let (pool, workers, _jobs) = mock_pool(0, 0, Duration::ZERO, 1).await;
        let _lease = pool.checkout(Some("alice"), "192.0.2.1").unwrap();
        pool.set_restart_policy(None, None, Some(1)).unwrap();
        assert!(workers[0].draining.load(Ordering::Relaxed));
        assert_eq!(pool.status().drain_queue, vec![1]);
        assert_eq!(pool.status().restart_max_connections, 1);
    }

    #[tokio::test]
    async fn disabling_all_thresholds_cancels_draining_without_closing_old_connections() {
        let (pool, workers, _jobs) = mock_pool(0, 1, Duration::ZERO, 1).await;
        workers[0].warp_ready.store(true, Ordering::Relaxed);
        let old = pool
            .lease(workers[0].clone(), Some("alice"), "192.0.2.1")
            .unwrap();
        assert_eq!(pool.status().drain_queue, vec![1]);
        pool.set_restart_policy(None, None, Some(0)).unwrap();
        assert!(pool.status().drain_queue.is_empty());
        assert!(pool.status().restart_queue.is_empty());
        assert!(!workers[0].restart_pending.load(Ordering::Relaxed));
        assert!(!workers[0].draining.load(Ordering::Relaxed));
        assert_eq!(workers[0].active.load(Ordering::Relaxed), 1);
        assert_eq!(workers[0].usage.lock().unwrap().connections, 0);
        let next = pool
            .lease(workers[0].clone(), Some("alice"), "192.0.2.1")
            .unwrap();
        assert_eq!(next.worker_id, old.worker_id);
        drop((old, next));
        // 关闭后建立的连接也在累计统计里，重新启用时会应用现有累计值。
        pool.set_restart_policy(None, None, Some(2)).unwrap();
        assert!(!workers[0].restart_pending.load(Ordering::Relaxed));
        let next = pool
            .lease(workers[0].clone(), Some("bob"), "192.0.2.2")
            .unwrap();
        assert!(workers[0].restart_pending.load(Ordering::Relaxed));
        drop(next);
    }

    #[tokio::test]
    async fn disabling_all_thresholds_cancels_ready_queue_before_reconnect() {
        let (pool, workers, mut jobs) = mock_pool(0, 1, Duration::ZERO, 1).await;
        workers[0].warp_ready.store(true, Ordering::Relaxed);
        let permit = pool.restart_limit.clone().acquire_owned().await.unwrap();
        let lease = pool
            .lease(workers[0].clone(), Some("alice"), "192.0.2.1")
            .unwrap();
        drop(lease);
        pool.inspect_restart_queues();
        assert_eq!(pool.status().restart_queue, vec![1]);
        pool.set_restart_policy(None, None, Some(0)).unwrap();
        assert!(pool.status().drain_queue.is_empty());
        assert!(pool.status().restart_queue.is_empty());
        assert!(!workers[0].restart_pending.load(Ordering::Relaxed));
        drop(permit);
        pool.inspect_restart_queues();
        tokio::task::yield_now().await;
        assert!(jobs[0].try_recv().is_err());
    }

    #[tokio::test]
    async fn cancelling_unverified_drain_does_not_expose_tunnel() {
        let (pool, workers, _jobs) = mock_pool(0, 1, Duration::ZERO, 1).await;
        let old = pool
            .lease(workers[0].clone(), Some("alice"), "192.0.2.1")
            .unwrap();
        pool.set_restart_policy(None, None, Some(0)).unwrap();
        assert!(!workers[0].restart_pending.load(Ordering::Relaxed));
        assert!(workers[0].draining.load(Ordering::Relaxed));
        assert!(workers[0].ready_since.lock().unwrap().is_none());
        assert!(pool
            .lease(workers[0].clone(), Some("alice"), "192.0.2.1")
            .is_none());
        drop(old);
    }

    #[tokio::test]
    async fn failed_restart_enters_background_retry() {
        let (pool, mut workers, mut receivers) = mock_pool(0, 0, Duration::ZERO, 1).await;
        let worker = workers.remove(0);
        worker.warp_ready.store(true, Ordering::Relaxed);
        let supervisor = tokio::spawn(super::supervise(
            Arc::downgrade(&pool),
            worker.clone(),
            receivers.remove(0),
        ));
        // 测试账号没有有效密钥，实际重启会失败；此后应进入后台循环继续尝试。
        assert!(pool.restart_one(worker.id).await.is_err());
        tokio::time::timeout(Duration::from_secs(3), async {
            loop {
                if pool
                    .logs()
                    .lines
                    .iter()
                    .any(|line| line.text.contains("尚未就绪"))
                {
                    break;
                }
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("失败后应进入后台重试，而不是卡在等待重启指令");
        assert!(worker.restart_pending.load(Ordering::Relaxed));
        pool.remove_account(worker.id).unwrap();
        tokio::time::timeout(Duration::from_secs(1), supervisor)
            .await
            .expect("移除后重试任务应退出")
            .unwrap();
    }

    #[tokio::test]
    async fn automatic_restart_failure_retries_after_releasing_execution_slot() {
        let (pool, mut workers, mut receivers) = mock_pool(0, 1, Duration::ZERO, 1).await;
        let worker = workers.remove(0);
        worker.warp_ready.store(true, Ordering::Relaxed);
        let (dead_tx, dead_rx) = watch::channel(false);
        worker.inner.lock().unwrap().dead = Some(dead_rx);
        let supervisor = tokio::spawn(super::supervise(
            Arc::downgrade(&pool),
            worker.clone(),
            receivers.remove(0),
        ));
        let lease = pool
            .lease(worker.clone(), Some("alice"), "192.0.2.1")
            .unwrap();
        drop(lease);
        pool.inspect_restart_queues();
        tokio::time::timeout(Duration::from_secs(3), async {
            loop {
                if pool
                    .logs()
                    .lines
                    .iter()
                    .any(|line| line.text.contains("尚未就绪"))
                {
                    break;
                }
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("自动重启失败后应释放名额并进入后台重试");
        assert!(worker.restart_pending.load(Ordering::Relaxed));
        assert!(!worker.restart_busy.load(Ordering::Relaxed));
        pool.remove_account(worker.id).unwrap();
        tokio::time::timeout(Duration::from_secs(1), supervisor)
            .await
            .unwrap()
            .unwrap();
        drop(dead_tx);
    }

    #[tokio::test]
    async fn supervisor_recovers_after_cancelling_queued_drain() {
        let (pool, mut workers, mut receivers) = mock_pool(0, 1, Duration::ZERO, 1).await;
        let worker = workers.remove(0);
        worker.warp_ready.store(true, Ordering::Relaxed);
        let (dead_tx, dead_rx) = watch::channel(false);
        worker.inner.lock().unwrap().dead = Some(dead_rx);
        let supervisor = tokio::spawn(super::supervise(
            Arc::downgrade(&pool),
            worker.clone(),
            receivers.remove(0),
        ));
        let lease = pool
            .lease(worker.clone(), Some("alice"), "192.0.2.1")
            .unwrap();
        assert!(worker.restart_pending.load(Ordering::Relaxed));
        pool.set_restart_policy(None, None, Some(0)).unwrap();
        assert!(!worker.restart_pending.load(Ordering::Relaxed));
        assert!(worker.is_ready());
        tokio::task::yield_now().await;
        assert!(worker.net().is_some());
        assert!(!supervisor.is_finished());
        pool.remove_account(worker.id).unwrap();
        tokio::time::timeout(Duration::from_secs(1), supervisor)
            .await
            .unwrap()
            .unwrap();
        drop((lease, dead_tx));
    }

    #[tokio::test]
    async fn background_retry_obeys_restart_concurrency() {
        let (pool, mut workers, mut receivers) = mock_pool(0, 0, Duration::ZERO, 1).await;
        let worker = workers.remove(0);
        worker.warp_ready.store(true, Ordering::Relaxed);
        worker.restart_pending.store(true, Ordering::Relaxed);
        worker.restart_attempted.store(true, Ordering::Relaxed);
        let permit = pool.restart_limit.clone().acquire_owned().await.unwrap();
        let supervisor = tokio::spawn(super::supervise(
            Arc::downgrade(&pool),
            worker.clone(),
            receivers.remove(0),
        ));
        tokio::task::yield_now().await;
        assert!(!pool
            .logs()
            .lines
            .iter()
            .any(|line| line.text.contains("尚未就绪")));
        drop(permit);
        tokio::time::timeout(Duration::from_secs(3), async {
            loop {
                if pool
                    .logs()
                    .lines
                    .iter()
                    .any(|line| line.text.contains("尚未就绪"))
                {
                    break;
                }
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("释放重启名额后应恢复后台尝试");
        pool.remove_account(worker.id).unwrap();
        tokio::time::timeout(Duration::from_secs(1), supervisor)
            .await
            .unwrap()
            .unwrap();
    }

    #[tokio::test]
    async fn removing_draining_worker_stops_supervisor() {
        let (pool, mut workers, mut receivers) = mock_pool(0, 1, Duration::ZERO, 1).await;
        let worker = workers.remove(0);
        worker.warp_ready.store(true, Ordering::Relaxed);
        let supervisor = tokio::spawn(super::supervise(
            Arc::downgrade(&pool),
            worker.clone(),
            receivers.remove(0),
        ));
        let lease = pool
            .lease(worker.clone(), Some("alice"), "192.0.2.1")
            .unwrap();
        assert_eq!(pool.status().drain_queue, vec![1]);
        pool.remove_account(worker.id).unwrap();
        tokio::time::timeout(Duration::from_secs(1), supervisor)
            .await
            .expect("排空中的实例移除后监督任务必须退出")
            .unwrap();
        drop(lease);
    }

    #[test]
    fn first_confirmed_connection_starts_uptime_without_resetting_it_again() {
        let (worker, _rx) = Worker::new(1, WarpConfig::default(), None);
        assert!(worker.ready_since.lock().unwrap().is_none());
        worker.mark_initial_ready();
        assert!(worker.ready_since.lock().unwrap().is_some());
        let original = Instant::now() - Duration::from_secs(10);
        *worker.ready_since.lock().unwrap() = Some(original);
        worker.mark_initial_ready();
        assert_eq!(*worker.ready_since.lock().unwrap(), Some(original));
    }

    #[tokio::test]
    async fn uptime_from_last_success_and_statistics_reset() {
        let (pool, workers, _jobs) = mock_pool(0, 0, Duration::from_secs(1), 1).await;
        *workers[0].ready_since.lock().unwrap() = Some(Instant::now() - Duration::from_secs(2));
        pool.inspect_restart_queues();
        assert!(workers[0].draining.load(Ordering::Relaxed));
        pool.finish_reconnect(&workers[0]);
        assert!(!workers[0].restart_pending.load(Ordering::Relaxed));
        assert!(!workers[0].draining.load(Ordering::Relaxed));
        assert!(workers[0].uptime() < Duration::from_secs(1));
        assert_eq!(workers[0].usage.lock().unwrap().connections, 0);
        assert!(workers[0].usage.lock().unwrap().identities.is_empty());
    }

    #[tokio::test]
    async fn removing_instance_cleans_queues() {
        let (pool, _workers, _jobs) = mock_pool(0, 1, Duration::ZERO, 1).await;
        let lease = pool.checkout(Some("alice"), "192.0.2.1").unwrap();
        assert_eq!(pool.status().drain_queue, vec![1]);
        pool.remove_account(1).unwrap();
        assert!(pool.status().drain_queue.is_empty());
        assert!(pool.status().restart_queue.is_empty());
        drop(lease);
    }

    #[tokio::test]
    async fn disabling_user_threshold_drops_cached_identities() {
        let (pool, workers, _jobs) = mock_pool(100, 0, Duration::ZERO, 1).await;
        let _lease = pool.checkout(Some("alice"), "192.0.2.1").unwrap();
        assert_eq!(workers[0].usage.lock().unwrap().identities.len(), 1);
        pool.set_restart_policy(None, Some(0), None).unwrap();
        assert!(workers[0].usage.lock().unwrap().identities.is_empty());
        pool.set_restart_policy(None, Some(1_000_001), None)
            .unwrap_err();
        assert_eq!(pool.status().restart_max_users, 0);
    }

    #[tokio::test]
    async fn drain_is_not_interrupted_by_direct_reconnect_notifications() {
        let (pool, workers, _jobs) = mock_pool(0, 1, Duration::ZERO, 1).await;
        let _lease = pool.checkout(Some("alice"), "192.0.2.1").unwrap();
        assert!(workers[0].draining.load(Ordering::Relaxed));
        pool.reconnect(1);
        // 手动重连通知在排空期间被忽略，不得把排空实例提前带入重连流程。
        assert!(workers[0].draining.load(Ordering::Relaxed));
        assert!(!workers[0].restart_attempted.load(Ordering::Relaxed));
        assert!(workers[0].restart_pending.load(Ordering::Relaxed));
    }
}

#[cfg(test)]
mod egress_tests {
    use super::{egress_for_family, egress_parts, shown_egress, TraceInfo};

    fn info(ip: &str, warp: &str, loc: &str, colo: &str) -> TraceInfo {
        TraceInfo {
            ip: ip.into(),
            warp: warp.into(),
            loc: loc.into(),
            colo: colo.into(),
            err: None,
        }
    }

    #[test]
    fn place_prefers_ipv4_and_falls_back_to_ipv6() {
        let v4 = info("1.2.3.4", "on", "US", "SJC");
        let v6 = info("2a09:bac::1", "on", "JP", "NRT");
        let (ipv4, ipv6, country, colo, warp) = egress_parts(Some(&v4), Some(&v6));
        assert_eq!(ipv4, "1.2.3.4");
        assert_eq!(ipv6, "2a09:bac::1");
        assert_eq!(country, "US");
        assert_eq!(colo, "SJC");
        assert_eq!(warp, "on");

        let failed = TraceInfo {
            err: Some("trace timeout".into()),
            ..TraceInfo::default()
        };
        let (ipv4, ipv6, country, colo, warp) = egress_parts(Some(&failed), Some(&v6));
        assert_eq!(ipv4, "");
        assert_eq!(ipv6, "2a09:bac::1");
        assert_eq!(country, "JP");
        assert_eq!(colo, "NRT");
        assert_eq!(warp, "on");
    }

    #[test]
    fn access_log_uses_the_family_that_was_connected() {
        assert_eq!(
            egress_for_family("ipv6", "104.28.233.73", "2a09:bac::1", "104.28.233.73"),
            "2a09:bac::1"
        );
        assert_eq!(
            egress_for_family("ipv4", "104.28.233.73", "2a09:bac::1", "104.28.233.73"),
            "104.28.233.73"
        );
        assert_eq!(
            egress_for_family("ipv6", "104.28.233.73", "", "104.28.233.73"),
            "-"
        );
    }

    #[test]
    fn lease_keeps_ipv6_even_when_the_fallback_is_ipv4() {
        let shown = shown_egress(
            "104.28.233.73",
            "2a09:bac::1",
            "172.16.0.2",
            "2606:4700:110::1",
        );
        assert_eq!(shown.fallback, "104.28.233.73");
        assert_eq!(
            egress_for_family("ipv6", &shown.v4, &shown.v6, &shown.fallback),
            "2a09:bac::1"
        );
        assert_eq!(
            egress_for_family("ipv4", &shown.v4, &shown.v6, &shown.fallback),
            "104.28.233.73"
        );

        let assigned = shown_egress("", "", "172.16.0.2", "2606:4700:110::1");
        assert_eq!(assigned.fallback, "172.16.0.2");
        assert_eq!(
            egress_for_family("ipv6", &assigned.v4, &assigned.v6, &assigned.fallback),
            "2606:4700:110::1"
        );

        let missing = shown_egress("104.28.233.73", "", "172.16.0.2", "");
        assert_eq!(
            egress_for_family("ipv6", &missing.v4, &missing.v6, &missing.fallback),
            "-"
        );
    }
}

#[cfg(test)]
mod temporary_account_tests {
    use super::{
        account_path, forget_saved_temporary, read_temporary_active, remember_saved_temporary,
        saved_account_ids, spare_account_id, Pool, PoolOptions, WarpConfig,
    };

    #[test]
    fn spare_skips_running_and_base_accounts() {
        let saved = [1usize, 2, 11, 12];
        assert_eq!(spare_account_id(&saved, &[1, 2, 12], &[1, 2]), Some(11));
        assert_eq!(spare_account_id(&saved, &[1, 2], &[1, 2, 11, 12]), None);
        assert_eq!(spare_account_id(&saved, &[], &[]), Some(1));
    }

    #[test]
    fn removing_a_temporary_account_keeps_its_config() {
        let dir = std::env::temp_dir().join(format!("warp-proxy-temporary-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let path = account_path(&dir, 7);
        std::fs::write(&path, "kept").unwrap();
        remember_saved_temporary(&dir, 7).unwrap();
        remember_saved_temporary(&dir, 8).unwrap();
        assert_eq!(read_temporary_active(&dir).unwrap(), vec![7, 8]);
        forget_saved_temporary(&dir, 7).unwrap();
        assert_eq!(std::fs::read_to_string(&path).unwrap(), "kept");
        assert_eq!(read_temporary_active(&dir).unwrap(), vec![8]);
        assert_eq!(saved_account_ids(&dir), vec![7]);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn imported_accounts_wait_when_instance_count_is_reached() {
        let dir = std::env::temp_dir().join(format!(
            "warp-proxy-import-limit-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let state_dir = dir.join("state");
        std::fs::create_dir_all(&state_dir).unwrap();
        let base_config = WarpConfig {
            id: "base".into(),
            ..WarpConfig::default()
        };
        base_config.save(account_path(&state_dir, 1)).unwrap();
        WarpConfig {
            id: "previously-imported".into(),
            ..WarpConfig::default()
        }
        .save(account_path(&state_dir, 2))
        .unwrap();
        remember_saved_temporary(&state_dir, 2).unwrap();
        let imported_config = WarpConfig {
            id: "microwarp-device".into(),
            private_key: "key".into(),
            ..WarpConfig::default()
        };
        let source_dir = dir.join("microwarp/instances/0");
        std::fs::create_dir_all(&source_dir).unwrap();
        imported_config
            .save(source_dir.join("masque-config.json"))
            .unwrap();

        let mut options = PoolOptions::basic(true);
        options.state_dir = Some(state_dir.clone());
        options.auto_restore_limit = Some(1);
        let pool = Pool::start(vec![base_config], options).await.unwrap();
        assert_eq!(pool.status().accounts.len(), 1);
        assert_eq!(
            pool.scan_microwarp(&dir.join("microwarp")).await.unwrap(),
            1
        );
        assert_eq!(pool.status().accounts.len(), 1);
        assert_eq!(read_temporary_active(&state_dir).unwrap(), vec![2, 3]);
        assert!(account_path(&state_dir, 3).is_file());

        pool.restore_temporary().await;
        assert_eq!(pool.status().accounts.len(), 1);
        std::fs::remove_dir_all(dir).unwrap();
    }
}
