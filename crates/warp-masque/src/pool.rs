//! 多账号连接池。每个账号一条 MASQUE 隧道和一个出口地址，前面用同一入口做调度。
//!
//! 上游 SOCKS5、黏性、保身份重启都发生在这个进程里。账号身份保存在各自的
//! WarpConfig 中；保身份重启只重连隧道，不重新注册。

use std::collections::hash_map::RandomState;
use std::collections::HashSet;
use std::hash::BuildHasher;
use std::net::{Ipv4Addr, SocketAddr};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicU8, AtomicUsize, Ordering};
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

#[derive(Clone, Copy, PartialEq, Eq)]
enum WakeReason {
    None,
    /// 间隔、批量或延后被改过，重新计时。
    Plan,
    /// 暂停、恢复或立即执行，不重置倒计时。
    Control,
}

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

/// 保身份重启参数。interval 为 0 时不定时重启。
/// batch 是每一轮重启几个账号，0 表示这一轮包含当前全部账号。
/// 连上隧道之后必须看到 warp=on 或 warp=plus，否则按退避一直重试。
#[derive(Clone, Debug)]
pub struct RestartConfig {
    pub mode: RestartMode,
    pub threshold: usize,
    pub interval: Duration,
    pub probe_timeout: Duration,
    /// 已经开始重连后，最多再等现有连接这么久，到点就强制重连。
    pub force_after: Duration,
    pub concurrency: usize,
    pub batch: usize,
    /// 计划重启时，账号仍有连接就延后这么久再试。0 表示不延后，直接排空。
    pub defer: Duration,
    /// 上一轮拖过下次时间时，立刻补跑或跳到下一个间隔点。
    pub misfire: Misfire,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RestartMode {
    Scheduled,
    Users,
    Connections,
}

impl RestartMode {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Scheduled => "scheduled",
            Self::Users => "users",
            Self::Connections => "connections",
        }
    }
}

pub fn parse_restart_mode(value: &str) -> Result<RestartMode, String> {
    match value.trim().to_ascii_lowercase().as_str() {
        "scheduled" => Ok(RestartMode::Scheduled),
        "users" => Ok(RestartMode::Users),
        "connections" => Ok(RestartMode::Connections),
        other => Err(format!(
            "未知 ROTATE_RESTART_MODE={other}（scheduled|users|connections）"
        )),
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct RestartPolicy {
    mode: RestartMode,
    threshold: usize,
}

impl RestartPolicy {
    fn validate(self) -> Result<(), String> {
        if self.mode != RestartMode::Scheduled && self.threshold == 0 {
            return Err("按用户数或连接数重启时，阈值必须大于 0".into());
        }
        Ok(())
    }
}

/// 一轮超过间隔后怎么处理错过的那次。
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum Misfire {
    /// 结束后立刻补跑一轮。错过的多个整点合成这一次。
    Fire = 0,
    /// 不补跑，下次排到仍在未来的下一个间隔点。
    Skip = 1,
}

impl Misfire {
    pub fn as_str(self) -> &'static str {
        match self {
            Misfire::Fire => "fire",
            Misfire::Skip => "skip",
        }
    }
}

/// 解析 ROTATE_RESTART_MISFIRE。fire 立刻补跑，skip 跳过。
pub fn parse_misfire(value: &str) -> Result<Misfire, String> {
    match value.trim().to_ascii_lowercase().as_str() {
        "fire" => Ok(Misfire::Fire),
        "skip" => Ok(Misfire::Skip),
        other => Err(format!("未知 ROTATE_RESTART_MISFIRE={other}（fire|skip）")),
    }
}

impl Default for RestartConfig {
    fn default() -> Self {
        Self {
            mode: RestartMode::Scheduled,
            threshold: 0,
            interval: Duration::ZERO,
            probe_timeout: Duration::from_secs(15),
            force_after: Duration::from_secs(60),
            concurrency: 1,
            batch: 1,
            defer: Duration::ZERO,
            misfire: Misfire::Fire,
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
    force_after: Duration,
}

/// 一个账号：配置、隧道、以及当前是否接新连接。
pub struct Worker {
    id: usize,
    rebuild: Notify,
    restart_tx: mpsc::UnboundedSender<RestartJob>,
    draining: AtomicBool,
    restart_pending: AtomicBool,
    accept_existing_users: AtomicBool,
    usage: Mutex<RestartUsage>,
    user_hash: RandomState,
    /// 计划重启因为仍有连接而被推迟。
    deferred: AtomicBool,
    active: AtomicUsize,
    /// 人工停用后不再接新连接，已有连接继续走完。
    manual: AtomicBool,
    temporary: AtomicBool,
    /// 已从池中移除。监督任务看到后退出，避免同一身份再建一条隧道。
    stopped: AtomicBool,
    /// 曾经确认过 warp=on 或 warp=plus。之后的出口检查失败不会拆隧道。
    warp_ready: AtomicBool,
    born: Instant,
    stage: Mutex<String>,
    stage_at: Mutex<Option<Instant>>,
    last_action: Mutex<String>,
    upstream: Option<UpstreamProxy>,
    inner: Mutex<WorkerInner>,
}

#[derive(Default)]
struct RestartUsage {
    connections: u64,
    users: HashSet<u64>,
}

impl RestartUsage {
    fn reached(&self, policy: RestartPolicy) -> bool {
        match policy.mode {
            RestartMode::Scheduled => false,
            RestartMode::Users => self.users.len() >= policy.threshold,
            RestartMode::Connections => self.connections >= policy.threshold as u64,
        }
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
            accept_existing_users: AtomicBool::new(false),
            usage: Mutex::new(RestartUsage::default()),
            user_hash: RandomState::new(),
            deferred: AtomicBool::new(false),
            active: AtomicUsize::new(0),
            manual: AtomicBool::new(true),
            temporary: AtomicBool::new(false),
            stopped: AtomicBool::new(false),
            warp_ready: AtomicBool::new(false),
            born: Instant::now(),
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
        self.warp_ready.store(false, Ordering::Relaxed);
        let mut inner = self.inner.lock().unwrap();
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
            && !self.draining.load(Ordering::Relaxed)
            && self.inner.lock().unwrap().net.is_some()
    }

    fn user_identity(&self, username: Option<&str>, client_ip: &str) -> u64 {
        let (kind, user) = match username.filter(|user| !user.is_empty()) {
            Some(user) => ("user", user),
            None => ("ip", client_ip),
        };
        self.user_hash.hash_one((kind, user))
    }

    fn accepts_existing_user(&self, username: Option<&str>, client_ip: &str) -> bool {
        if !self.accept_existing_users.load(Ordering::Relaxed)
            || !self.manual.load(Ordering::Relaxed)
            || self.stopped.load(Ordering::Relaxed)
        {
            return false;
        }
        let identity = self.user_identity(username, client_ip);
        let inner = self.inner.lock().unwrap();
        inner.net.is_some()
            && self.accept_existing_users.load(Ordering::Relaxed)
            && self.usage.lock().unwrap().users.contains(&identity)
    }

    fn begin_draining(&self) {
        let _inner = self.inner.lock().unwrap();
        self.accept_existing_users.store(false, Ordering::Relaxed);
        self.draining.store(true, Ordering::Relaxed);
    }

    fn queue_if_reached(&self, usage: &RestartUsage, policy: RestartPolicy) -> bool {
        if self.restart_pending.load(Ordering::Relaxed)
            || self.draining.load(Ordering::Relaxed)
            || self.stopped.load(Ordering::Relaxed)
            || !self.manual.load(Ordering::Relaxed)
            || !usage.reached(policy)
        {
            return false;
        }
        self.restart_pending.store(true, Ordering::Relaxed);
        self.accept_existing_users
            .store(policy.mode == RestartMode::Users, Ordering::Relaxed);
        self.draining.store(true, Ordering::Relaxed);
        self.set_stage("等待重启");
        self.note("达到阈值，等待重启");
        true
    }

    fn reset_usage(&self) {
        let _inner = self.inner.lock().unwrap();
        *self.usage.lock().unwrap() = RestartUsage::default();
        self.restart_pending.store(false, Ordering::Relaxed);
        self.accept_existing_users.store(false, Ordering::Relaxed);
        self.draining.store(false, Ordering::Relaxed);
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

/// 账号池和入口调度状态。
pub struct Pool {
    workers: Mutex<Vec<Arc<Worker>>>,
    initializing: AtomicBool,
    expected_accounts: usize,
    enabled: AtomicBool,
    pinned: AtomicUsize,
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
    threshold_tx: mpsc::UnboundedSender<usize>,
    health_interval: Duration,
    health_timeout: Duration,
    restart_limit: Arc<Semaphore>,
    connect_limit: Semaphore,
    /// 运行中可改的保身份重启间隔。0 表示关闭计划。
    restart_interval: Mutex<Duration>,
    /// 错过整点时补跑或跳过。见 Misfire。
    restart_misfire: AtomicU8,
    /// 每一轮重启几个账号。0 表示当前全部账号。
    restart_batch: AtomicUsize,
    /// 忙碌账号延后重启的时间。0 表示到点就排空。
    restart_defer: Mutex<Duration>,
    restart_wake: Arc<Notify>,
    restart_paused: AtomicBool,
    restart_now: AtomicBool,
    wake_reason: Mutex<WakeReason>,
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
        let policy = RestartPolicy {
            mode: opts.restart.mode,
            threshold: opts.restart.threshold,
        };
        policy.validate().map_err(crate::Error::Config)?;
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
        let (pool, threshold_rx) = Self::create(opts, configs.len())?;
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
        Self::spawn_tasks(&pool, threshold_rx);
        Ok(pool)
    }

    /// 先建立可用的控制面，账号可随后逐个加载并在后台并发拨号。
    pub fn start_deferred(opts: PoolOptions, base_count: usize) -> crate::Result<Arc<Pool>> {
        let (pool, threshold_rx) = Self::create(opts, base_count)?;
        *pool.base_ids.lock().unwrap() = (1..=base_count).collect();
        pool.next_id
            .store(base_count.saturating_add(1), Ordering::Relaxed);
        pool.initializing.store(true, Ordering::Relaxed);
        Self::spawn_tasks(&pool, threshold_rx);
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

    fn create(
        opts: PoolOptions,
        expected_accounts: usize,
    ) -> crate::Result<(Arc<Pool>, mpsc::UnboundedReceiver<usize>)> {
        let policy = RestartPolicy {
            mode: opts.restart.mode,
            threshold: opts.restart.threshold,
        };
        policy.validate().map_err(crate::Error::Config)?;
        if !opts.upstream.is_empty() && !opts.http2 {
            return Err(crate::Error::Config(
                "上游 SOCKS5 只支持 TCP，必须使用 HTTP/2（--http2）".into(),
            ));
        }
        let (threshold_tx, threshold_rx) = mpsc::unbounded_channel();
        let pool = Arc::new(Pool {
            workers: Mutex::new(Vec::new()),
            initializing: AtomicBool::new(false),
            expected_accounts,
            enabled: AtomicBool::new(true),
            pinned: AtomicUsize::new(0),
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
            restart_policy: RwLock::new(policy),
            threshold_tx,
            health_interval: opts.health_interval,
            health_timeout: opts.health_timeout,
            restart_limit: Arc::new(Semaphore::new(opts.restart.concurrency.max(1))),
            connect_limit: Semaphore::new(CONNECT_CONCURRENCY),
            restart_interval: Mutex::new(opts.restart.interval),
            restart_misfire: AtomicU8::new(opts.restart.misfire as u8),
            restart_batch: AtomicUsize::new(opts.restart.batch),
            restart_defer: Mutex::new(opts.restart.defer),
            restart_wake: Arc::new(Notify::new()),
            restart_paused: AtomicBool::new(false),
            restart_now: AtomicBool::new(false),
            wake_reason: Mutex::new(WakeReason::None),
            console: Console::new(),
            listen: Mutex::new(String::new()),
            state_dir: opts.state_dir.clone(),
            auto_restore_limit: opts.auto_restore_limit,
            base_ids: Mutex::new(Vec::new()),
            reserved_ids: Mutex::new(Vec::new()),
        });
        Ok((pool, threshold_rx))
    }

    fn spawn_tasks(pool: &Arc<Pool>, threshold_rx: mpsc::UnboundedReceiver<usize>) {
        Pool::spawn_rotator(pool.clone());
        Pool::spawn_restarter(pool.clone());
        Pool::spawn_threshold_restarter(pool.clone(), threshold_rx);
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
        drop(pool);
        tokio::spawn(async move {
            let mut index = 0usize;
            let mut round_at: Option<tokio::time::Instant> = None;
            let mut deferred: Vec<(usize, tokio::time::Instant)> = Vec::new();
            loop {
                let Some(pool) = weak.upgrade() else { return };
                let interval = if pool.restart_policy.read().unwrap().mode == RestartMode::Scheduled
                {
                    *pool.restart_interval.lock().unwrap()
                } else {
                    Duration::ZERO
                };
                let wake = Arc::clone(&pool.restart_wake);
                if interval.is_zero() {
                    round_at = None;
                    pool.console.set_next(None);
                    if deferred.is_empty() && !pool.restart_now.load(Ordering::Relaxed) {
                        pool.console.clear_queues();
                        drop(pool);
                        tokio::select! {
                            _ = tokio::time::sleep(Duration::from_secs(5)) => {}
                            _ = wake.notified() => {}
                        }
                        continue;
                    }
                }
                let now = tokio::time::Instant::now();
                if round_at.is_none() && !interval.is_zero() {
                    round_at = Some(now + interval);
                }
                // 开始等待前就已经过点，说明上一轮把这次整点拖过去了。
                let already_late = round_at.is_some_and(|at| at <= now);
                publish_next(&pool, round_at);
                let next = if pool.restart_now.load(Ordering::Relaxed) {
                    now
                } else {
                    earliest_restart(round_at, &deferred).unwrap_or(now)
                };
                let wait = next.saturating_duration_since(now);
                drop(pool);
                tokio::select! {
                    _ = tokio::time::sleep(wait) => {}
                    _ = wake.notified() => {
                        let Some(pool) = weak.upgrade() else { return };
                        if pool.take_wake() == WakeReason::Plan {
                            round_at = None;
                            deferred.clear();
                            pool.console.clear_queues();
                            continue;
                        }
                    }
                }
                let Some(pool) = weak.upgrade() else { return };
                let now = tokio::time::Instant::now();
                let defer_for = *pool.restart_defer.lock().unwrap();
                let force = pool.restart_now.swap(false, Ordering::Relaxed);
                let paused = pool.restart_paused.load(Ordering::Relaxed);
                let mut due = Vec::new();
                deferred.retain(|(id, at)| {
                    if *at <= now {
                        due.push(*id);
                        false
                    } else {
                        true
                    }
                });
                let round_due = round_at.is_some_and(|at| at <= now);
                if paused && !force {
                    if round_due {
                        round_at = Some(now + interval);
                    }
                    // 暂停期间到期的延后项先放回队列，恢复后再处理。
                    for id in due.drain(..) {
                        schedule_defer(&mut deferred, id, now + Duration::from_secs(5));
                    }
                    publish_next(&pool, round_at);
                    continue;
                }
                match round_action(pool.misfire(), already_late, round_due, force) {
                    RoundAction::Skip => {
                        if let Some(at) = round_at {
                            let next_at = next_future_deadline(at, interval, now);
                            let secs = next_at.saturating_duration_since(now).as_secs();
                            round_at = Some(next_at);
                            let text = format!(
                                "[pool] 上一轮超过间隔，跳过补跑，约 {secs} 秒后进入下一间隔点"
                            );
                            eprintln!("{text}");
                            pool.console.log("plan", text);
                        }
                    }
                    RoundAction::Run => {
                        let ids: Vec<usize> =
                            pool.snapshot().iter().map(|worker| worker.id).collect();
                        let batch = pool.restart_batch.load(Ordering::Relaxed);
                        let (chosen, next_index) = next_restart_batch(&ids, index, batch);
                        index = next_index;
                        for id in chosen {
                            if !due.contains(&id)
                                && !deferred.iter().any(|(pending, _)| *pending == id)
                            {
                                due.push(id);
                            }
                        }
                        if round_due {
                            round_at = Some(now + interval);
                        }
                    }
                    RoundAction::Wait => {}
                }
                publish_next(&pool, round_at);
                if due.is_empty() {
                    let pending: Vec<usize> = deferred.iter().map(|(id, _)| *id).collect();
                    pool.console.set_queues(&[], &pending);
                    continue;
                }
                let workers = pool.snapshot();
                let active = |id: usize| {
                    workers
                        .iter()
                        .find(|worker| worker.id == id)
                        .map(|worker| worker.active.load(Ordering::Relaxed))
                        .unwrap_or(0)
                };
                let (restart_now, later) = split_due_restarts(&due, active, !defer_for.is_zero());
                for id in &later {
                    if let Some(worker) = workers.iter().find(|worker| worker.id == *id) {
                        worker.deferred.store(true, Ordering::Relaxed);
                        worker.set_stage("等待空闲");
                        worker.note("延后重启");
                    }
                    schedule_defer(&mut deferred, *id, now + defer_for);
                    let text = format!(
                        "[pool] 账号 {id} 仍有 {} 个连接，延后 {} 秒再重启",
                        active(*id),
                        defer_for.as_secs()
                    );
                    eprintln!("{text}");
                    pool.console.log("plan", text);
                }
                let pending: Vec<usize> = deferred.iter().map(|(id, _)| *id).collect();
                pool.console.set_queues(&restart_now, &pending);
                if restart_now.is_empty() {
                    continue;
                }
                let label = restart_now
                    .iter()
                    .map(|id| id.to_string())
                    .collect::<Vec<_>>()
                    .join(",");
                let text = format!(
                    "[pool] 计划保身份重启账号 {label}（同时最多 {}）",
                    pool.restart.concurrency.max(1)
                );
                eprintln!("{text}");
                pool.console.log("plan", text);
                let started = Instant::now();
                let mut joins = tokio::task::JoinSet::new();
                for id in restart_now {
                    if let Some(worker) = workers.iter().find(|worker| worker.id == id) {
                        worker.deferred.store(false, Ordering::Relaxed);
                        worker.set_stage("排队");
                    }
                    let pool = Arc::clone(&pool);
                    joins.spawn(async move { pool.restart_one(id).await.is_ok() });
                }
                let mut success = 0usize;
                let mut failed = 0usize;
                while let Some(joined) = joins.join_next().await {
                    match joined {
                        Ok(true) => success += 1,
                        _ => failed += 1,
                    }
                }
                pool.console.finish_round(
                    success,
                    failed,
                    later.len(),
                    started.elapsed().as_millis() as u64,
                );
                pool.console.log(
                    "plan",
                    format!(
                        "一轮结束：成功 {success}，失败 {failed}，延后 {}。失败的账号会继续重试，直到 warp=on",
                        later.len()
                    ),
                );
            }
        });
    }

    fn spawn_threshold_restarter(pool: Arc<Pool>, mut rx: mpsc::UnboundedReceiver<usize>) {
        let weak = Arc::downgrade(&pool);
        drop(pool);
        tokio::spawn(async move {
            while let Some(id) = rx.recv().await {
                let Some(pool) = weak.upgrade() else { return };
                tokio::spawn(async move {
                    if let Err(err) = pool.restart_one_pending(id).await {
                        pool.console
                            .log("plan", format!("账号 {id} 阈值重启失败: {err}"));
                    }
                });
            }
        });
    }

    pub fn enabled(&self) -> bool {
        self.enabled.load(Ordering::Relaxed)
    }

    pub fn set_enabled(&self, on: bool) {
        self.enabled.store(on, Ordering::Relaxed);
    }

    pub fn select(&self, id: usize) {
        self.pinned.store(id, Ordering::Relaxed);
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

    /// 为新连接选择账号。全局 pin 优先；否则按策略和黏性选择。
    pub fn checkout(&self, username: Option<&str>, client_ip: &str) -> Result<ConnLease, PickFail> {
        let workers = self.snapshot();
        let pin = self.pinned.load(Ordering::Relaxed);
        if pin != 0 {
            if let Some(worker) = workers.iter().find(|worker| worker.id == pin) {
                if let Some(lease) = self.lease(worker.clone(), username, client_ip) {
                    return Ok(lease);
                }
            }
        }
        let eligible: Vec<usize> = workers
            .iter()
            .filter(|worker| worker.is_ready() || worker.accepts_existing_user(username, client_ip))
            .map(|worker| worker.id)
            .collect();
        let alive: Vec<usize> = workers.iter().map(|worker| worker.id).collect();
        let id =
            self.scheduler
                .pick(&self.policy, &eligible, &alive, username, client_ip, |id| {
                    workers
                        .iter()
                        .find(|worker| worker.id == id)
                        .map(|worker| worker.active.load(Ordering::Relaxed))
                        .unwrap_or(0)
                })?;
        let worker = workers
            .into_iter()
            .find(|worker| worker.id == id)
            .ok_or(PickFail::NoWorker)?;
        self.lease(worker, username, client_ip)
            .ok_or(PickFail::NoWorker)
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
        let policy = self.restart_policy.read().unwrap();
        let inner = worker.inner.lock().unwrap();
        if !worker.manual.load(Ordering::Relaxed) || worker.stopped.load(Ordering::Relaxed) {
            return None;
        }
        let net = inner.net.clone()?;
        let mut usage = worker.usage.lock().unwrap();
        let identity =
            (policy.mode == RestartMode::Users).then(|| worker.user_identity(username, client_ip));
        if worker.draining.load(Ordering::Relaxed)
            && !(worker.accept_existing_users.load(Ordering::Relaxed)
                && identity.is_some_and(|identity| usage.users.contains(&identity)))
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
        if let Some(identity) = identity {
            usage.users.insert(identity);
        }
        let queued = worker.queue_if_reached(&usage, *policy);
        drop(usage);
        drop(inner);
        let mode = policy.mode;
        drop(policy);
        if queued {
            self.queue_threshold_restart(worker.id, mode);
        }
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
            if id == 0 || worker.id == id {
                worker.rebuild.notify_one();
            }
        }
    }

    /// 保身份重启一个账号；id 为 0 时按顺序逐个重启。
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
        self.restart_one_inner(id, false).await
    }

    async fn restart_one_pending(&self, id: usize) -> Result<(), String> {
        self.restart_one_inner(id, true).await
    }

    async fn restart_one_inner(&self, id: usize, only_pending: bool) -> Result<(), String> {
        let permit = self
            .restart_limit
            .clone()
            .acquire_owned()
            .await
            .map_err(|_| "重启已取消".to_string())?;
        let worker = self
            .snapshot()
            .into_iter()
            .find(|worker| worker.id == id)
            .ok_or_else(|| format!("没有账号 {id}"))?;
        if only_pending && !worker.restart_pending.load(Ordering::Relaxed) {
            return Ok(());
        }
        worker.deferred.store(false, Ordering::Relaxed);
        let (reply_tx, reply_rx) = oneshot::channel();
        worker
            .restart_tx
            .send(RestartJob {
                reply: reply_tx,
                probe_timeout: self.restart.probe_timeout,
                force_after: self.restart.force_after,
            })
            .map_err(|_| "账号监督任务已退出".to_string())?;
        let result = reply_rx.await.map_err(|_| "重启任务中断".to_string())?;
        drop(permit);
        result
    }

    fn queue_threshold_restart(&self, id: usize, mode: RestartMode) {
        let admission = if mode == RestartMode::Users {
            "停止接收新用户，已统计用户可继续连接直到排空超时"
        } else {
            "停止接收新连接"
        };
        let text = format!("[pool] 账号 {id} 达到重启阈值，{admission}，进入重启队列");
        eprintln!("{text}");
        self.console.log("plan", text);
        let _ = self.threshold_tx.send(id);
    }

    fn finish_reconnect(&self, worker: &Worker) {
        self.scheduler.forget_users(worker.id);
        worker.reset_usage();
    }

    pub fn set_restart_policy(
        &self,
        mode: Option<RestartMode>,
        threshold: Option<usize>,
    ) -> Result<(), String> {
        let mut policy = self.restart_policy.write().unwrap();
        let next = RestartPolicy {
            mode: mode.unwrap_or(policy.mode),
            threshold: threshold.unwrap_or(policy.threshold),
        };
        next.validate()?;
        if next == *policy {
            return Ok(());
        }
        let changed_mode = next.mode != policy.mode;
        *policy = next;
        for worker in self.snapshot() {
            let inner = worker.inner.lock().unwrap();
            let mut usage = worker.usage.lock().unwrap();
            if changed_mode && !worker.restart_pending.load(Ordering::Relaxed) {
                *usage = RestartUsage::default();
            }
            if next.mode != RestartMode::Users {
                worker.accept_existing_users.store(false, Ordering::Relaxed);
            }
            if changed_mode && worker.deferred.swap(false, Ordering::Relaxed) {
                worker.clear_stage();
            }
            let queued = inner.net.is_some() && worker.queue_if_reached(&usage, next);
            drop(usage);
            drop(inner);
            if queued {
                self.queue_threshold_restart(worker.id, next.mode);
            }
        }
        drop(policy);
        if changed_mode {
            self.wake(WakeReason::Plan);
        }
        Ok(())
    }

    pub async fn rotate(&self, id: usize) -> crate::Result<()> {
        let workers = self.snapshot();
        let target = if id != 0 {
            workers.into_iter().find(|worker| worker.id == id)
        } else {
            let pin = self.pinned.load(Ordering::Relaxed);
            workers
                .iter()
                .find(|worker| worker.id == pin)
                .cloned()
                .or_else(|| workers.first().cloned())
        };
        let Some(worker) = target else {
            return Err(crate::Error::Config("没有这个账号".into()));
        };
        let opts = RegisterOptions {
            device_name: Some(format!("{}-{}", self.device_name, worker.id)),
            ..Default::default()
        };
        let fresh = register_with(worker.upstream.as_ref(), &opts).await?;
        worker.inner.lock().unwrap().config = fresh;
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

    /// 修改保身份重启计划。`None` 表示这一项保持原值。
    /// batch 为 0 时，每一轮包含当前全部账号。改间隔、批量或延后会重新计时；只改 misfire 不会。
    pub fn set_restart_plan(
        &self,
        interval: Option<Duration>,
        batch: Option<usize>,
        defer: Option<Duration>,
        misfire: Option<Misfire>,
    ) {
        let mut reschedule = false;
        if let Some(interval) = interval {
            *self.restart_interval.lock().unwrap() = interval;
            reschedule = true;
        }
        if let Some(batch) = batch {
            self.restart_batch.store(batch, Ordering::Relaxed);
            reschedule = true;
        }
        if let Some(defer) = defer {
            *self.restart_defer.lock().unwrap() = defer;
            reschedule = true;
        }
        if let Some(misfire) = misfire {
            self.restart_misfire.store(misfire as u8, Ordering::Relaxed);
        }
        // 只改错过策略时不重新计时，也不取消已经延后的账号。
        if !reschedule {
            return;
        }
        for worker in self.snapshot() {
            worker.deferred.store(false, Ordering::Relaxed);
            worker.clear_stage();
        }
        self.wake(WakeReason::Plan);
    }

    fn misfire(&self) -> Misfire {
        match self.restart_misfire.load(Ordering::Relaxed) {
            1 => Misfire::Skip,
            _ => Misfire::Fire,
        }
    }

    pub fn set_plan_paused(&self, paused: bool) {
        self.restart_paused.store(paused, Ordering::Relaxed);
        self.console.set_paused(paused);
        self.console.log(
            "plan",
            if paused {
                "已暂停后续轮次"
            } else {
                "已恢复后续轮次"
            },
        );
        self.wake(WakeReason::Control);
    }

    pub fn plan_paused(&self) -> bool {
        self.restart_paused.load(Ordering::Relaxed)
    }

    pub fn run_plan_now(&self) {
        self.restart_now.store(true, Ordering::Relaxed);
        self.console.log("plan", "已请求立即执行一轮");
        self.wake(WakeReason::Control);
    }

    fn wake(&self, reason: WakeReason) {
        let mut pending = self.wake_reason.lock().unwrap();
        if *pending != WakeReason::Plan || reason == WakeReason::Plan {
            *pending = reason;
        }
        self.restart_wake.notify_one();
    }

    fn take_wake(&self) -> WakeReason {
        let mut reason = self.wake_reason.lock().unwrap();
        let current = *reason;
        *reason = WakeReason::None;
        current
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
        drop(workers);
        worker.stopped.store(true, Ordering::Relaxed);
        worker.retire();
        worker.rebuild.notify_one();
        self.scheduler.forget(id);
        if self.pinned.load(Ordering::Relaxed) == id {
            self.pinned.store(0, Ordering::Relaxed);
        }
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
        let pinned = self.pinned.load(Ordering::Relaxed);
        let policy = *self.restart_policy.read().unwrap();
        let users = self.scheduler.user_counts();
        let now_ms = crate::console::unix_ms();
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
                let deferred = worker.deferred.load(Ordering::Relaxed);
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
                } else if deferred {
                    "waiting"
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
                    "maintenance" | "waiting" | "disabled" => maintenance += 1,
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
                let ready = manual && !draining && inner.net.is_some();
                AccountStatus {
                    id: worker.id,
                    ready,
                    tunnel: inner.net.is_some(),
                    draining,
                    deferred,
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
                    restart_users: usage.users.len(),
                    restart_connections: usage.connections,
                    restart_pending: worker.restart_pending.load(Ordering::Relaxed),
                    uptime_seconds: worker.born.elapsed().as_secs(),
                    last_action: worker.last_action.lock().unwrap().clone(),
                    ip: inner.assigned_v4.to_string(),
                    assigned_v6: inner.config.ipv6.clone(),
                    trace,
                }
            })
            .collect();
        let (bytes_up, bytes_down) = self.console.totals();
        let _ = now_ms;
        PoolStatus {
            initializing: self.initializing.load(Ordering::Relaxed),
            expected_accounts: self.expected_accounts,
            enabled: self.enabled(),
            mode: if pinned == 0 { "auto" } else { "pinned" },
            pinned,
            http2: self.http2.load(Ordering::Relaxed),
            mixed: self.mixed,
            listen: self.listen.lock().unwrap().clone(),
            rotate_seconds: self.rotate_secs.load(Ordering::Relaxed),
            restart_seconds: self.restart_interval.lock().unwrap().as_secs(),
            restart_mode: policy.mode.as_str(),
            restart_threshold: policy.threshold,
            restart_batch: self.restart_batch.load(Ordering::Relaxed),
            restart_concurrency: self.restart.concurrency.max(1),
            restart_defer_seconds: self.restart_defer.lock().unwrap().as_secs(),
            restart_misfire: self.misfire().as_str(),
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
            plan: self.console.plan(),
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

/// 从账号列表里取出下一轮要重启的账号，并返回下一轮的游标。
/// batch 为 0 时取当前全部账号，且同一轮不会重复同一个账号。
fn publish_next(pool: &Pool, round_at: Option<tokio::time::Instant>) {
    let next = round_at.map(|at| {
        let wait = at.saturating_duration_since(tokio::time::Instant::now());
        crate::console::unix_ms().saturating_add(wait.as_millis() as u64)
    });
    pool.console.set_next(next);
}

fn earliest_restart(
    round_at: Option<tokio::time::Instant>,
    deferred: &[(usize, tokio::time::Instant)],
) -> Option<tokio::time::Instant> {
    deferred.iter().fold(round_at, |soon, (_, at)| {
        Some(soon.map_or(*at, |previous| previous.min(*at)))
    })
}

fn schedule_defer(
    deferred: &mut Vec<(usize, tokio::time::Instant)>,
    id: usize,
    at: tokio::time::Instant,
) {
    if let Some(slot) = deferred.iter_mut().find(|(existing, _)| *existing == id) {
        slot.1 = slot.1.min(at);
    } else {
        deferred.push((id, at));
    }
}

/// 把到点的账号分成立即重启和继续延后。延后关闭时，有连接也会立即进入排空。
pub(crate) fn split_due_restarts(
    ids: &[usize],
    active: impl Fn(usize) -> usize,
    defer_enabled: bool,
) -> (Vec<usize>, Vec<usize>) {
    let mut now = Vec::new();
    let mut later = Vec::new();
    for id in ids {
        if defer_enabled && active(*id) > 0 {
            later.push(*id);
        } else {
            now.push(*id);
        }
    }
    (now, later)
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum RoundAction {
    Run,
    Skip,
    Wait,
}

/// 到点且上一轮已经把整点拖过去时，skip 不补跑。准时触发和手动执行仍然跑。
pub(crate) fn round_action(
    policy: Misfire,
    already_late: bool,
    round_due: bool,
    force: bool,
) -> RoundAction {
    if round_due && !force && policy == Misfire::Skip && already_late {
        RoundAction::Skip
    } else if round_due || force {
        RoundAction::Run
    } else {
        RoundAction::Wait
    }
}

/// 从错过的整点继续加间隔，直到严格晚于 now。
pub(crate) fn next_future_deadline(
    deadline: tokio::time::Instant,
    interval: Duration,
    now: tokio::time::Instant,
) -> tokio::time::Instant {
    if interval.is_zero() || deadline > now {
        return if deadline > now { deadline } else { now };
    }
    let late = now.saturating_duration_since(deadline);
    let step = interval.as_nanos().max(1);
    let steps = u32::try_from(late.as_nanos() / step + 1).unwrap_or(u32::MAX);
    let mut next = deadline + interval.saturating_mul(steps);
    if next <= now {
        next = now + interval;
    }
    next
}

pub(crate) fn next_restart_batch(ids: &[usize], index: usize, batch: usize) -> (Vec<usize>, usize) {
    if ids.is_empty() {
        return (Vec::new(), index);
    }
    let count = if batch == 0 {
        ids.len()
    } else {
        batch.min(ids.len())
    };
    let start = index % ids.len();
    let chosen = (0..count)
        .map(|offset| ids[(start + offset) % ids.len()])
        .collect();
    (chosen, start + count)
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
        if worker_needs_warp_check(&worker) {
            worker.begin_draining();
            let confirmed = confirm_warp(&pool, &worker).await;
            worker.draining.store(false, Ordering::Relaxed);
            if !confirmed {
                worker.retire();
            }
        }
        let next_health = tokio::time::Instant::now() + health_every;
        if let Some(mut dead) = worker.dead_signal() {
            tokio::select! {
                biased;
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
        } else {
            worker.set_stage("重连");
        }
        let Ok(permit) = current.connect_limit.acquire().await else {
            return false;
        };
        if worker.stopped.load(Ordering::Relaxed) {
            return false;
        }
        let built = current.build_tunnel(worker).await;
        let failure = match built {
            Err(err) => Some(err.to_string()),
            Ok(()) => match probe_egress(worker, probe_timeout).await {
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
        drop(current);
        tokio::select! {
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
    account_log(pool, format!("[pool] 账号 {} 开始保身份重启", worker.id));
    wait_before_restart(worker, job.force_after).await;
    let result = restart_in_place(pool, worker, job).await;
    if result.is_ok() {
        if let Some(current) = pool.upgrade() {
            current.finish_reconnect(worker);
        } else {
            worker.reset_usage();
        }
    }
    worker.clear_stage();
    worker.note(if result.is_ok() {
        "保身份重启"
    } else {
        "重启失败"
    });
    result
}

async fn wait_before_restart(worker: &Worker, force_after: Duration) {
    if worker.accept_existing_users.load(Ordering::Relaxed) {
        worker.set_stage("等待排空超时");
        tokio::time::sleep(force_after).await;
        worker.begin_draining();
    } else {
        worker.begin_draining();
        worker.set_stage("排空");
        wait_for_drain(worker, force_after).await;
    }
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

async fn wait_for_drain(worker: &Worker, force_after: Duration) {
    let started = tokio::time::Instant::now();
    while worker.active.load(Ordering::Relaxed) > 0 && started.elapsed() < force_after {
        tokio::time::sleep(Duration::from_millis(200)).await;
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
    pub mode: &'static str,
    pub pinned: usize,
    pub http2: bool,
    pub mixed: bool,
    pub listen: String,
    pub rotate_seconds: u64,
    pub restart_seconds: u64,
    pub restart_mode: &'static str,
    pub restart_threshold: usize,
    pub restart_batch: usize,
    pub restart_concurrency: usize,
    pub restart_defer_seconds: u64,
    pub restart_misfire: &'static str,
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
    pub plan: crate::console::PlanView,
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
    pub deferred: bool,
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
mod restart_threshold_tests {
    use super::{parse_restart_mode, Pool, PoolOptions, RestartMode, WarpConfig, Worker};
    use std::sync::atomic::Ordering;
    use std::sync::Arc;
    use std::time::Duration;
    use tokio::sync::mpsc;

    async fn mock_pool(
        mode: RestartMode,
        threshold: usize,
        concurrency: usize,
    ) -> (
        Arc<Pool>,
        Vec<Arc<Worker>>,
        Vec<mpsc::UnboundedReceiver<super::RestartJob>>,
    ) {
        let mut options = PoolOptions::basic(true);
        options.restart.mode = mode;
        options.restart.threshold = threshold;
        options.restart.concurrency = concurrency;
        let pool = Pool::start(Vec::new(), options).await.unwrap();
        let mut workers = Vec::new();
        let mut receivers = Vec::new();
        for id in 1..=2 {
            let (worker, jobs) = Worker::new(id, WarpConfig::default(), None);
            worker.inner.lock().unwrap().net = Some(crate::netstack::NetHandle::test_handle());
            pool.workers.lock().unwrap().push(worker.clone());
            workers.push(worker);
            receivers.push(jobs);
        }
        (pool, workers, receivers)
    }

    #[test]
    fn rejects_invalid_modes_and_zero_thresholds() {
        assert_eq!(parse_restart_mode("USERS").unwrap(), RestartMode::Users);
        assert_eq!(
            parse_restart_mode("connections").unwrap(),
            RestartMode::Connections
        );
        assert!(parse_restart_mode("unknown").is_err());
        let invalid = super::RestartPolicy {
            mode: RestartMode::Users,
            threshold: 0,
        };
        assert!(invalid.validate().is_err());
    }

    #[tokio::test]
    async fn successful_reconnect_clears_only_its_sticky_user_count() {
        let mut options = PoolOptions::basic(true);
        options.policy.sticky = crate::schedule::StickyMode::UsernameRound;
        let pool = Pool::start(Vec::new(), options).await.unwrap();
        let mut workers = Vec::new();
        for id in 1..=2 {
            let (worker, _jobs) = Worker::new(id, WarpConfig::default(), None);
            worker.inner.lock().unwrap().net = Some(crate::netstack::NetHandle::test_handle());
            pool.workers.lock().unwrap().push(worker.clone());
            workers.push(worker);
        }

        let alice = pool.checkout(Some("alice"), "192.0.2.1").unwrap();
        let bob = pool.checkout(Some("bob"), "192.0.2.2").unwrap();
        assert_eq!(alice.worker_id, 1);
        assert_eq!(bob.worker_id, 2);
        assert_eq!(pool.status().accounts[0].users, 1);
        assert_eq!(pool.status().accounts[1].users, 1);

        workers[0].begin_draining();
        pool.finish_reconnect(&workers[0]);
        assert_eq!(pool.status().accounts[0].users, 0);
        assert_eq!(pool.status().accounts[1].users, 1);
        assert_eq!(
            pool.checkout(Some("bob"), "192.0.2.3").unwrap().worker_id,
            2
        );

        workers[1].begin_draining();
        pool.finish_reconnect(&workers[1]);
        assert_eq!(pool.status().accounts[1].users, 0);
    }

    #[tokio::test]
    async fn failed_reconnect_preserves_sticky_user_count_until_recovery() {
        let mut options = PoolOptions::basic(true);
        options.policy.sticky = crate::schedule::StickyMode::UsernameRound;
        let pool = Pool::start(Vec::new(), options).await.unwrap();
        let (worker, _jobs) = Worker::new(1, WarpConfig::default(), None);
        worker.inner.lock().unwrap().net = Some(crate::netstack::NetHandle::test_handle());
        pool.workers.lock().unwrap().push(worker.clone());
        let lease = pool.checkout(Some("alice"), "192.0.2.1").unwrap();
        drop(lease);

        let (reply, _rx) = tokio::sync::oneshot::channel();
        let job = super::RestartJob {
            reply,
            probe_timeout: Duration::ZERO,
            force_after: Duration::ZERO,
        };
        assert!(super::graceful(&Arc::downgrade(&pool), &worker, &job)
            .await
            .is_err());
        assert_eq!(pool.status().accounts[0].users, 1);
        pool.finish_reconnect(&worker);
        assert_eq!(pool.status().accounts[0].users, 0);
    }

    #[tokio::test(start_paused = true)]
    async fn threshold_restart_clears_instance_users_and_recounts_in_both_modes() {
        for mode in [RestartMode::Users, RestartMode::Connections] {
            let mut options = PoolOptions::basic(true);
            options.policy.sticky = crate::schedule::StickyMode::UsernameRound;
            options.restart.mode = mode;
            options.restart.threshold = 2;
            let pool = Pool::start(Vec::new(), options).await.unwrap();
            let (worker, mut jobs) = Worker::new(1, WarpConfig::default(), None);
            let (other_worker, _other_jobs) = Worker::new(2, WarpConfig::default(), None);
            worker.inner.lock().unwrap().net = Some(crate::netstack::NetHandle::test_handle());
            other_worker.inner.lock().unwrap().net =
                Some(crate::netstack::NetHandle::test_handle());
            pool.workers
                .lock()
                .unwrap()
                .extend([worker.clone(), other_worker]);

            let first = pool.checkout(Some("alice"), "192.0.2.1").unwrap();
            let other = pool.checkout(Some("outside"), "192.0.2.2").unwrap();
            assert_eq!(other.worker_id, 2);
            let second_user = if mode == RestartMode::Users {
                "bob"
            } else {
                "alice"
            };
            let second = pool.checkout(Some(second_user), "192.0.2.3").unwrap();
            let before = &pool.status().accounts[0];
            assert_eq!(before.users, if mode == RestartMode::Users { 2 } else { 1 });
            assert_eq!(before.restart_connections, 2);
            assert_eq!(
                before.restart_users,
                if mode == RestartMode::Users { 2 } else { 0 }
            );
            assert!(before.restart_pending);
            assert!(before.draining);
            assert_eq!(pool.status().accounts[1].users, 1);

            let job = tokio::time::timeout(Duration::from_secs(1), jobs.recv())
                .await
                .unwrap()
                .unwrap();
            if mode == RestartMode::Users {
                let repeat = pool.checkout(Some("alice"), "192.0.2.4").unwrap();
                assert_eq!(repeat.worker_id, 1);
                assert_eq!(pool.status().accounts[0].restart_users, 2);
                assert_eq!(pool.status().accounts[0].restart_connections, 3);
                drop(repeat);
            } else {
                assert!(pool.checkout(Some("alice"), "192.0.2.4").is_err());
            }
            drop((first, second));

            pool.finish_reconnect(&worker);
            let _ = job.reply.send(Ok(()));
            let after = &pool.status().accounts[0];
            assert_eq!(after.users, 0);
            assert_eq!(after.restart_users, 0);
            assert_eq!(after.restart_connections, 0);
            assert!(!after.restart_pending);
            assert!(!after.draining);
            assert_eq!(pool.status().accounts[1].users, 1);
            assert_eq!(pool.status().accounts[1].restart_connections, 1);

            let fresh = pool.checkout(Some("alice"), "192.0.2.5").unwrap();
            assert_eq!(fresh.worker_id, 1);
            let after_new_connection = &pool.status().accounts[0];
            assert_eq!(after_new_connection.users, 1);
            assert_eq!(after_new_connection.restart_connections, 1);
            assert_eq!(
                after_new_connection.restart_users,
                if mode == RestartMode::Users { 1 } else { 0 }
            );
        }
    }

    #[tokio::test(start_paused = true)]
    async fn threshold_restart_failure_keeps_instance_user_count() {
        for mode in [RestartMode::Users, RestartMode::Connections] {
            let mut options = PoolOptions::basic(true);
            options.policy.sticky = crate::schedule::StickyMode::UsernameRound;
            options.restart.mode = mode;
            options.restart.threshold = 1;
            let pool = Pool::start(Vec::new(), options).await.unwrap();
            let (worker, mut jobs) = Worker::new(1, WarpConfig::default(), None);
            worker.inner.lock().unwrap().net = Some(crate::netstack::NetHandle::test_handle());
            pool.workers.lock().unwrap().push(worker.clone());

            let lease = pool.checkout(Some("alice"), "192.0.2.1").unwrap();
            let job = tokio::time::timeout(Duration::from_secs(1), jobs.recv())
                .await
                .unwrap()
                .unwrap();
            drop(lease);
            let result = super::graceful(&Arc::downgrade(&pool), &worker, &job).await;
            assert!(result.is_err());
            let _ = job.reply.send(result);

            let failed = &pool.status().accounts[0];
            assert_eq!(failed.users, 1);
            assert_eq!(failed.restart_connections, 1);
            assert_eq!(
                failed.restart_users,
                usize::from(mode == RestartMode::Users)
            );
            assert!(failed.restart_pending);
            assert!(failed.draining);
            assert!(pool.checkout(Some("alice"), "192.0.2.1").is_err());
        }
    }

    #[tokio::test(start_paused = true)]
    async fn user_threshold_allows_counted_users_until_drain_timeout() {
        let mut options = PoolOptions::basic(true);
        options.policy.sticky = crate::schedule::StickyMode::UsernameRound;
        options.restart.mode = RestartMode::Users;
        options.restart.threshold = 2;
        let pool = Pool::start(Vec::new(), options).await.unwrap();
        let (worker, mut jobs) = Worker::new(1, WarpConfig::default(), None);
        worker.inner.lock().unwrap().net = Some(crate::netstack::NetHandle::test_handle());
        pool.workers.lock().unwrap().push(worker.clone());

        let first = pool.checkout(Some("alice"), "192.0.2.1").unwrap();
        let second = pool.checkout(Some("bob"), "192.0.2.2").unwrap();
        let job = tokio::time::timeout(Duration::from_secs(1), jobs.recv())
            .await
            .unwrap()
            .unwrap();
        drop((first, second));

        assert!(worker.restart_pending.load(Ordering::Relaxed));
        assert!(worker.draining.load(Ordering::Relaxed));
        assert!(pool.checkout(Some("charlie"), "192.0.2.3").is_err());

        let waiting = worker.clone();
        let restart_wait = tokio::spawn(async move {
            super::wait_before_restart(&waiting, Duration::from_secs(3)).await;
        });
        tokio::task::yield_now().await;
        assert!(!restart_wait.is_finished());
        tokio::time::advance(Duration::from_secs(2)).await;
        assert!(!restart_wait.is_finished());

        let alice_again = pool.checkout(Some("alice"), "198.51.100.2").unwrap();
        let bob_again = pool.checkout(Some("bob"), "198.51.100.3").unwrap();
        assert_eq!(alice_again.worker_id, 1);
        assert_eq!(bob_again.worker_id, 1);
        assert_eq!(pool.status().accounts[0].restart_users, 2);
        assert_eq!(pool.status().accounts[0].restart_connections, 4);
        assert!(pool.checkout(Some("charlie"), "192.0.2.3").is_err());

        tokio::time::advance(Duration::from_secs(1)).await;
        restart_wait.await.unwrap();
        assert!(pool.checkout(Some("alice"), "198.51.100.2").is_err());
        assert!(pool.checkout(Some("bob"), "198.51.100.3").is_err());
        assert!(worker.restart_pending.load(Ordering::Relaxed));
        assert_eq!(pool.status().accounts[0].restart_users, 2);
        drop((alice_again, bob_again));
        let _ = job.reply.send(Err("模拟超时后重启失败".into()));
    }

    #[tokio::test(start_paused = true)]
    async fn anonymous_user_threshold_recognizes_original_ip_only() {
        let (pool, workers, mut receivers) = mock_pool(RestartMode::Users, 1, 1).await;
        workers[1].manual.store(false, Ordering::Relaxed);
        let first = pool.checkout(None, "192.0.2.1").unwrap();
        assert_eq!(first.worker_id, 1);
        let repeat = pool.checkout(None, "192.0.2.1").unwrap();
        assert_eq!(repeat.worker_id, 1);
        assert!(pool.checkout(None, "192.0.2.2").is_err());
        assert_eq!(pool.status().accounts[0].restart_users, 1);
        assert_eq!(pool.status().accounts[0].restart_connections, 2);
        assert!(
            tokio::time::timeout(Duration::from_secs(1), receivers[0].recv())
                .await
                .unwrap()
                .is_some()
        );
        drop((first, repeat));
    }

    #[tokio::test(start_paused = true)]
    async fn user_threshold_routes_new_users_to_other_instances() {
        for sticky in [
            crate::schedule::StickyMode::UsernameRound,
            crate::schedule::StickyMode::UsernameLeast,
        ] {
            let mut options = PoolOptions::basic(true);
            options.policy.sticky = sticky;
            options.restart.mode = RestartMode::Users;
            options.restart.threshold = 2;
            let pool = Pool::start(Vec::new(), options).await.unwrap();
            let (first_worker, _first_jobs) = Worker::new(1, WarpConfig::default(), None);
            let (second_worker, _second_jobs) = Worker::new(2, WarpConfig::default(), None);
            first_worker.inner.lock().unwrap().net =
                Some(crate::netstack::NetHandle::test_handle());
            second_worker.inner.lock().unwrap().net =
                Some(crate::netstack::NetHandle::test_handle());
            second_worker.manual.store(false, Ordering::Relaxed);
            pool.workers
                .lock()
                .unwrap()
                .extend([first_worker, second_worker.clone()]);

            let alice = pool.checkout(Some("alice"), "192.0.2.1").unwrap();
            let bob = pool.checkout(Some("bob"), "192.0.2.2").unwrap();
            assert_eq!(alice.worker_id, 1);
            assert_eq!(bob.worker_id, 1);
            second_worker.manual.store(true, Ordering::Relaxed);

            assert_eq!(
                pool.checkout(Some("alice"), "192.0.2.3").unwrap().worker_id,
                1
            );
            assert_eq!(
                pool.checkout(Some("bob"), "192.0.2.4").unwrap().worker_id,
                1
            );
            assert_eq!(
                pool.checkout(Some("charlie"), "192.0.2.5")
                    .unwrap()
                    .worker_id,
                2
            );
            assert_eq!(pool.status().accounts[0].restart_users, 2);
            assert_eq!(pool.status().accounts[1].restart_users, 1);
        }
    }

    #[tokio::test(start_paused = true)]
    async fn concurrent_new_users_cannot_exceed_user_threshold() {
        let (pool, workers, _receivers) = mock_pool(RestartMode::Users, 5, 1).await;
        workers[1].manual.store(false, Ordering::Relaxed);
        let mut tasks = Vec::new();
        for index in 0..100 {
            let pool = pool.clone();
            tasks.push(tokio::spawn(async move {
                pool.checkout(Some(&format!("user-{index}")), "192.0.2.1")
                    .is_ok()
            }));
        }
        let mut admitted = 0;
        for task in tasks {
            admitted += usize::from(task.await.unwrap());
        }
        assert_eq!(admitted, 5);
        assert_eq!(pool.status().accounts[0].restart_users, 5);
        assert!(workers[0].restart_pending.load(Ordering::Relaxed));
    }

    #[tokio::test(start_paused = true)]
    async fn switching_away_from_user_mode_disables_existing_user_admission() {
        let (pool, workers, _receivers) = mock_pool(RestartMode::Users, 1, 1).await;
        workers[1].manual.store(false, Ordering::Relaxed);
        let first = pool.checkout(Some("alice"), "192.0.2.1").unwrap();
        assert!(pool.checkout(Some("alice"), "192.0.2.2").is_ok());

        pool.set_restart_policy(Some(RestartMode::Connections), None)
            .unwrap();
        assert!(pool.checkout(Some("alice"), "192.0.2.3").is_err());
        assert!(workers[0].restart_pending.load(Ordering::Relaxed));
        drop(first);
    }

    #[tokio::test(start_paused = true)]
    async fn connection_limit_stops_new_leases_without_dropping_active_ones() {
        let (pool, workers, mut receivers) = mock_pool(RestartMode::Connections, 2, 1).await;
        let first = pool.checkout(None, "192.0.2.1").unwrap();
        assert_eq!(first.worker_id, 1);
        assert_eq!(workers[0].usage.lock().unwrap().connections, 1);
        let second = pool.checkout(None, "192.0.2.2").unwrap();
        assert_eq!(second.worker_id, 2);
        let third = pool.checkout(None, "192.0.2.3").unwrap();
        assert_eq!(third.worker_id, 1);
        assert!(workers[0].restart_pending.load(Ordering::Relaxed));
        assert_eq!(workers[0].active.load(Ordering::Relaxed), 2);
        let job = tokio::time::timeout(Duration::from_secs(1), receivers[0].recv())
            .await
            .unwrap()
            .unwrap();
        assert!(receivers[1].try_recv().is_err());
        assert_eq!(pool.checkout(None, "192.0.2.4").unwrap().worker_id, 2);
        assert!(workers[1].restart_pending.load(Ordering::Relaxed));
        assert!(pool.checkout(None, "192.0.2.5").is_err());
        assert!(receivers[1].try_recv().is_err());
        drop(first);
        drop(third);
        assert_eq!(workers[0].active.load(Ordering::Relaxed), 0);
        assert!(workers[0].restart_pending.load(Ordering::Relaxed));
        let _ = job.reply.send(Ok(()));
        assert!(
            tokio::time::timeout(Duration::from_secs(1), receivers[1].recv())
                .await
                .unwrap()
                .is_some()
        );
        pool.finish_reconnect(&workers[0]);
        assert_eq!(workers[0].usage.lock().unwrap().connections, 0);
        assert!(!workers[0].restart_pending.load(Ordering::Relaxed));
        drop(second);
    }

    #[tokio::test(start_paused = true)]
    async fn user_limit_counts_distinct_names_and_anonymous_ips() {
        let (pool, workers, mut receivers) = mock_pool(RestartMode::Users, 3, 1).await;
        pool.select(1);
        let first = pool.checkout(Some("alice"), "192.0.2.1").unwrap();
        let repeat = pool.checkout(Some("alice"), "192.0.2.2").unwrap();
        assert_eq!(workers[0].usage.lock().unwrap().users.len(), 1);
        assert!(!workers[0].draining.load(Ordering::Relaxed));
        let second = pool.checkout(None, "192.0.2.1").unwrap();
        assert_eq!(workers[0].usage.lock().unwrap().users.len(), 2);
        let repeat_anonymous = pool.checkout(None, "192.0.2.1").unwrap();
        assert_eq!(workers[0].usage.lock().unwrap().users.len(), 2);
        let third = pool.checkout(None, "192.0.2.3").unwrap();
        assert_eq!(workers[0].usage.lock().unwrap().users.len(), 3);
        assert!(workers[0].draining.load(Ordering::Relaxed));
        assert_eq!(
            pool.checkout(Some("alice"), "192.0.2.1").unwrap().worker_id,
            1
        );
        assert_eq!(workers[0].usage.lock().unwrap().users.len(), 3);
        assert!(
            tokio::time::timeout(Duration::from_secs(1), receivers[0].recv())
                .await
                .unwrap()
                .is_some()
        );
        pool.finish_reconnect(&workers[0]);
        assert!(workers[0].usage.lock().unwrap().users.is_empty());
        drop((first, repeat, second, repeat_anonymous, third));
    }

    #[tokio::test(start_paused = true)]
    async fn concurrent_checkout_never_exceeds_threshold() {
        let (pool, workers, _receivers) = mock_pool(RestartMode::Connections, 10, 1).await;
        workers[1].manual.store(false, Ordering::Relaxed);
        let mut tasks = Vec::new();
        for _ in 0..100 {
            let pool = pool.clone();
            tasks.push(tokio::spawn(async move {
                pool.checkout(None, "192.0.2.1").is_ok()
            }));
        }
        let mut accepted = 0;
        for task in tasks {
            accepted += usize::from(task.await.unwrap());
        }
        assert_eq!(accepted, 10);
        assert_eq!(workers[0].usage.lock().unwrap().connections, 10);
        assert!(workers[0].restart_pending.load(Ordering::Relaxed));
    }

    #[tokio::test(start_paused = true)]
    async fn updating_threshold_checks_existing_counts() {
        let (pool, workers, mut receivers) = mock_pool(RestartMode::Connections, 5, 1).await;
        pool.select(1);
        let lease = pool.checkout(None, "192.0.2.1").unwrap();
        assert!(!workers[0].restart_pending.load(Ordering::Relaxed));
        pool.set_restart_policy(None, Some(1)).unwrap();
        assert!(workers[0].restart_pending.load(Ordering::Relaxed));
        assert!(
            tokio::time::timeout(Duration::from_secs(1), receivers[0].recv())
                .await
                .unwrap()
                .is_some()
        );
        drop(lease);
    }

    #[tokio::test]
    async fn failed_restart_retains_counts_and_blocks_new_leases() {
        let (pool, workers, _receivers) = mock_pool(RestartMode::Connections, 1, 1).await;
        let worker = &workers[0];
        worker.usage.lock().unwrap().connections = 1;
        worker.begin_draining();
        let (reply, _rx) = tokio::sync::oneshot::channel();
        let job = super::RestartJob {
            reply,
            probe_timeout: Duration::ZERO,
            force_after: Duration::ZERO,
        };
        assert!(super::graceful(&Arc::downgrade(&pool), worker, &job)
            .await
            .is_err());
        assert!(worker.draining.load(Ordering::Relaxed));
        assert_eq!(worker.usage.lock().unwrap().connections, 1);
        assert_eq!(pool.checkout(None, "192.0.2.1").unwrap().worker_id, 2);
    }
}

#[cfg(test)]
mod restart_plan_tests {
    use super::next_restart_batch;
    use super::{Pool, PoolOptions, RestartConfig, WarpConfig, Worker};
    use std::sync::atomic::Ordering;
    use std::sync::Arc;
    use std::time::Duration;
    use tokio::sync::mpsc;

    async fn mock_pool(
        interval: Duration,
        defer: Duration,
    ) -> (
        Arc<Pool>,
        Arc<Worker>,
        mpsc::UnboundedReceiver<tokio::time::Instant>,
    ) {
        let mut options = PoolOptions::basic(true);
        options.restart = RestartConfig {
            interval,
            defer,
            ..RestartConfig::default()
        };
        let pool = Pool::start(Vec::new(), options).await.unwrap();
        let (worker, mut jobs) = Worker::new(1, WarpConfig::default(), None);
        pool.workers.lock().unwrap().push(worker.clone());
        let (sender, receiver) = mpsc::unbounded_channel();
        tokio::spawn(async move {
            while let Some(job) = jobs.recv().await {
                let _ = sender.send(tokio::time::Instant::now());
                let _ = job.reply.send(Ok(()));
            }
        });
        tokio::task::yield_now().await;
        (pool, worker, receiver)
    }

    #[tokio::test(start_paused = true)]
    async fn manual_round_runs_when_periodic_restart_is_disabled() {
        let (pool, _, mut jobs) = mock_pool(Duration::ZERO, Duration::ZERO).await;
        pool.run_plan_now();
        assert!(tokio::time::timeout(Duration::from_secs(1), jobs.recv())
            .await
            .unwrap()
            .is_some());
        assert!(pool.status().plan.next_at.is_none());
        tokio::time::advance(Duration::from_secs(120)).await;
        tokio::task::yield_now().await;
        assert!(jobs.try_recv().is_err());
    }

    #[tokio::test(start_paused = true)]
    async fn manual_round_keeps_retrying_deferred_accounts_with_periodic_restart_disabled() {
        let (pool, worker, mut jobs) = mock_pool(Duration::ZERO, Duration::from_secs(5)).await;
        worker.active.store(1, Ordering::Relaxed);
        pool.run_plan_now();
        tokio::task::yield_now().await;
        assert!(worker.deferred.load(Ordering::Relaxed));
        tokio::time::advance(Duration::from_secs(5)).await;
        tokio::task::yield_now().await;
        assert!(jobs.try_recv().is_err());
        worker.active.store(0, Ordering::Relaxed);
        tokio::time::advance(Duration::from_secs(4)).await;
        assert!(jobs.try_recv().is_err());
        tokio::time::advance(Duration::from_secs(1)).await;
        assert!(tokio::time::timeout(Duration::from_secs(1), jobs.recv())
            .await
            .unwrap()
            .is_some());
        assert!(pool.status().plan.next_at.is_none());
        tokio::time::advance(Duration::from_secs(15)).await;
        tokio::task::yield_now().await;
        assert!(jobs.try_recv().is_err());
    }

    #[tokio::test(start_paused = true)]
    async fn new_round_does_not_overwrite_pending_defer_deadline() {
        let started = tokio::time::Instant::now();
        let (_pool, worker, mut jobs) =
            mock_pool(Duration::from_secs(40), Duration::from_secs(70)).await;
        worker.active.store(1, Ordering::Relaxed);
        tokio::time::advance(Duration::from_secs(40)).await;
        tokio::task::yield_now().await;
        assert!(worker.deferred.load(Ordering::Relaxed));
        tokio::time::advance(Duration::from_secs(40)).await;
        tokio::task::yield_now().await;
        tokio::time::advance(Duration::from_secs(20)).await;
        worker.active.store(0, Ordering::Relaxed);
        tokio::time::advance(Duration::from_secs(9)).await;
        assert!(jobs.try_recv().is_err());
        tokio::time::advance(Duration::from_secs(1)).await;
        let executed = tokio::time::timeout(Duration::from_secs(1), jobs.recv())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(executed.duration_since(started), Duration::from_secs(110));
    }

    #[tokio::test(start_paused = true)]
    async fn busy_account_is_deferred_again_at_its_deadline() {
        let (_pool, worker, mut jobs) =
            mock_pool(Duration::from_secs(40), Duration::from_secs(70)).await;
        worker.active.store(1, Ordering::Relaxed);
        tokio::time::advance(Duration::from_secs(40)).await;
        tokio::task::yield_now().await;
        tokio::time::advance(Duration::from_secs(40)).await;
        tokio::task::yield_now().await;
        tokio::time::advance(Duration::from_secs(30)).await;
        tokio::task::yield_now().await;
        assert!(worker.deferred.load(Ordering::Relaxed));
        worker.active.store(0, Ordering::Relaxed);
        tokio::time::advance(Duration::from_secs(10)).await;
        tokio::task::yield_now().await;
        assert!(jobs.try_recv().is_err());
        tokio::time::advance(Duration::from_secs(59)).await;
        assert!(jobs.try_recv().is_err());
        tokio::time::advance(Duration::from_secs(1)).await;
        assert!(tokio::time::timeout(Duration::from_secs(1), jobs.recv())
            .await
            .unwrap()
            .is_some());
    }

    #[tokio::test(start_paused = true)]
    async fn drain_prevents_new_leases_but_keeps_existing_sessions() {
        let (pool, worker, _) = mock_pool(Duration::ZERO, Duration::ZERO).await;
        worker.inner.lock().unwrap().net = Some(crate::netstack::NetHandle::test_handle());
        let existing = pool.checkout(Some("alice"), "192.0.2.1").unwrap();
        assert_eq!(worker.active.load(Ordering::Relaxed), 1);
        worker.begin_draining();
        assert!(pool.checkout(Some("alice"), "192.0.2.1").is_err());
        assert!(pool.checkout(None, "192.0.2.2").is_err());
        assert_eq!(worker.active.load(Ordering::Relaxed), 1);
        drop(existing);
        assert_eq!(worker.active.load(Ordering::Relaxed), 0);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn concurrent_checkout_cannot_admit_connections_after_draining() {
        let (pool, worker, _) = mock_pool(Duration::ZERO, Duration::ZERO).await;
        worker.inner.lock().unwrap().net = Some(crate::netstack::NetHandle::test_handle());
        let mut tasks = Vec::new();
        for _ in 0..8 {
            let pool = pool.clone();
            tasks.push(tokio::spawn(async move {
                for _ in 0..1000 {
                    if let Ok(lease) = pool.checkout(None, "192.0.2.1") {
                        tokio::task::yield_now().await;
                        drop(lease);
                    }
                }
            }));
        }
        tokio::task::yield_now().await;
        worker.begin_draining();
        for _ in 0..100 {
            assert!(pool.checkout(None, "192.0.2.1").is_err());
        }
        for task in tasks {
            task.await.unwrap();
        }
        assert_eq!(worker.active.load(Ordering::Relaxed), 0);
    }

    #[tokio::test(start_paused = true)]
    async fn draining_sticky_account_fails_closed_without_blocking_other_accounts() {
        let mut options = PoolOptions::basic(true);
        options.policy.sticky = crate::schedule::StickyMode::UsernameRound;
        let pool = Pool::start(Vec::new(), options).await.unwrap();
        let mut workers = Vec::new();
        for id in 1..=2 {
            let (worker, _) = Worker::new(id, WarpConfig::default(), None);
            worker.inner.lock().unwrap().net = Some(crate::netstack::NetHandle::test_handle());
            pool.workers.lock().unwrap().push(worker.clone());
            workers.push(worker);
        }
        let alice = pool.checkout(Some("alice"), "192.0.2.1").unwrap();
        let chosen = alice.worker_id;
        workers[chosen - 1].begin_draining();
        assert!(matches!(
            pool.checkout(Some("alice"), "192.0.2.2"),
            Err(crate::schedule::PickFail::StickyDown)
        ));
        let other = pool.checkout(None, "192.0.2.3").unwrap();
        assert_ne!(other.worker_id, chosen);
        drop(alice);
        assert_eq!(workers[chosen - 1].active.load(Ordering::Relaxed), 0);
    }

    #[tokio::test(start_paused = true)]
    async fn scheduled_batch_honors_restart_concurrency() {
        let mut options = PoolOptions::basic(true);
        options.restart.batch = 0;
        options.restart.concurrency = 2;
        let pool = Pool::start(Vec::new(), options).await.unwrap();
        let mut receivers = Vec::new();
        for id in 1..=3 {
            let (worker, jobs) = Worker::new(id, WarpConfig::default(), None);
            pool.workers.lock().unwrap().push(worker);
            receivers.push(jobs);
        }
        pool.run_plan_now();
        let mut running = Vec::new();
        for _ in 0..30 {
            for receiver in &mut receivers {
                if let Ok(job) = receiver.try_recv() {
                    running.push(job);
                }
            }
            if running.len() == 2 {
                break;
            }
            tokio::task::yield_now().await;
        }
        assert_eq!(running.len(), 2);
        tokio::time::advance(Duration::from_secs(1)).await;
        assert!(receivers
            .iter_mut()
            .all(|receiver| receiver.try_recv().is_err()));
        running.pop().unwrap().reply.send(Ok(())).unwrap();

        let mut third = None;
        for _ in 0..30 {
            for receiver in &mut receivers {
                if let Ok(job) = receiver.try_recv() {
                    third = Some(job);
                }
            }
            if third.is_some() {
                break;
            }
            tokio::task::yield_now().await;
        }
        assert!(third.is_some());
        running.pop().unwrap().reply.send(Ok(())).unwrap();
        third.unwrap().reply.send(Ok(())).unwrap();
        tokio::task::yield_now().await;
    }

    #[tokio::test(start_paused = true)]
    async fn drain_waits_for_active_connections_but_respects_force_after() {
        let (worker, _) = Worker::new(1, WarpConfig::default(), None);
        worker.active.store(1, Ordering::Relaxed);
        let waiting = worker.clone();
        let deadline = tokio::spawn(async move {
            super::wait_for_drain(&waiting, Duration::from_secs(3)).await;
        });
        tokio::task::yield_now().await;
        tokio::time::advance(Duration::from_secs(2)).await;
        assert!(!deadline.is_finished());
        tokio::time::advance(Duration::from_secs(1)).await;
        deadline.await.unwrap();

        let waiting = worker.clone();
        let idle = tokio::spawn(async move {
            super::wait_for_drain(&waiting, Duration::from_secs(30)).await;
        });
        tokio::task::yield_now().await;
        tokio::time::advance(Duration::from_secs(1)).await;
        worker.active.store(0, Ordering::Relaxed);
        tokio::time::advance(Duration::from_millis(200)).await;
        idle.await.unwrap();
    }

    #[test]
    fn batches_walk_the_pool_without_repeating_inside_a_round() {
        let ids = [1usize, 2, 3, 4];
        let (first, index) = next_restart_batch(&ids, 0, 2);
        assert_eq!(first, vec![1, 2]);
        let (second, index) = next_restart_batch(&ids, index, 2);
        assert_eq!(second, vec![3, 4]);
        let (third, index) = next_restart_batch(&ids, index, 2);
        assert_eq!(third, vec![1, 2]);
        let (fourth, _) = next_restart_batch(&ids, index, 2);
        assert_eq!(fourth, vec![3, 4]);

        let (all, _) = next_restart_batch(&ids, 1, 0);
        assert_eq!(all, vec![2, 3, 4, 1]);
        let (capped, _) = next_restart_batch(&ids, 3, 9);
        assert_eq!(capped, vec![4, 1, 2, 3]);
        assert!(next_restart_batch(&[], 2, 1).0.is_empty());
    }

    #[test]
    fn busy_accounts_wait_only_when_defer_is_enabled() {
        let ids = [1usize, 2, 3];
        let active = |id: usize| if id == 2 { 4 } else { 0 };
        let (now, later) = super::split_due_restarts(&ids, active, true);
        assert_eq!(now, vec![1, 3]);
        assert_eq!(later, vec![2]);
        let (forced, waiting) = super::split_due_restarts(&ids, active, false);
        assert_eq!(forced, vec![1, 2, 3]);
        assert!(waiting.is_empty());
    }
    #[test]
    fn skip_waits_for_the_next_future_slot_instead_of_catching_up() {
        use std::time::Duration;

        use super::{next_future_deadline, round_action, Misfire, RoundAction};

        assert_eq!(
            round_action(Misfire::Skip, false, true, false),
            RoundAction::Run
        );
        assert_eq!(
            round_action(Misfire::Skip, true, true, false),
            RoundAction::Skip
        );
        assert_eq!(
            round_action(Misfire::Fire, true, true, false),
            RoundAction::Run
        );
        assert_eq!(
            round_action(Misfire::Skip, true, true, true),
            RoundAction::Run
        );
        assert_eq!(
            round_action(Misfire::Skip, true, false, false),
            RoundAction::Wait
        );

        let start = tokio::time::Instant::now();
        let interval = Duration::from_secs(30 * 60);
        let scheduled = start + interval;
        assert_eq!(
            next_future_deadline(
                scheduled,
                interval,
                scheduled + Duration::from_secs(20 * 60)
            ),
            scheduled + interval
        );
        assert_eq!(
            next_future_deadline(
                scheduled,
                interval,
                scheduled + Duration::from_secs(40 * 60)
            ),
            scheduled + interval * 2
        );
        assert_eq!(
            next_future_deadline(scheduled, interval, scheduled),
            scheduled + interval
        );
        let future = scheduled + interval;
        assert_eq!(next_future_deadline(future, interval, scheduled), future);
    }

    #[test]
    fn misfire_accepts_fire_and_skip_only() {
        assert_eq!(super::parse_misfire("fire").unwrap(), super::Misfire::Fire);
        assert_eq!(super::parse_misfire("SKIP").unwrap(), super::Misfire::Skip);
        assert!(super::parse_misfire("later").is_err());
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
