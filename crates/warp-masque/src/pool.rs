//! 多账号连接池。每个账号一条 MASQUE 隧道和一个出口地址，前面用同一入口做调度。
//!
//! 上游 SOCKS5、黏性、保身份重启都发生在这个进程里。账号身份保存在各自的
//! WarpConfig 中；保身份重启只重连隧道，不重新注册。

use std::net::{Ipv4Addr, SocketAddr};
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, Weak};
use std::time::Duration;

use serde::Serialize;
use tokio::sync::{mpsc, oneshot, watch, Notify, Semaphore};

use crate::config::DEFAULT_ENDPOINT_H2_V4;
use crate::netstack::{self, NetHandle, ResolvePreference};
use crate::register::{RegisterOptions, RegistrationClient};
use crate::schedule::{PickFail, Policy, Scheduler};
use crate::trace::TraceInfo;
use crate::tunnel::{Transport, Tunnel};
use crate::upstream::{UpstreamProxy, UpstreamSet};
use crate::{DeviceKeypair, WarpConfig};

const MAX_BACKOFF: Duration = Duration::from_secs(30);
const MIN_ROTATE_SECS: u64 = 60;

/// 入口代理的用户名密码。SOCKS5 和 HTTP 共用。
#[derive(Clone)]
pub struct ProxyAuth {
    pub username: String,
    pub password: String,
}

/// 保身份重启参数。interval 为 0 时不定时重启。
/// batch 是每一轮重启几个账号，0 表示这一轮包含当前全部账号。
#[derive(Clone, Debug)]
pub struct RestartConfig {
    pub interval: Duration,
    pub probe_timeout: Duration,
    pub retries: u32,
    pub drain_timeout: Duration,
    pub concurrency: usize,
    pub batch: usize,
    /// 计划重启时，账号仍有连接就延后这么久再试。0 表示不延后，直接排空。
    pub defer: Duration,
}

impl Default for RestartConfig {
    fn default() -> Self {
        Self {
            interval: Duration::ZERO,
            probe_timeout: Duration::from_secs(15),
            retries: 2,
            drain_timeout: Duration::from_secs(60),
            concurrency: 1,
            batch: 1,
            defer: Duration::ZERO,
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
    pub device_name: String,
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
            device_name: "warp-proxy".into(),
        }
    }
}

struct RestartJob {
    reply: oneshot::Sender<Result<(), String>>,
    probe_timeout: Duration,
    retries: u32,
    drain_timeout: Duration,
}

/// 一个账号：配置、隧道、以及当前是否接新连接。
pub struct Worker {
    id: usize,
    rebuild: Notify,
    restart_tx: mpsc::UnboundedSender<RestartJob>,
    draining: AtomicBool,
    /// 计划重启因为仍有连接而被推迟。
    deferred: AtomicBool,
    active: AtomicUsize,
    upstream: Option<UpstreamProxy>,
    inner: Mutex<WorkerInner>,
}

struct WorkerInner {
    config: WarpConfig,
    net: Option<NetHandle>,
    tunnel: Option<Tunnel>,
    dead: Option<watch::Receiver<bool>>,
    assigned_v4: Ipv4Addr,
    trace: Option<TraceInfo>,
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
            deferred: AtomicBool::new(false),
            active: AtomicUsize::new(0),
            upstream,
            inner: Mutex::new(WorkerInner {
                config,
                net: None,
                tunnel: None,
                dead: None,
                assigned_v4: Ipv4Addr::UNSPECIFIED,
                trace: None,
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
        let mut inner = self.inner.lock().unwrap();
        inner.net = None;
        inner.dead = None;
    }

    fn retire(&self) {
        let mut inner = self.inner.lock().unwrap();
        inner.net = None;
        inner.dead = None;
        inner.tunnel = None;
    }

    fn set_trace(&self, trace: TraceInfo) {
        self.inner.lock().unwrap().trace = Some(trace);
    }

    fn is_ready(&self) -> bool {
        !self.draining.load(Ordering::Relaxed) && self.inner.lock().unwrap().net.is_some()
    }
}

/// 已经分配到某个账号的入口连接。丢弃时减少该账号的活跃计数。
pub struct ConnLease {
    pub worker_id: usize,
    pub egress: String,
    net: NetHandle,
    worker: Arc<Worker>,
}

impl ConnLease {
    pub fn net(&self) -> &NetHandle {
        &self.net
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
    restart_limit: Arc<Semaphore>,
    /// 运行中可改的保身份重启间隔。0 表示关闭计划。
    restart_interval: Mutex<Duration>,
    /// 每一轮重启几个账号。0 表示当前全部账号。
    restart_batch: AtomicUsize,
    /// 忙碌账号延后重启的时间。0 表示到点就排空。
    restart_defer: Mutex<Duration>,
    restart_wake: Arc<Notify>,
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
        let pool = Arc::new(Pool {
            workers: Mutex::new(Vec::new()),
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
            restart_limit: Arc::new(Semaphore::new(opts.restart.concurrency.max(1))),
            restart_interval: Mutex::new(opts.restart.interval),
            restart_batch: AtomicUsize::new(opts.restart.batch),
            restart_defer: Mutex::new(opts.restart.defer),
            restart_wake: Arc::new(Notify::new()),
        });
        for cfg in configs {
            let id = pool.next_id.fetch_add(1, Ordering::Relaxed);
            let upstream = pool.upstream.for_index(id.saturating_sub(1));
            let (worker, jobs) = Worker::new(id, cfg, upstream);
            pool.workers.lock().unwrap().push(worker.clone());
            if let Err(err) = pool.build_tunnel(&worker).await {
                eprintln!("[pool] 账号 {id} 初次连接失败: {err}");
            }
            Pool::spawn_supervisor(pool.clone(), worker, jobs);
        }
        Pool::spawn_rotator(pool.clone());
        Pool::spawn_restarter(pool.clone());
        Ok(pool)
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
                let interval = *pool.restart_interval.lock().unwrap();
                let wake = Arc::clone(&pool.restart_wake);
                drop(pool);
                if interval.is_zero() {
                    round_at = None;
                    deferred.clear();
                    tokio::select! {
                        _ = tokio::time::sleep(Duration::from_secs(5)) => {}
                        _ = wake.notified() => {}
                    }
                    continue;
                }
                let now = tokio::time::Instant::now();
                if round_at.is_none() {
                    round_at = Some(now + interval);
                }
                let next = earliest_restart(round_at.unwrap_or(now), &deferred);
                let wait = next.saturating_duration_since(now);
                tokio::select! {
                    _ = tokio::time::sleep(wait) => {}
                    // 计划被改过。清掉已延后的重启，按新间隔重新计时。
                    _ = wake.notified() => {
                        round_at = None;
                        deferred.clear();
                        continue;
                    }
                }
                let Some(pool) = weak.upgrade() else { return };
                if pool.restart_interval.lock().unwrap().is_zero() {
                    round_at = None;
                    deferred.clear();
                    for worker in pool.snapshot() {
                        worker.deferred.store(false, Ordering::Relaxed);
                    }
                    continue;
                }
                let now = tokio::time::Instant::now();
                let defer_for = *pool.restart_defer.lock().unwrap();
                let mut due = Vec::new();
                deferred.retain(|(id, at)| {
                    if *at <= now {
                        due.push(*id);
                        false
                    } else {
                        true
                    }
                });
                if round_at.is_some_and(|at| at <= now) {
                    let ids: Vec<usize> = pool.snapshot().iter().map(|worker| worker.id).collect();
                    let batch = pool.restart_batch.load(Ordering::Relaxed);
                    let (chosen, next_index) = next_restart_batch(&ids, index, batch);
                    index = next_index;
                    for id in chosen {
                        if !due.contains(&id) {
                            due.push(id);
                        }
                    }
                    round_at = Some(now + interval);
                }
                if due.is_empty() {
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
                    }
                    schedule_defer(&mut deferred, *id, now + defer_for);
                    eprintln!(
                        "[pool] 账号 {id} 仍有 {} 个连接，延后 {} 秒再重启",
                        active(*id),
                        defer_for.as_secs()
                    );
                }
                if restart_now.is_empty() {
                    continue;
                }
                let label = restart_now
                    .iter()
                    .map(|id| id.to_string())
                    .collect::<Vec<_>>()
                    .join(",");
                eprintln!(
                    "[pool] 计划保身份重启账号 {label}（同时最多 {}）",
                    pool.restart.concurrency.max(1)
                );
                let mut joins = tokio::task::JoinSet::new();
                for id in restart_now {
                    if let Some(worker) = workers.iter().find(|worker| worker.id == id) {
                        worker.deferred.store(false, Ordering::Relaxed);
                    }
                    let pool = Arc::clone(&pool);
                    joins.spawn(async move {
                        if let Err(err) = pool.restart_one(id).await {
                            eprintln!("[pool] 账号 {id} 保身份重启失败: {err}");
                        }
                    });
                }
                while joins.join_next().await.is_some() {}
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
            if let Some(worker) = workers
                .iter()
                .find(|worker| worker.id == pin && worker.is_ready())
            {
                return Ok(self.lease(worker.clone()));
            }
        }
        let eligible: Vec<usize> = workers
            .iter()
            .filter(|worker| worker.is_ready())
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
        if !worker.is_ready() {
            return Err(PickFail::NoWorker);
        }
        Ok(self.lease(worker))
    }

    /// 兼容旧调用：匿名轮询，不计入活跃连接。
    pub fn pick(&self) -> Option<NetHandle> {
        let lease = self.checkout(None, "").ok()?;
        let net = lease.net.clone();
        drop(lease);
        Some(net)
    }

    fn lease(&self, worker: Arc<Worker>) -> ConnLease {
        worker.active.fetch_add(1, Ordering::Relaxed);
        let inner = worker.inner.lock().unwrap();
        let egress = inner
            .trace
            .as_ref()
            .map(|trace| trace.ip.clone())
            .filter(|ip| !ip.is_empty())
            .unwrap_or_else(|| inner.assigned_v4.to_string());
        let net = inner.net.clone().expect("只租借已经就绪的账号");
        drop(inner);
        ConnLease {
            worker_id: worker.id,
            egress,
            net,
            worker,
        }
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
        worker.deferred.store(false, Ordering::Relaxed);
        let (reply_tx, reply_rx) = oneshot::channel();
        worker
            .restart_tx
            .send(RestartJob {
                reply: reply_tx,
                probe_timeout: self.restart.probe_timeout,
                retries: self.restart.retries,
                drain_timeout: self.restart.drain_timeout,
            })
            .map_err(|_| "账号监督任务已退出".to_string())?;
        let result = reply_rx.await.map_err(|_| "重启任务中断".to_string())?;
        drop(permit);
        result
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
    /// batch 为 0 时，每一轮包含当前全部账号。改完后按新间隔重新计时。
    pub fn set_restart_plan(
        &self,
        interval: Option<Duration>,
        batch: Option<usize>,
        defer: Option<Duration>,
    ) {
        if let Some(interval) = interval {
            *self.restart_interval.lock().unwrap() = interval;
        }
        if let Some(batch) = batch {
            self.restart_batch.store(batch, Ordering::Relaxed);
        }
        if let Some(defer) = defer {
            *self.restart_defer.lock().unwrap() = defer;
        }
        for worker in self.snapshot() {
            worker.deferred.store(false, Ordering::Relaxed);
        }
        self.restart_wake.notify_one();
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
        let id = self.next_id.fetch_add(1, Ordering::Relaxed);
        let opts = RegisterOptions {
            device_name: Some(format!("{}-{id}", self.device_name)),
            ..Default::default()
        };
        let upstream = self.upstream.for_index(id.saturating_sub(1));
        let cfg = register_with(upstream.as_ref(), &opts).await?;
        let (worker, jobs) = Worker::new(id, cfg, upstream);
        self.workers.lock().unwrap().push(worker.clone());
        self.build_tunnel(&worker).await?;
        Pool::spawn_supervisor(self.clone(), worker.clone(), jobs);
        spawn_trace(&worker);
        Ok(id)
    }

    pub fn remove_account(&self, id: usize) -> crate::Result<()> {
        let mut workers = self.workers.lock().unwrap();
        if workers.len() <= 1 {
            return Err(crate::Error::Config("不能删除最后一个账号".into()));
        }
        let before = workers.len();
        workers.retain(|worker| worker.id != id);
        if workers.len() == before {
            return Err(crate::Error::Config(format!("没有账号 {id}")));
        }
        drop(workers);
        self.scheduler.forget(id);
        if self.pinned.load(Ordering::Relaxed) == id {
            self.pinned.store(0, Ordering::Relaxed);
        }
        Ok(())
    }

    pub async fn refresh_trace(&self, id: usize) {
        for worker in self.snapshot() {
            if id != 0 && worker.id != id {
                continue;
            }
            if let Some(net) = worker.net() {
                worker.set_trace(crate::trace::fetch_trace(&net).await);
            }
        }
    }

    pub fn status(&self) -> PoolStatus {
        let pinned = self.pinned.load(Ordering::Relaxed);
        let accounts = self
            .snapshot()
            .iter()
            .map(|worker| {
                let draining = worker.draining.load(Ordering::Relaxed);
                let active = worker.active.load(Ordering::Relaxed);
                let inner = worker.inner.lock().unwrap();
                AccountStatus {
                    id: worker.id,
                    ready: !draining && inner.net.is_some(),
                    tunnel: inner.net.is_some(),
                    draining,
                    deferred: worker.deferred.load(Ordering::Relaxed),
                    active,
                    ip: inner.assigned_v4.to_string(),
                    trace: inner.trace.clone(),
                }
            })
            .collect();
        PoolStatus {
            enabled: self.enabled(),
            mode: if pinned == 0 { "auto" } else { "pinned" },
            pinned,
            http2: self.http2.load(Ordering::Relaxed),
            rotate_seconds: self.rotate_secs.load(Ordering::Relaxed),
            restart_seconds: self.restart_interval.lock().unwrap().as_secs(),
            restart_batch: self.restart_batch.load(Ordering::Relaxed),
            restart_concurrency: self.restart.concurrency.max(1),
            restart_defer_seconds: self.restart_defer.lock().unwrap().as_secs(),
            strategy: strategy_name(self.policy.strategy),
            sticky: sticky_name(self.policy.sticky),
            accounts,
        }
    }
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
fn earliest_restart(
    round_at: tokio::time::Instant,
    deferred: &[(usize, tokio::time::Instant)],
) -> tokio::time::Instant {
    deferred
        .iter()
        .fold(round_at, |soon, (_, at)| soon.min(*at))
}

fn schedule_defer(
    deferred: &mut Vec<(usize, tokio::time::Instant)>,
    id: usize,
    at: tokio::time::Instant,
) {
    if let Some(slot) = deferred.iter_mut().find(|(existing, _)| *existing == id) {
        slot.1 = at;
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
        if let Some(mut dead) = worker.dead_signal() {
            tokio::select! {
                _ = wait_true(&mut dead) => worker.clear_net(),
                _ = worker.rebuild.notified() => worker.clear_net(),
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
            }
        }
        if !reconnect_loop(&pool, &worker, &mut jobs).await {
            return;
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
        let Some(current) = pool.upgrade() else {
            return false;
        };
        let built = current.build_tunnel(worker).await;
        drop(current);
        match built {
            Ok(()) => {
                spawn_trace(worker);
                return true;
            }
            Err(err) => {
                eprintln!(
                    "[pool] 账号 {} 连接失败: {err}，{} 秒后重试",
                    worker.id,
                    backoff.as_secs()
                );
            }
        }
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
    worker.draining.store(true, Ordering::Relaxed);
    let result = restart_in_place(pool, worker, job).await;
    worker.draining.store(false, Ordering::Relaxed);
    result
}

async fn restart_in_place(
    pool: &Weak<Pool>,
    worker: &Arc<Worker>,
    job: &RestartJob,
) -> Result<(), String> {
    let started = tokio::time::Instant::now();
    while worker.active.load(Ordering::Relaxed) > 0 && started.elapsed() < job.drain_timeout {
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
    let mut last = "没有探测结果".to_string();
    let attempts = job.retries.saturating_add(1);
    for attempt in 1..=attempts {
        worker.retire();
        let Some(current) = pool.upgrade() else {
            return Err("连接池已关闭".into());
        };
        if let Err(err) = current.build_tunnel(worker).await {
            last = err.to_string();
            eprintln!(
                "[pool] 账号 {} 保身份重连失败 ({attempt}/{attempts}): {last}",
                worker.id
            );
            continue;
        }
        let Some(net) = worker.net() else {
            last = "隧道没有就绪".into();
            continue;
        };
        let info = crate::trace::fetch_trace_timeout(&net, job.probe_timeout).await;
        if info.warp == "on" || info.warp == "plus" {
            worker.set_trace(info);
            eprintln!("[pool] 账号 {} 保身份重启完成", worker.id);
            return Ok(());
        }
        last = info
            .err
            .clone()
            .unwrap_or_else(|| format!("warp={}", info.warp));
        eprintln!("[pool] 账号 {} 重启探测未通过: {last}", worker.id);
    }
    worker.retire();
    Err(last)
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

fn spawn_trace(worker: &Arc<Worker>) {
    let worker = worker.clone();
    tokio::spawn(async move {
        if let Some(net) = worker.net() {
            worker.set_trace(crate::trace::fetch_trace(&net).await);
        }
    });
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
    pub enabled: bool,
    pub mode: &'static str,
    pub pinned: usize,
    pub http2: bool,
    pub rotate_seconds: u64,
    /// 保身份重启间隔，0 表示没有计划。
    pub restart_seconds: u64,
    /// 每一轮重启几个账号，0 表示全部。
    pub restart_batch: usize,
    /// 同一轮里最多同时重启几个账号。
    pub restart_concurrency: usize,
    /// 忙碌时延后重启的秒数，0 表示不延后。
    pub restart_defer_seconds: u64,
    pub strategy: &'static str,
    pub sticky: &'static str,
    pub accounts: Vec<AccountStatus>,
}

/// 单个账号的状态。
#[derive(Serialize)]
pub struct AccountStatus {
    pub id: usize,
    pub ready: bool,
    pub tunnel: bool,
    pub draining: bool,
    /// 计划中的重启因为仍有连接而推迟。
    pub deferred: bool,
    pub active: usize,
    pub ip: String,
    pub trace: Option<TraceInfo>,
}

#[cfg(test)]
mod restart_plan_tests {
    use super::next_restart_batch;

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
}
