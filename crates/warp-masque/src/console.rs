//! 面板用的运行时记录：活跃连接、日志环和定时重启计划。
//!
//! 这些状态只活在进程里。临时账号和执行历史不会写入账号文件。

use std::collections::{HashMap, VecDeque};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};

use serde::Serialize;

const LOG_LIMIT: usize = 300;
const HISTORY_LIMIT: usize = 10;

pub fn unix_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_millis() as u64)
        .unwrap_or(0)
}

/// 一条连接的实时流量。中继线程和面板读的是同一组计数。
pub struct TrafficMeter {
    pub up: AtomicU64,
    pub down: AtomicU64,
    pub touched: AtomicU64,
}

impl TrafficMeter {
    pub fn new() -> Self {
        Self {
            up: AtomicU64::new(0),
            down: AtomicU64::new(0),
            touched: AtomicU64::new(unix_ms()),
        }
    }

    pub fn touch(&self) {
        self.touched.store(unix_ms(), Ordering::Relaxed);
    }
}

struct LiveSession {
    id: u64,
    protocol: String,
    client: String,
    user: String,
    target: String,
    egress: String,
    family: String,
    account: usize,
    started: u64,
    meter: Arc<TrafficMeter>,
}

#[derive(Clone, Serialize)]
pub struct SessionView {
    pub id: u64,
    pub protocol: String,
    pub client: String,
    pub user: String,
    pub target: String,
    pub egress: String,
    pub family: String,
    pub account: usize,
    pub age_ms: u64,
    pub idle_ms: u64,
    pub up: u64,
    pub down: u64,
}

#[derive(Clone, Serialize)]
pub struct LogLine {
    pub at: u64,
    pub kind: String,
    pub text: String,
}

#[derive(Clone, Serialize)]
pub struct LogPage {
    pub lines: Vec<LogLine>,
    pub ready: usize,
    pub attention: usize,
    pub maintenance: usize,
    pub unknown: usize,
}

#[derive(Clone, Serialize)]
pub struct PlanRound {
    pub at: u64,
    pub success: usize,
    pub failed: usize,
    pub deferred: usize,
    pub millis: u64,
}

#[derive(Clone, Serialize)]
pub struct PlanView {
    pub paused: bool,
    pub next_at: Option<u64>,
    pub ready: Vec<usize>,
    pub deferred: Vec<usize>,
    pub retry: Vec<usize>,
    pub last: Option<PlanRound>,
    pub history: Vec<PlanRound>,
}

struct PlanState {
    paused: bool,
    next_at: Option<u64>,
    ready: Vec<usize>,
    deferred: Vec<usize>,
    retry: Vec<usize>,
    last: Option<PlanRound>,
    history: VecDeque<PlanRound>,
}

impl PlanState {
    fn view(&self) -> PlanView {
        PlanView {
            paused: self.paused,
            next_at: self.next_at,
            ready: self.ready.clone(),
            deferred: self.deferred.clone(),
            retry: self.retry.clone(),
            last: self.last.clone(),
            history: self.history.iter().cloned().collect(),
        }
    }
}

struct Inner {
    next_id: AtomicU64,
    sessions: Mutex<HashMap<u64, LiveSession>>,
    logs: Mutex<VecDeque<LogLine>>,
    up: AtomicU64,
    down: AtomicU64,
    started: u64,
    plan: Mutex<PlanState>,
}

pub struct SessionOpen {
    pub protocol: String,
    pub client: String,
    pub user: String,
    pub target: String,
    pub egress: String,
    pub family: String,
    pub account: usize,
    pub meter: Arc<TrafficMeter>,
}

/// 进程内的面板数据。克隆只增加引用计数。
#[derive(Clone)]
pub struct Console {
    inner: Arc<Inner>,
}

impl Default for Console {
    fn default() -> Self {
        Self::new()
    }
}

impl Console {
    pub fn new() -> Self {
        Self {
            inner: Arc::new(Inner {
                next_id: AtomicU64::new(1),
                sessions: Mutex::new(HashMap::new()),
                logs: Mutex::new(VecDeque::new()),
                up: AtomicU64::new(0),
                down: AtomicU64::new(0),
                started: unix_ms(),
                plan: Mutex::new(PlanState {
                    paused: false,
                    next_at: None,
                    ready: Vec::new(),
                    deferred: Vec::new(),
                    retry: Vec::new(),
                    last: None,
                    history: VecDeque::new(),
                }),
            }),
        }
    }

    pub fn started_at(&self) -> u64 {
        self.inner.started
    }

    pub fn totals(&self) -> (u64, u64) {
        let mut up = self.inner.up.load(Ordering::Relaxed);
        let mut down = self.inner.down.load(Ordering::Relaxed);
        for session in self.inner.sessions.lock().unwrap().values() {
            up += session.meter.up.load(Ordering::Relaxed);
            down += session.meter.down.load(Ordering::Relaxed);
        }
        (up, down)
    }

    pub fn open_session(&self, open: SessionOpen) -> SessionGuard {
        let id = self.inner.next_id.fetch_add(1, Ordering::Relaxed);
        self.inner.sessions.lock().unwrap().insert(
            id,
            LiveSession {
                id,
                protocol: open.protocol,
                client: open.client,
                user: open.user,
                target: open.target,
                egress: open.egress,
                family: open.family,
                account: open.account,
                started: unix_ms(),
                meter: Arc::clone(&open.meter),
            },
        );
        SessionGuard {
            inner: Arc::clone(&self.inner),
            id,
            meter: open.meter,
        }
    }

    pub fn sessions(&self) -> Vec<SessionView> {
        let now = unix_ms();
        let mut rows: Vec<_> = self
            .inner
            .sessions
            .lock()
            .unwrap()
            .values()
            .map(|session| {
                let touched = session.meter.touched.load(Ordering::Relaxed);
                SessionView {
                    id: session.id,
                    protocol: session.protocol.clone(),
                    client: session.client.clone(),
                    user: session.user.clone(),
                    target: session.target.clone(),
                    egress: session.egress.clone(),
                    family: session.family.clone(),
                    account: session.account,
                    age_ms: now.saturating_sub(session.started),
                    idle_ms: now.saturating_sub(touched),
                    up: session.meter.up.load(Ordering::Relaxed),
                    down: session.meter.down.load(Ordering::Relaxed),
                }
            })
            .collect();
        rows.sort_by_key(|row| row.id);
        rows
    }

    pub fn log(&self, kind: &str, text: impl Into<String>) {
        let mut logs = self.inner.logs.lock().unwrap();
        logs.push_back(LogLine {
            at: unix_ms(),
            kind: kind.to_string(),
            text: text.into(),
        });
        while logs.len() > LOG_LIMIT {
            logs.pop_front();
        }
    }

    pub fn logs(
        &self,
        ready: usize,
        attention: usize,
        maintenance: usize,
        unknown: usize,
    ) -> LogPage {
        LogPage {
            lines: self.inner.logs.lock().unwrap().iter().cloned().collect(),
            ready,
            attention,
            maintenance,
            unknown,
        }
    }

    pub fn plan(&self) -> PlanView {
        self.inner.plan.lock().unwrap().view()
    }

    pub fn set_paused(&self, paused: bool) {
        self.inner.plan.lock().unwrap().paused = paused;
    }

    pub fn set_next(&self, next_at: Option<u64>) {
        self.inner.plan.lock().unwrap().next_at = next_at;
    }

    pub fn set_queues(&self, ready: &[usize], deferred: &[usize]) {
        let mut plan = self.inner.plan.lock().unwrap();
        plan.ready = ready.to_vec();
        plan.deferred = deferred.to_vec();
        plan.retry = deferred.to_vec();
    }

    pub fn clear_queues(&self) {
        let mut plan = self.inner.plan.lock().unwrap();
        plan.ready.clear();
        plan.deferred.clear();
        plan.retry.clear();
    }

    pub fn finish_round(&self, success: usize, failed: usize, deferred: usize, millis: u64) {
        let round = PlanRound {
            at: unix_ms(),
            success,
            failed,
            deferred,
            millis,
        };
        let mut plan = self.inner.plan.lock().unwrap();
        plan.last = Some(round.clone());
        plan.history.push_front(round);
        while plan.history.len() > HISTORY_LIMIT {
            plan.history.pop_back();
        }
        plan.ready.clear();
    }
}

/// 连接结束时从活跃表移除，并把流量计入累计值。
pub struct SessionGuard {
    inner: Arc<Inner>,
    id: u64,
    meter: Arc<TrafficMeter>,
}

impl SessionGuard {
    pub fn id(&self) -> u64 {
        self.id
    }
}

impl Drop for SessionGuard {
    fn drop(&mut self) {
        self.inner.sessions.lock().unwrap().remove(&self.id);
        self.inner
            .up
            .fetch_add(self.meter.up.load(Ordering::Relaxed), Ordering::Relaxed);
        self.inner
            .down
            .fetch_add(self.meter.down.load(Ordering::Relaxed), Ordering::Relaxed);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn closed_session_leaves_the_table_and_keeps_bytes() {
        let console = Console::new();
        let meter = Arc::new(TrafficMeter::new());
        meter.up.store(12, Ordering::Relaxed);
        let guard = console.open_session(SessionOpen {
            protocol: "socks".into(),
            client: "127.0.0.1:1".into(),
            user: "-".into(),
            target: "example.com:443".into(),
            egress: "1.1.1.1".into(),
            family: "ipv4".into(),
            account: 1,
            meter,
        });
        assert_eq!(console.sessions().len(), 1);
        assert_eq!(guard.id(), 1);
        drop(guard);
        assert!(console.sessions().is_empty());
        assert_eq!(console.totals(), (12, 0));
    }

    #[test]
    fn log_ring_and_plan_history_stay_bounded() {
        let console = Console::new();
        for index in 0..320 {
            console.log("access", format!("line {index}"));
        }
        assert_eq!(console.logs(0, 0, 0, 0).lines.len(), 300);
        for _ in 0..12 {
            console.finish_round(1, 0, 0, 10);
        }
        assert_eq!(console.plan().history.len(), 10);
        assert_eq!(console.plan().last.unwrap().success, 1);
    }
}
