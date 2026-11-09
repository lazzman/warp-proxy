//! 面板用的运行时记录：连接与最近历史、日志环和定时重启计划。
//!
//! 这些状态只活在进程里。临时账号和执行历史不会写入账号文件。

use std::collections::{BTreeMap, VecDeque};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};

use serde::Serialize;

const LOG_LIMIT: usize = 300;
const LOG_LINE_LIMIT: usize = 2048;
const SESSION_LIMIT: usize = 300;
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

impl LiveSession {
    fn view(&self, now: u64, active: bool) -> SessionView {
        let touched = self.meter.touched.load(Ordering::Relaxed);
        SessionView {
            id: self.id,
            protocol: self.protocol.clone(),
            client: self.client.clone(),
            user: self.user.clone(),
            target: self.target.clone(),
            egress: self.egress.clone(),
            family: self.family.clone(),
            account: self.account,
            age_ms: now.saturating_sub(self.started),
            idle_ms: now.saturating_sub(touched),
            up: self.meter.up.load(Ordering::Relaxed),
            down: self.meter.down.load(Ordering::Relaxed),
            active,
        }
    }
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
    pub active: bool,
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

struct Sessions {
    active: BTreeMap<u64, LiveSession>,
    closed: BTreeMap<u64, SessionView>,
}

struct Inner {
    next_id: AtomicU64,
    sessions: Mutex<Sessions>,
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
                sessions: Mutex::new(Sessions {
                    active: BTreeMap::new(),
                    closed: BTreeMap::new(),
                }),
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
        let sessions = self.inner.sessions.lock().unwrap();
        let mut up = self.inner.up.load(Ordering::Relaxed);
        let mut down = self.inner.down.load(Ordering::Relaxed);
        for session in sessions.active.values() {
            up += session.meter.up.load(Ordering::Relaxed);
            down += session.meter.down.load(Ordering::Relaxed);
        }
        (up, down)
    }

    pub fn open_session(&self, open: SessionOpen) -> SessionGuard {
        let id = self.inner.next_id.fetch_add(1, Ordering::Relaxed);
        self.inner.sessions.lock().unwrap().active.insert(
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
        let sessions = self.inner.sessions.lock().unwrap();
        let mut rows: Vec<_> = sessions
            .active
            .iter()
            .rev()
            .take(SESSION_LIMIT)
            .map(|(_, session)| session.view(now, true))
            .chain(
                sessions
                    .closed
                    .iter()
                    .rev()
                    .take(SESSION_LIMIT)
                    .map(|(_, session)| session.clone()),
            )
            .collect();
        rows.sort_unstable_by(|left, right| right.id.cmp(&left.id));
        rows.truncate(SESSION_LIMIT);
        rows
    }

    pub fn active_count(&self) -> usize {
        self.inner.sessions.lock().unwrap().active.len()
    }

    pub fn log(&self, kind: &str, text: impl Into<String>) {
        let mut text = text.into();
        if text.len() > LOG_LINE_LIMIT {
            let mut end = LOG_LINE_LIMIT - "…".len();
            while !text.is_char_boundary(end) {
                end -= 1;
            }
            text.truncate(end);
            text.push('…');
        }
        let mut logs = self.inner.logs.lock().unwrap();
        logs.push_back(LogLine {
            at: unix_ms(),
            kind: kind.to_string(),
            text,
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

/// 连接结束时移入历史记录，并把流量计入累计值。
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
        let mut sessions = self.inner.sessions.lock().unwrap();
        if let Some(session) = sessions.active.remove(&self.id) {
            sessions
                .closed
                .insert(self.id, session.view(unix_ms(), false));
            if sessions.closed.len() > SESSION_LIMIT {
                sessions.closed.pop_first();
            }
        }
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

    fn test_session(console: &Console) -> (SessionGuard, Arc<TrafficMeter>) {
        let meter = Arc::new(TrafficMeter::new());
        let guard = console.open_session(SessionOpen {
            protocol: "socks".into(),
            client: "127.0.0.1:1".into(),
            user: "-".into(),
            target: "example.com:443".into(),
            egress: "1.1.1.1".into(),
            family: "ipv4".into(),
            account: 1,
            meter: Arc::clone(&meter),
        });
        (guard, meter)
    }

    #[test]
    fn closed_session_stays_in_history_and_keeps_bytes() {
        let console = Console::new();
        let (guard, meter) = test_session(&console);
        meter.up.store(12, Ordering::Relaxed);
        meter.down.store(3, Ordering::Relaxed);
        assert_eq!(console.sessions().len(), 1);
        assert!(console.sessions()[0].active);
        assert_eq!(console.active_count(), 1);
        assert_eq!(guard.id(), 1);
        drop(guard);
        assert_eq!(console.active_count(), 0);
        let closed = console.sessions().remove(0);
        assert!(!closed.active);
        assert_eq!((closed.up, closed.down), (12, 3));
        assert_eq!(console.totals(), (12, 3));
        meter.up.store(99, Ordering::Relaxed);
        assert_eq!(console.sessions()[0].up, 12);
    }

    #[test]
    fn sessions_show_newest_first_and_keep_at_most_300() {
        let console = Console::new();
        let (oldest, _) = test_session(&console);
        for _ in 0..10_000 {
            let (guard, meter) = test_session(&console);
            meter.up.store(1, Ordering::Relaxed);
            drop(guard);
        }
        let rows = console.sessions();
        assert_eq!(rows.len(), 300);
        assert_eq!(console.inner.sessions.lock().unwrap().closed.len(), 300);
        assert_eq!((rows[0].id, rows[299].id), (10_001, 9_702));
        assert!(rows.iter().all(|row| !row.active));
        assert_eq!(console.active_count(), 1);
        assert_eq!(console.totals(), (10_000, 0));

        drop(oldest);
        let rows = console.sessions();
        assert_eq!(rows.len(), 300);
        assert_eq!((rows[0].id, rows[299].id), (10_001, 9_702));
        assert_eq!(console.active_count(), 0);
    }

    #[test]
    fn active_and_closed_sessions_share_newest_first_order() {
        let console = Console::new();
        let (oldest, _) = test_session(&console);
        let (middle, _) = test_session(&console);
        let (newest, _) = test_session(&console);
        drop(middle);

        let rows = console.sessions();
        assert_eq!(rows.iter().map(|row| row.id).collect::<Vec<_>>(), [3, 2, 1]);
        assert_eq!(
            rows.iter().map(|row| row.active).collect::<Vec<_>>(),
            [true, false, true]
        );
        assert_eq!(console.active_count(), 2);
        drop((oldest, newest));
    }

    #[test]
    fn active_count_is_not_limited_by_display_history() {
        let console = Console::new();
        let guards: Vec<_> = (0..310).map(|_| test_session(&console).0).collect();
        assert_eq!(console.active_count(), 310);
        let rows = console.sessions();
        assert_eq!(rows.len(), 300);
        assert_eq!((rows[0].id, rows[299].id), (310, 11));
        assert!(rows.iter().all(|row| row.active));
        drop(guards);
        assert_eq!(console.active_count(), 0);
    }

    #[test]
    fn log_ring_and_plan_history_stay_bounded() {
        let console = Console::new();
        for index in 0..320 {
            console.log("access", format!("line {index}"));
        }
        assert_eq!(console.logs(0, 0, 0, 0).lines.len(), 300);
        console.log("access", "测".repeat(1000));
        let lines = console.logs(0, 0, 0, 0).lines;
        assert_eq!(lines.len(), 300);
        assert!(lines.last().unwrap().text.len() <= LOG_LINE_LIMIT);
        assert!(lines.last().unwrap().text.ends_with('…'));
        for _ in 0..12 {
            console.finish_round(1, 0, 0, 10);
        }
        assert_eq!(console.plan().history.len(), 10);
        assert_eq!(console.plan().last.unwrap().success, 1);
    }
}
