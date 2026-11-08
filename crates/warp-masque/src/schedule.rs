//! 入口连接的选路。
//!
//! 带用户名的连接走黏性；匿名连接走 [`Strategy`]。username-round 的既有映射
//! 在目标账号仍存在但不健康时不会改派到其他账号。账号被删除后，映射作废，
//! 下一次作为新用户重新分配。

use std::collections::HashMap;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Mutex;
use std::time::{Duration, Instant};

/// 匿名连接，以及没有命中黏性时的选路方式。
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Strategy {
    Round,
    Random,
    Hash,
    Rotate,
}

/// 有身份时的黏性。`None` 表示全部走 [`Strategy`]。
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum StickyMode {
    None,
    UsernameRound,
    UsernameLeast,
    UsernameHash,
    IpHash,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PickFail {
    /// 当前没有可接流量的账号。
    NoWorker,
    /// 黏性账号仍在，但正在重启或离线，不为这个用户改派。
    StickyDown,
}

#[derive(Clone, Debug)]
pub struct Policy {
    pub strategy: Strategy,
    pub sticky: StickyMode,
    pub rotate_every: Duration,
}

impl Default for Policy {
    fn default() -> Self {
        Self {
            strategy: Strategy::Round,
            sticky: StickyMode::None,
            rotate_every: Duration::from_secs(300),
        }
    }
}

pub struct Scheduler {
    rr: AtomicUsize,
    sticky_cursor: AtomicUsize,
    sticky_map: Mutex<HashMap<String, usize>>,
    rotate_started: Mutex<Instant>,
    rotate_slot: Mutex<u64>,
    rotate_target: Mutex<Option<usize>>,
    rotate_order: Mutex<Vec<usize>>,
}

impl Scheduler {
    pub fn new() -> Self {
        Self {
            rr: AtomicUsize::new(0),
            sticky_cursor: AtomicUsize::new(0),
            sticky_map: Mutex::new(HashMap::new()),
            rotate_started: Mutex::new(Instant::now()),
            rotate_slot: Mutex::new(0),
            rotate_target: Mutex::new(None),
            rotate_order: Mutex::new(Vec::new()),
        }
    }

    /// 每个账号当前黏住的用户名数量。
    pub fn user_counts(&self) -> HashMap<usize, usize> {
        let map = self.sticky_map.lock().unwrap();
        let mut counts = HashMap::new();
        for id in map.values() {
            *counts.entry(*id).or_insert(0) += 1;
        }
        counts
    }

    pub fn forget(&self, worker_id: usize) {
        self.sticky_map
            .lock()
            .unwrap()
            .retain(|_, id| *id != worker_id);
        self.rotate_order
            .lock()
            .unwrap()
            .retain(|id| *id != worker_id);
        let mut target = self.rotate_target.lock().unwrap();
        if *target == Some(worker_id) {
            *target = None;
        }
    }

    pub fn pick(
        &self,
        policy: &Policy,
        eligible: &[usize],
        alive: &[usize],
        username: Option<&str>,
        client_ip: &str,
        active: impl Fn(usize) -> usize,
    ) -> Result<usize, PickFail> {
        if policy.sticky == StickyMode::IpHash {
            return rendezvous(&format!("ip:{client_ip}"), eligible).ok_or(PickFail::NoWorker);
        }
        if let Some(user) = username.filter(|user| !user.is_empty()) {
            match policy.sticky {
                StickyMode::UsernameRound => {
                    return self.sticky_assign(user, eligible, alive, true, &active);
                }
                StickyMode::UsernameLeast => {
                    return self.sticky_assign(user, eligible, alive, false, &active);
                }
                StickyMode::UsernameHash => {
                    return rendezvous(&format!("user:{user}"), eligible).ok_or(PickFail::NoWorker);
                }
                StickyMode::None | StickyMode::IpHash => {}
            }
        }
        if eligible.is_empty() {
            return Err(PickFail::NoWorker);
        }
        Ok(match policy.strategy {
            Strategy::Round => self.round(eligible),
            Strategy::Random => {
                let index = rand::random::<usize>() % eligible.len();
                eligible[index]
            }
            Strategy::Hash => {
                rendezvous(&format!("ip:{client_ip}"), eligible).unwrap_or(eligible[0])
            }
            Strategy::Rotate => self.rotate(policy.rotate_every, alive, eligible),
        })
    }

    fn round(&self, eligible: &[usize]) -> usize {
        let start = self.rr.fetch_add(1, Ordering::Relaxed);
        eligible[start % eligible.len()]
    }

    fn sticky_assign(
        &self,
        user: &str,
        eligible: &[usize],
        alive: &[usize],
        by_mapping: bool,
        active: &impl Fn(usize) -> usize,
    ) -> Result<usize, PickFail> {
        let mut map = self.sticky_map.lock().unwrap();
        if let Some(id) = map.get(user).copied() {
            if eligible.contains(&id) {
                return Ok(id);
            }
            if alive.contains(&id) {
                return Err(PickFail::StickyDown);
            }
            map.remove(user);
        }
        if eligible.is_empty() {
            return Err(PickFail::NoWorker);
        }
        let mut mapping_counts = HashMap::<usize, usize>::new();
        if by_mapping {
            for id in eligible {
                mapping_counts.insert(*id, 0);
            }
            for id in map.values() {
                if let Some(count) = mapping_counts.get_mut(id) {
                    *count += 1;
                }
            }
        }
        let score = |id: usize| -> usize {
            if by_mapping {
                mapping_counts.get(&id).copied().unwrap_or(0)
            } else {
                active(id)
            }
        };
        let minimum = eligible.iter().map(|id| score(*id)).min().unwrap();
        let start = self.sticky_cursor.load(Ordering::Relaxed) % eligible.len();
        let mut chosen = eligible[0];
        let mut offset_used = 0usize;
        for offset in 0..eligible.len() {
            let candidate = eligible[(start + offset) % eligible.len()];
            if score(candidate) == minimum {
                chosen = candidate;
                offset_used = offset;
                break;
            }
        }
        self.sticky_cursor
            .fetch_add(offset_used + 1, Ordering::Relaxed);
        map.insert(user.to_string(), chosen);
        Ok(chosen)
    }

    fn rotate(&self, every: Duration, alive: &[usize], eligible: &[usize]) -> usize {
        if every.is_zero() {
            return self.round(eligible);
        }
        let mut order = self.rotate_order.lock().unwrap();
        for id in alive {
            if !order.contains(id) {
                order.push(*id);
            }
        }
        order.retain(|id| alive.contains(id));
        if order.is_empty() {
            return eligible[0];
        }
        let slot = self.rotate_started.lock().unwrap().elapsed().as_secs() / every.as_secs().max(1);
        let mut seen_slot = self.rotate_slot.lock().unwrap();
        let mut target = self.rotate_target.lock().unwrap();
        if target.is_none() {
            *target = Some(order[0]);
            *seen_slot = 0;
        }
        while *seen_slot < slot {
            let current = target.unwrap_or(order[0]);
            let index = order.iter().position(|id| *id == current).unwrap_or(0);
            *target = Some(order[(index + 1) % order.len()]);
            *seen_slot += 1;
        }
        let preferred = target.unwrap_or(order[0]);
        if eligible.contains(&preferred) {
            return preferred;
        }
        let start = order.iter().position(|id| *id == preferred).unwrap_or(0);
        for offset in 1..=order.len() {
            let candidate = order[(start + offset) % order.len()];
            if eligible.contains(&candidate) {
                return candidate;
            }
        }
        eligible[0]
    }
}

impl Default for Scheduler {
    fn default() -> Self {
        Self::new()
    }
}

pub fn rendezvous(key: &str, eligible: &[usize]) -> Option<usize> {
    eligible.iter().copied().max_by_key(|id| score(key, *id))
}

fn score(key: &str, id: usize) -> u64 {
    let mut hash = 0xcbf29ce484222325u64;
    for byte in key.as_bytes() {
        hash ^= u64::from(*byte);
        hash = hash.wrapping_mul(0x100000001b3);
    }
    hash ^= 0xff;
    for byte in id.to_le_bytes() {
        hash ^= u64::from(byte);
        hash = hash.wrapping_mul(0x100000001b3);
    }
    hash
}

pub fn parse_strategy(value: &str) -> Result<Strategy, String> {
    match value.trim().to_ascii_lowercase().as_str() {
        "round" | "round-robin" => Ok(Strategy::Round),
        "random" => Ok(Strategy::Random),
        "hash" => Ok(Strategy::Hash),
        "rotate" => Ok(Strategy::Rotate),
        other => Err(format!(
            "未知 LB_STRATEGY={other}（round|random|hash|rotate）"
        )),
    }
}

pub fn parse_sticky(value: &str) -> Result<StickyMode, String> {
    match value.trim().to_ascii_lowercase().as_str() {
        "none" | "off" | "" => Ok(StickyMode::None),
        "username-round" => Ok(StickyMode::UsernameRound),
        "username-least" => Ok(StickyMode::UsernameLeast),
        "username-hash" => Ok(StickyMode::UsernameHash),
        "ip-hash" | "client-ip-hash" => Ok(StickyMode::IpHash),
        other => Err(format!(
            "未知 LB_STICKY_MODE={other}（none|username-round|username-least|username-hash|ip-hash）"
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn policy(strategy: Strategy, sticky: StickyMode) -> Policy {
        Policy {
            strategy,
            sticky,
            rotate_every: Duration::from_secs(300),
        }
    }

    #[test]
    fn username_round_sticks_and_does_not_migrate() {
        let scheduler = Scheduler::new();
        let rule = policy(Strategy::Round, StickyMode::UsernameRound);
        let eligible = [1usize, 2, 3];
        let first = scheduler
            .pick(
                &rule,
                &eligible,
                &eligible,
                Some("alice"),
                "10.0.0.1",
                |_| 0,
            )
            .unwrap();
        let again = scheduler
            .pick(
                &rule,
                &eligible,
                &eligible,
                Some("alice"),
                "10.0.0.9",
                |_| 0,
            )
            .unwrap();
        assert_eq!(first, again);

        let still_alive = [1usize, 2, 3];
        let without = eligible
            .into_iter()
            .filter(|id| *id != first)
            .collect::<Vec<_>>();
        let held = scheduler.pick(
            &rule,
            &without,
            &still_alive,
            Some("alice"),
            "10.0.0.1",
            |_| 0,
        );
        assert_eq!(held, Err(PickFail::StickyDown));

        scheduler.forget(first);
        let reassigned = scheduler
            .pick(&rule, &without, &without, Some("alice"), "10.0.0.1", |_| 0)
            .unwrap();
        assert_ne!(reassigned, first);
    }

    #[test]
    fn anonymous_ignores_username_sticky() {
        let scheduler = Scheduler::new();
        let rule = policy(Strategy::Round, StickyMode::UsernameRound);
        let eligible = [7usize, 8];
        let first = scheduler
            .pick(&rule, &eligible, &eligible, None, "10.0.0.2", |_| 0)
            .unwrap();
        let second = scheduler
            .pick(&rule, &eligible, &eligible, None, "10.0.0.2", |_| 0)
            .unwrap();
        assert_ne!(first, second);
    }

    #[test]
    fn username_least_uses_active_count_then_sticks() {
        let scheduler = Scheduler::new();
        let rule = policy(Strategy::Round, StickyMode::UsernameLeast);
        let eligible = [1usize, 2];
        let picked = scheduler
            .pick(&rule, &eligible, &eligible, Some("bob"), "", |id| {
                if id == 1 {
                    4
                } else {
                    1
                }
            })
            .unwrap();
        assert_eq!(picked, 2);
        let stuck = scheduler
            .pick(&rule, &eligible, &eligible, Some("bob"), "", |_| 0)
            .unwrap();
        assert_eq!(stuck, 2);
    }

    #[test]
    fn hash_is_stable_for_the_same_key() {
        let ids = [3usize, 9, 12];
        assert_eq!(
            rendezvous("user:alice", &ids),
            rendezvous("user:alice", &ids)
        );
    }

    #[test]
    fn username_hash_sticks_and_anonymous_does_not() {
        let scheduler = Scheduler::new();
        let rule = policy(Strategy::Round, StickyMode::UsernameHash);
        let eligible = [1usize, 2, 3];
        let first = scheduler
            .pick(
                &rule,
                &eligible,
                &eligible,
                Some("alice"),
                "10.0.0.1",
                |_| 0,
            )
            .unwrap();
        let again = scheduler
            .pick(
                &rule,
                &eligible,
                &eligible,
                Some("alice"),
                "10.9.9.9",
                |_| 0,
            )
            .unwrap();
        assert_eq!(first, again);
        let anon_a = scheduler
            .pick(&rule, &eligible, &eligible, None, "10.0.0.1", |_| 0)
            .unwrap();
        let anon_b = scheduler
            .pick(&rule, &eligible, &eligible, None, "10.0.0.1", |_| 0)
            .unwrap();
        assert_ne!(anon_a, anon_b);
    }

    #[test]
    fn ip_hash_ignores_username() {
        let scheduler = Scheduler::new();
        let rule = policy(Strategy::Round, StickyMode::IpHash);
        let eligible = [4usize, 5, 6];
        let alice = scheduler
            .pick(
                &rule,
                &eligible,
                &eligible,
                Some("alice"),
                "192.0.2.10",
                |_| 0,
            )
            .unwrap();
        let bob = scheduler
            .pick(
                &rule,
                &eligible,
                &eligible,
                Some("bob"),
                "192.0.2.10",
                |_| 0,
            )
            .unwrap();
        assert_eq!(alice, bob);
        assert_eq!(rendezvous("ip:192.0.2.10", &eligible), Some(alice));
    }

    #[test]
    fn rotate_stays_inside_window_and_advances_after_it() {
        let scheduler = Scheduler::new();
        let rule = Policy {
            strategy: Strategy::Rotate,
            sticky: StickyMode::None,
            rotate_every: Duration::from_secs(10),
        };
        let eligible = [1usize, 2];
        *scheduler.rotate_started.lock().unwrap() = Instant::now() - Duration::from_secs(15);
        let first = scheduler
            .pick(&rule, &eligible, &eligible, None, "192.0.2.1", |_| 0)
            .unwrap();
        let same_window = scheduler
            .pick(&rule, &eligible, &eligible, None, "192.0.2.1", |_| 0)
            .unwrap();
        assert_eq!(first, 2);
        assert_eq!(same_window, first);

        *scheduler.rotate_started.lock().unwrap() = Instant::now() - Duration::from_secs(25);
        let next_window = scheduler
            .pick(&rule, &eligible, &eligible, None, "192.0.2.1", |_| 0)
            .unwrap();
        assert_eq!(next_window, 1);

        // 当前窗口的账号不健康时，临时改派，不把窗口指针拨走。
        let failover = scheduler
            .pick(&rule, &[2], &eligible, None, "192.0.2.1", |_| 0)
            .unwrap();
        assert_eq!(failover, 2);
        let restored = scheduler
            .pick(&rule, &eligible, &eligible, None, "192.0.2.1", |_| 0)
            .unwrap();
        assert_eq!(restored, 1);
    }
}
