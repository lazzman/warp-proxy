//! A userspace TCP/IP netstack that turns the raw IP-packet [`TunnelIo`] into
//! usable outbound TCP connections and DNS resolution.
//!
//! smoltcp is synchronous/poll-driven, so it runs on its own OS thread (the
//! "actor"): it owns the [`Interface`], the [`SocketSet`] and a channel-backed
//! [`Device`], drives `iface.poll()`, and forwards packets to/from the tunnel.
//! The async world (the SOCKS server) talks to it through a [`NetHandle`] over a
//! command channel; each TCP connection gets a pair of byte channels bridged to
//! a smoltcp socket.
//!
//! Assigned addresses are static (from registration); the interface is
//! configured with them plus default routes so every off-link destination is
//! emitted to the tunnel device.

use std::collections::{HashMap, HashSet, VecDeque};
use std::future::Future;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::mpsc as smpsc;
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::{Duration, Instant as StdInstant};

use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

use smoltcp::iface::{Config, Interface, PollResult, SocketHandle, SocketSet};
use smoltcp::phy::{Device, DeviceCapabilities, Medium, RxToken, TxToken};
use smoltcp::socket::{dns, tcp};
use smoltcp::time::Instant;
use smoltcp::wire::{
    DnsQueryType, HardwareAddress, IpAddress, IpCidr, IpEndpoint, IpListenEndpoint,
};
use tokio::sync::{
    mpsc as tmpsc, oneshot, AcquireError, OwnedSemaphorePermit, Semaphore, TryAcquireError,
};

use crate::tunnel::{AbortOnDrop, TunnelIo};

/// 单条 TCP 连接的接收/发送缓冲大小（配合 smoltcp RFC 1323 窗口缩放提升高延迟单流速度）。
const SOCK_RX_BUF: usize = 512 * 1024;
const SOCK_TX_BUF: usize = 256 * 1024;
/// 单条连接在异步侧与 actor 之间允许在途的最大上行字节数，防止大文件上传打爆内存。
const TX_WINDOW_BYTES: usize = 512 * 1024;
/// 单次上行写入申请的最大许可块大小，避免超大缓冲写入时等待整窗归零。
const TX_WRITE_CHUNK: usize = 64 * 1024;
const RECV_CHUNK: usize = 16 * 1024;
const CHAN_DEPTH: usize = 64;
/// 隧道入站未消费 IP 包上限，超出时按网卡满环丢包以保护进程内存。
const MAX_INBOUND_QUEUE: usize = 1024;
/// smoltcp 连接超时与保活间隔，防止黑洞或静默失联 socket 永久占用内存。
const TCP_SOCKET_TIMEOUT: smoltcp::time::Duration = smoltcp::time::Duration::from_secs(60);
const TCP_KEEP_ALIVE: smoltcp::time::Duration = smoltcp::time::Duration::from_secs(30);
/// 本端读写均已关闭但对端长期不回 FIN/ACK 时的强制回收兜底时长。
const TCP_CLOSING_TIMEOUT: Duration = Duration::from_secs(15);
/// out_buf 排空后容量超过该值则收缩，避免长连接偶发突发上传后长期占用峰值内存。
const OUT_BUF_SHRINK_THRESHOLD: usize = 64 * 1024;

/// 隧道内域名解析的地址族偏好。字面量 IP 也按这个偏好过滤。
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ResolvePreference {
    /// 同时查询 A 和 AAAA，两者都有时用 IPv4。
    Auto,
    Ipv4Prefer,
    Ipv6Prefer,
    Ipv4Only,
    Ipv6Only,
}

impl ResolvePreference {
    pub fn parse(value: &str) -> Result<Self, String> {
        match value.trim().to_ascii_lowercase().as_str() {
            "" | "auto" => Ok(Self::Auto),
            "ipv4_prefer" | "ipv4-prefer" => Ok(Self::Ipv4Prefer),
            "ipv6_prefer" | "ipv6-prefer" => Ok(Self::Ipv6Prefer),
            "ipv4_only" | "ipv4" | "v4" => Ok(Self::Ipv4Only),
            "ipv6_only" | "ipv6" | "v6" => Ok(Self::Ipv6Only),
            other => Err(format!(
                "未知 RESOLVE_PREFERENCE={other}（auto|ipv4_prefer|ipv6_prefer|ipv4_only|ipv6_only）"
            )),
        }
    }
}

/// 域名或字面量地址在进入 DNS 之前的决定。
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum ResolvePlan {
    /// 已经有最终结果，不再发查询。
    Ready(Result<IpAddr, String>),
    /// 需要向隧道内 DNS 查询的地址族。
    Lookup {
        preference: ResolvePreference,
        query_v4: bool,
        query_v6: bool,
    },
}

/// 根据偏好和隧道是否拥有 IPv6，决定字面量是否放行、以及要查 A 还是 AAAA。
pub(crate) fn plan_resolve(
    name: &str,
    preference: ResolvePreference,
    ipv6_enabled: bool,
) -> ResolvePlan {
    if let Ok(ip) = name.parse::<IpAddr>() {
        let allowed = match ip {
            IpAddr::V4(_) => preference != ResolvePreference::Ipv6Only,
            IpAddr::V6(_) => ipv6_enabled && preference != ResolvePreference::Ipv4Only,
        };
        return ResolvePlan::Ready(if allowed {
            Ok(ip)
        } else {
            Err("地址族与解析偏好不符".into())
        });
    }
    if preference == ResolvePreference::Ipv6Only && !ipv6_enabled {
        return ResolvePlan::Ready(Err("隧道没有 IPv6 地址".into()));
    }
    let preference = if ipv6_enabled {
        preference
    } else {
        ResolvePreference::Ipv4Only
    };
    ResolvePlan::Lookup {
        query_v4: preference != ResolvePreference::Ipv6Only,
        query_v6: preference != ResolvePreference::Ipv4Only,
        preference,
    }
}

/// 按偏好从两组结果里选一个地址。
pub fn select_ip(
    preference: ResolvePreference,
    v4: &[IpAddr],
    v6: &[IpAddr],
) -> Result<IpAddr, String> {
    let v4 = v4.iter().find(|ip| ip.is_ipv4()).cloned();
    let v6 = v6.iter().find(|ip| ip.is_ipv6()).cloned();
    match preference {
        ResolvePreference::Ipv4Only => v4.ok_or_else(|| "没有 IPv4 地址".into()),
        ResolvePreference::Ipv6Only => v6.ok_or_else(|| "没有 IPv6 地址".into()),
        ResolvePreference::Ipv6Prefer => v6.or(v4).ok_or_else(|| "没有地址".into()),
        ResolvePreference::Auto | ResolvePreference::Ipv4Prefer => {
            v4.or(v6).ok_or_else(|| "没有地址".into())
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
struct ConnectionHandle(u64);

/// Commands sent from the async world to the smoltcp actor thread.
enum Cmd {
    Inbound(Vec<u8>),
    Connect {
        remote: SocketAddr,
        from_net: tmpsc::Sender<Vec<u8>>,
        rx_stalled: Arc<AtomicBool>,
        tx_budget: Arc<Semaphore>,
        reply: oneshot::Sender<Result<ConnectionHandle, String>>,
    },
    Send {
        handle: ConnectionHandle,
        data: Vec<u8>,
        permits: usize,
    },
    Close {
        handle: ConnectionHandle,
    },
    Abort {
        handle: ConnectionHandle,
    },
    /// connect() 已取得连接标识，确认后续由 TcpConn 接管。
    Handoff {
        handle: ConnectionHandle,
    },
    Resolve {
        name: String,
        reply: oneshot::Sender<Result<IpAddr, String>>,
    },
    /// 消费者从满队列取走数据后立即唤醒 actor 重新开窗。
    Wake,
    /// 底层隧道已关闭，立刻清理残留 socket 并终止等待中的建连/解析。
    TunnelClosed,
    /// 所有外部句柄已释放，退出 actor OS 线程。
    Shutdown,
}

/// 持有全部外部引用计数：最后一个 NetHandle/TcpConn/TcpReader/TcpWriter/TcpAbort 释放时，
/// 自动中止 feeder 任务并通知 actor OS 线程退出，杜绝线程与任务泄漏。
struct NetShutdown {
    cmd: smpsc::Sender<Cmd>,
    feeder: AbortOnDrop,
}

impl Drop for NetShutdown {
    fn drop(&mut self) {
        self.feeder.0.abort();
        let _ = self.cmd.send(Cmd::Shutdown);
    }
}

/// A cloneable async handle to the netstack.
#[derive(Clone)]
pub struct NetHandle {
    cmd: smpsc::Sender<Cmd>,
    lifecycle: Option<Arc<NetShutdown>>,
}

/// 测试用：保留命令接收端但不启动 actor，让 resolve/connect 永远等不到回复。
#[cfg(test)]
pub(crate) struct PendingNetGuard {
    _cmd: smpsc::Receiver<Cmd>,
}

#[cfg(test)]
pub(crate) fn pending_test_handle() -> (NetHandle, PendingNetGuard) {
    let (cmd, rx) = smpsc::channel();
    (
        NetHandle {
            cmd,
            lifecycle: None,
        },
        PendingNetGuard { _cmd: rx },
    )
}

/// 测试用模拟连接套件：返回 TcpConn 与观测端，便于验证半关闭与背压行为。
#[cfg(test)]
pub(crate) struct MockTcpConn {
    pub conn: TcpConn,
    pub from_net_tx: tmpsc::Sender<Vec<u8>>,
    pub sent_rx: smpsc::Receiver<Vec<u8>>,
    pub closed_rx: smpsc::Receiver<bool>,
}

/// 测试用：创建可观察命令和注入下行数据的模拟 TcpConn，用于验证中继半关闭语义。
#[cfg(test)]
pub(crate) fn mock_tcp_conn() -> MockTcpConn {
    let (cmd_tx, cmd_rx) = smpsc::channel();
    let (from_net_tx, from_net_rx) = tmpsc::channel(CHAN_DEPTH);
    let (sent_tx, sent_rx) = smpsc::channel();
    let (closed_tx, closed_rx) = smpsc::channel();
    let tx_budget = Arc::new(Semaphore::new(TX_WINDOW_BYTES));
    let budget_for_bridge = Arc::clone(&tx_budget);
    std::thread::spawn(move || {
        while let Ok(cmd) = cmd_rx.recv() {
            match cmd {
                Cmd::Send { data, permits, .. } => {
                    if permits > 0 {
                        budget_for_bridge.add_permits(permits);
                    }
                    let _ = sent_tx.send(data);
                }
                Cmd::Close { .. } => {
                    let _ = closed_tx.send(true);
                }
                Cmd::Abort { .. } => {
                    let _ = closed_tx.send(false);
                    break;
                }
                _ => {}
            }
        }
    });
    let handle = ConnectionHandle(1);
    let conn = TcpConn {
        handle,
        cmd: cmd_tx.clone(),
        from_net: from_net_rx,
        rx_stalled: Arc::new(AtomicBool::new(false)),
        tx_budget,
        write_wait: None,
        read_buf: Vec::new(),
        read_pos: 0,
        abort_guard: AbortOnDropConn {
            cmd: cmd_tx,
            handle,
            armed: AtomicBool::new(true),
        },
        lifecycle: None,
    };
    MockTcpConn {
        conn,
        from_net_tx,
        sent_rx,
        closed_rx,
    }
}

impl NetHandle {
    #[cfg(test)]
    pub(crate) fn test_handle() -> Self {
        let (cmd, _receiver) = smpsc::channel();
        Self {
            cmd,
            lifecycle: None,
        }
    }

    /// Resolve a hostname to an IP address through the tunnel.
    pub async fn resolve(&self, name: &str) -> Result<IpAddr, String> {
        let (reply, rx) = oneshot::channel();
        self.cmd
            .send(Cmd::Resolve {
                name: name.to_string(),
                reply,
            })
            .map_err(|_| "netstack stopped".to_string())?;
        rx.await.map_err(|_| "netstack dropped".to_string())?
    }

    /// Open an outbound TCP connection to `remote` through the tunnel.
    pub async fn connect(&self, remote: SocketAddr) -> Result<TcpConn, String> {
        let (from_net_tx, from_net_rx) = tmpsc::channel(CHAN_DEPTH);
        let rx_stalled = Arc::new(AtomicBool::new(false));
        let tx_budget = Arc::new(Semaphore::new(TX_WINDOW_BYTES));
        let (reply, rx) = oneshot::channel();
        self.cmd
            .send(Cmd::Connect {
                remote,
                from_net: from_net_tx,
                rx_stalled: Arc::clone(&rx_stalled),
                tx_budget: Arc::clone(&tx_budget),
                reply,
            })
            .map_err(|_| "netstack stopped".to_string())?;
        let handle = rx.await.map_err(|_| "netstack stopped".to_string())??;
        // 确认异步侧已接管；若请求在建立 TcpConn 前被取消，actor 会据
        // handed_off=false 且 from_net 已关闭清理这个 socket。
        self.cmd
            .send(Cmd::Handoff { handle })
            .map_err(|_| "netstack stopped".to_string())?;
        Ok(TcpConn {
            handle,
            cmd: self.cmd.clone(),
            from_net: from_net_rx,
            rx_stalled,
            tx_budget,
            write_wait: None,
            read_buf: Vec::new(),
            read_pos: 0,
            abort_guard: AbortOnDropConn {
                cmd: self.cmd.clone(),
                handle,
                armed: AtomicBool::new(true),
            },
            lifecycle: self.lifecycle.clone(),
        })
    }
}

type PermitFuture =
    Pin<Box<dyn Future<Output = Result<OwnedSemaphorePermit, AcquireError>> + Send + Sync>>;

impl AsyncRead for TcpConn {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        let me = self.get_mut();
        if me.read_pos >= me.read_buf.len() {
            match me.from_net.poll_recv(cx) {
                Poll::Ready(Some(v)) => {
                    if me.rx_stalled.swap(false, Ordering::AcqRel) {
                        let _ = me.cmd.send(Cmd::Wake);
                    }
                    me.read_buf = v;
                    me.read_pos = 0;
                }
                Poll::Ready(None) => return Poll::Ready(Ok(())), // EOF
                Poll::Pending => return Poll::Pending,
            }
        }
        let n = std::cmp::min(buf.remaining(), me.read_buf.len() - me.read_pos);
        buf.put_slice(&me.read_buf[me.read_pos..me.read_pos + n]);
        me.read_pos += n;
        Poll::Ready(Ok(()))
    }
}

impl AsyncWrite for TcpConn {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        if buf.is_empty() {
            return Poll::Ready(Ok(0));
        }
        let me = self.get_mut();
        let step = buf.len().min(TX_WRITE_CHUNK);

        if let Some((reserved, fut)) = me.write_wait.as_mut() {
            match fut.as_mut().poll(cx) {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(Err(_)) => {
                    me.write_wait = None;
                    return Poll::Ready(Err(std::io::ErrorKind::BrokenPipe.into()));
                }
                Poll::Ready(Ok(permit)) => {
                    let reserved = *reserved;
                    me.write_wait = None;
                    permit.forget();
                    let to_send = buf.len().min(reserved);
                    if reserved > to_send {
                        me.tx_budget.add_permits(reserved - to_send);
                    }
                    return match me.cmd.send(Cmd::Send {
                        handle: me.handle,
                        data: buf[..to_send].to_vec(),
                        permits: to_send,
                    }) {
                        Ok(()) => Poll::Ready(Ok(to_send)),
                        Err(_) => {
                            me.tx_budget.add_permits(to_send);
                            Poll::Ready(Err(std::io::ErrorKind::BrokenPipe.into()))
                        }
                    };
                }
            }
        }

        match me.tx_budget.try_acquire_many(step as u32) {
            Ok(permit) => {
                permit.forget();
                match me.cmd.send(Cmd::Send {
                    handle: me.handle,
                    data: buf[..step].to_vec(),
                    permits: step,
                }) {
                    Ok(()) => Poll::Ready(Ok(step)),
                    Err(_) => {
                        me.tx_budget.add_permits(step);
                        Poll::Ready(Err(std::io::ErrorKind::BrokenPipe.into()))
                    }
                }
            }
            Err(TryAcquireError::Closed) => Poll::Ready(Err(std::io::ErrorKind::BrokenPipe.into())),
            Err(TryAcquireError::NoPermits) => {
                let mut fut: PermitFuture =
                    Box::pin(Arc::clone(&me.tx_budget).acquire_many_owned(step as u32));
                match fut.as_mut().poll(cx) {
                    Poll::Pending => {
                        me.write_wait = Some((step, fut));
                        Poll::Pending
                    }
                    Poll::Ready(Err(_)) => Poll::Ready(Err(std::io::ErrorKind::BrokenPipe.into())),
                    Poll::Ready(Ok(permit)) => {
                        permit.forget();
                        match me.cmd.send(Cmd::Send {
                            handle: me.handle,
                            data: buf[..step].to_vec(),
                            permits: step,
                        }) {
                            Ok(()) => Poll::Ready(Ok(step)),
                            Err(_) => {
                                me.tx_budget.add_permits(step);
                                Poll::Ready(Err(std::io::ErrorKind::BrokenPipe.into()))
                            }
                        }
                    }
                }
            }
        }
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        let me = self.get_mut();
        // 已请求优雅关闭，后续 Drop 不应再用 Abort 覆盖。
        me.abort_guard.armed.store(false, Ordering::Relaxed);
        let _ = me.cmd.send(Cmd::Close { handle: me.handle });
        Poll::Ready(Ok(()))
    }
}

/// One outbound TCP connection through the netstack. Implements
/// [`AsyncRead`]/[`AsyncWrite`], so it can back a TLS client or be spliced with
/// `tokio::io::copy_bidirectional`.
pub struct TcpConn {
    handle: ConnectionHandle,
    cmd: smpsc::Sender<Cmd>,
    from_net: tmpsc::Receiver<Vec<u8>>,
    rx_stalled: Arc<AtomicBool>,
    tx_budget: Arc<Semaphore>,
    write_wait: Option<(usize, PermitFuture)>,
    read_buf: Vec<u8>,
    read_pos: usize,
    /// 若 TcpConn 在 into_split 之前被丢弃（例如排空超时取消请求），
    /// 没有 TcpWriter/TcpReader 会发 Close，必须直接 abort 清理 actor 里的 socket。
    abort_guard: AbortOnDropConn,
    lifecycle: Option<Arc<NetShutdown>>,
}

impl TcpConn {
    /// Receive the next chunk of bytes from the remote, or `None` at EOF.
    pub async fn recv(&mut self) -> Option<Vec<u8>> {
        let chunk = self.from_net.recv().await?;
        if self.rx_stalled.swap(false, Ordering::AcqRel) {
            let _ = self.cmd.send(Cmd::Wake);
        }
        Some(chunk)
    }

    /// Queue bytes to send to the remote.
    pub fn send(&self, data: Vec<u8>) {
        let _ = self.cmd.send(Cmd::Send {
            handle: self.handle,
            data,
            permits: 0,
        });
    }

    /// Ask the netstack to close the sending half once drained.
    pub fn close(&self) {
        self.abort_guard.armed.store(false, Ordering::Relaxed);
        let _ = self.cmd.send(Cmd::Close {
            handle: self.handle,
        });
    }

    /// 生成一个可稍后强制断开该连接的轻量句柄。
    pub fn abort_handle(&self) -> TcpAbort {
        TcpAbort {
            cmd: self.cmd.clone(),
            handle: self.handle,
            _lifecycle: self.lifecycle.clone(),
        }
    }

    /// Split into independent read/write halves for concurrent relaying.
    pub fn into_split(self) -> (TcpReader, TcpWriter) {
        // 之后由 TcpWriter::drop 发 Close，不再需要守卫强制 abort。
        self.abort_guard.armed.store(false, Ordering::Relaxed);
        (
            TcpReader {
                from_net: self.from_net,
                cmd: self.cmd.clone(),
                rx_stalled: self.rx_stalled,
                _lifecycle: self.lifecycle.clone(),
            },
            TcpWriter {
                handle: self.handle,
                cmd: self.cmd,
                tx_budget: self.tx_budget,
                _lifecycle: self.lifecycle,
            },
        )
    }
}

/// Read half of a [`TcpConn`].
pub struct TcpReader {
    from_net: tmpsc::Receiver<Vec<u8>>,
    cmd: smpsc::Sender<Cmd>,
    rx_stalled: Arc<AtomicBool>,
    _lifecycle: Option<Arc<NetShutdown>>,
}

impl TcpReader {
    /// Receive the next chunk from the remote, or `None` at EOF.
    pub async fn recv(&mut self) -> Option<Vec<u8>> {
        let chunk = self.from_net.recv().await?;
        if self.rx_stalled.swap(false, Ordering::AcqRel) {
            let _ = self.cmd.send(Cmd::Wake);
        }
        Some(chunk)
    }
}

/// Write half of a [`TcpConn`]. Closes the connection when dropped.
pub struct TcpWriter {
    handle: ConnectionHandle,
    cmd: smpsc::Sender<Cmd>,
    tx_budget: Arc<Semaphore>,
    _lifecycle: Option<Arc<NetShutdown>>,
}

impl TcpWriter {
    /// 带背压的异步发送：等待该连接的上行窗口额度，防止高速上传撑爆内存。
    pub async fn send_async(&self, data: &[u8]) -> Result<(), ()> {
        for chunk in data.chunks(TX_WRITE_CHUNK) {
            let permit = self
                .tx_budget
                .acquire_many(chunk.len() as u32)
                .await
                .map_err(|_| ())?;
            permit.forget();
            if self
                .cmd
                .send(Cmd::Send {
                    handle: self.handle,
                    data: chunk.to_vec(),
                    permits: chunk.len(),
                })
                .is_err()
            {
                self.tx_budget.add_permits(chunk.len());
                return Err(());
            }
        }
        Ok(())
    }

    /// Queue bytes to send to the remote.
    pub fn send(&self, data: Vec<u8>) {
        let _ = self.cmd.send(Cmd::Send {
            handle: self.handle,
            data,
            permits: 0,
        });
    }

    /// Close the sending half once drained.
    pub fn close(&self) {
        let _ = self.cmd.send(Cmd::Close {
            handle: self.handle,
        });
    }
}

#[derive(Clone)]
pub struct TcpAbort {
    cmd: smpsc::Sender<Cmd>,
    handle: ConnectionHandle,
    _lifecycle: Option<Arc<NetShutdown>>,
}

impl TcpAbort {
    pub fn abort(&self) {
        let _ = self.cmd.send(Cmd::Abort {
            handle: self.handle,
        });
    }
}

struct AbortOnDropConn {
    cmd: smpsc::Sender<Cmd>,
    handle: ConnectionHandle,
    armed: AtomicBool,
}

impl Drop for AbortOnDropConn {
    fn drop(&mut self) {
        if self.armed.load(Ordering::Relaxed) {
            let _ = self.cmd.send(Cmd::Abort {
                handle: self.handle,
            });
        }
    }
}

impl Drop for TcpWriter {
    fn drop(&mut self) {
        self.close();
    }
}

impl Drop for TcpReader {
    fn drop(&mut self) {
        self.from_net.close();
    }
}

/// Spawn the netstack: a feeder task pumping tunnel→actor, and the smoltcp actor
/// thread. Returns a [`NetHandle`] for the async world.
pub fn spawn(io: TunnelIo, assigned_v4: Ipv4Addr, assigned_v6: Option<Ipv6Addr>) -> NetHandle {
    spawn_with(io, assigned_v4, assigned_v6, ResolvePreference::Ipv4Only)
}

/// 与 [`spawn`] 相同，但按 `preference` 解析域名。
pub fn spawn_with(
    io: TunnelIo,
    assigned_v4: Ipv4Addr,
    assigned_v6: Option<Ipv6Addr>,
    preference: ResolvePreference,
) -> NetHandle {
    let (handle, _thread) = spawn_inner(io, assigned_v4, assigned_v6, preference);
    handle
}

fn spawn_inner(
    io: TunnelIo,
    assigned_v4: Ipv4Addr,
    assigned_v6: Option<Ipv6Addr>,
    preference: ResolvePreference,
) -> (NetHandle, std::thread::JoinHandle<()>) {
    let mtu = io.max_ip_packet().clamp(576, 1280);
    let (cmd_tx, cmd_rx) = smpsc::channel::<Cmd>();
    let inbound_queued = Arc::new(AtomicUsize::new(0));

    // Feeder: read IP packets off the tunnel and hand them to the actor.
    let feeder_io = io.clone();
    let feeder_cmd = cmd_tx.clone();
    let feeder_queued = Arc::clone(&inbound_queued);
    let feeder = AbortOnDrop(tokio::spawn(async move {
        while let Ok(pkt) = feeder_io.recv_ip().await {
            if feeder_queued
                .fetch_update(Ordering::AcqRel, Ordering::Acquire, |count| {
                    (count < MAX_INBOUND_QUEUE).then_some(count + 1)
                })
                .is_err()
            {
                continue;
            }
            if feeder_cmd.send(Cmd::Inbound(pkt)).is_err() {
                feeder_queued.fetch_sub(1, Ordering::AcqRel);
                break;
            }
        }
        let _ = feeder_cmd.send(Cmd::TunnelClosed);
    }));

    let thread = std::thread::Builder::new()
        .name("warp-netstack".into())
        .spawn(move || {
            Actor::with_inbound_counter(
                io,
                mtu,
                assigned_v4,
                assigned_v6,
                preference,
                inbound_queued,
            )
            .run(cmd_rx)
        })
        .expect("spawn netstack thread");
    let lifecycle = Arc::new(NetShutdown {
        cmd: cmd_tx.clone(),
        feeder,
    });
    (
        NetHandle {
            cmd: cmd_tx,
            lifecycle: Some(lifecycle),
        },
        thread,
    )
}

/// 测试用：启动带线程句柄返回的 netstack，用于验证释放后 OS 线程确实退出。
#[cfg(test)]
pub(crate) fn spawn_for_test(
    io: TunnelIo,
    assigned_v4: Ipv4Addr,
) -> (NetHandle, std::thread::JoinHandle<()>) {
    spawn_inner(io, assigned_v4, None, ResolvePreference::Ipv4Only)
}

// ---- the smoltcp actor -----------------------------------------------------

struct Conn {
    socket_handle: SocketHandle,
    local_port: u16,
    from_net: Option<tmpsc::Sender<Vec<u8>>>,
    rx_stalled: Arc<AtomicBool>,
    tx_budget: Arc<Semaphore>,
    borrowed_permits: usize,
    out_buf: VecDeque<u8>,
    connect_reply: Option<oneshot::Sender<Result<ConnectionHandle, String>>>,
    /// 异步侧已确认接管该 socket；未确认时 from_net 关闭说明请求被取消。
    handed_off: bool,
    closing: bool,
    /// 本端读写都已结束的时刻，用于兜底回收长期卡在 FinWait/零窗口的死连接。
    closed_at: Option<StdInstant>,
}

impl Drop for Conn {
    fn drop(&mut self) {
        // 关闭上行信号量，立刻唤醒所有等待背压许可的写端避免挂死。
        self.tx_budget.close();
    }
}

struct PendingDns {
    reply: oneshot::Sender<Result<IpAddr, String>>,
    preference: ResolvePreference,
    v4: QuerySlot,
    v6: QuerySlot,
}

enum QuerySlot {
    Skip,
    Pending(dns::QueryHandle),
    Ready(Vec<IpAddr>),
    Failed,
}

impl QuerySlot {
    fn pending(&self) -> bool {
        matches!(self, Self::Pending(_))
    }
}

struct Actor {
    io: TunnelIo,
    device: TunDevice,
    iface: Interface,
    sockets: SocketSet<'static>,
    start: StdInstant,
    next_port: u16,
    next_connection_id: u64,
    conns: HashMap<ConnectionHandle, Conn>,
    used_ports: HashSet<u16>,
    scratch_handles: Vec<ConnectionHandle>,
    dns_handle: SocketHandle,
    dns_pending: Vec<PendingDns>,
    preference: ResolvePreference,
    ipv6_enabled: bool,
    inbound_queued: Arc<AtomicUsize>,
    tunnel_closed: bool,
}

impl Actor {
    #[cfg(test)]
    fn new(
        io: TunnelIo,
        mtu: usize,
        v4: Ipv4Addr,
        v6: Option<Ipv6Addr>,
        preference: ResolvePreference,
    ) -> Self {
        Self::with_inbound_counter(io, mtu, v4, v6, preference, Arc::new(AtomicUsize::new(0)))
    }

    fn with_inbound_counter(
        io: TunnelIo,
        mtu: usize,
        v4: Ipv4Addr,
        v6: Option<Ipv6Addr>,
        preference: ResolvePreference,
        inbound_queued: Arc<AtomicUsize>,
    ) -> Self {
        let mut device = TunDevice {
            rx: VecDeque::new(),
            tx: Vec::new(),
            mtu,
        };
        let start = StdInstant::now();
        let mut iface = Interface::new(
            Config::new(HardwareAddress::Ip),
            &mut device,
            Instant::from_millis(0),
        );
        iface.update_ip_addrs(|addrs| {
            let _ = addrs.push(IpCidr::new(IpAddress::Ipv4(v4), 32));
            if let Some(v6) = v6 {
                let _ = addrs.push(IpCidr::new(IpAddress::Ipv6(v6), 128));
            }
        });
        // Point-to-point tunnel: no L2, so the gateway value is only used for
        // route matching. Any address works; send everything off-link to the tun.
        let _ = iface
            .routes_mut()
            .add_default_ipv4_route(Ipv4Addr::new(172, 16, 0, 1));
        if v6.is_some() {
            let _ = iface
                .routes_mut()
                .add_default_ipv6_route(Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 1));
        }

        let mut sockets = SocketSet::new(Vec::new());
        let servers = [IpAddress::Ipv4(Ipv4Addr::new(1, 1, 1, 1))];
        let dns_handle = sockets.add(dns::Socket::new(&servers, Vec::new()));

        Actor {
            io,
            device,
            iface,
            sockets,
            start,
            next_port: 49152,
            next_connection_id: 0,
            conns: HashMap::new(),
            used_ports: HashSet::new(),
            scratch_handles: Vec::new(),
            dns_handle,
            dns_pending: Vec::new(),
            preference,
            ipv6_enabled: v6.is_some(),
            inbound_queued,
            tunnel_closed: false,
        }
    }

    fn now(&self) -> Instant {
        Instant::from_millis(self.start.elapsed().as_millis() as i64)
    }

    fn next_ephemeral_port(&mut self) -> Option<u16> {
        const PORT_START: u16 = 49152;
        const PORT_COUNT: usize = (u16::MAX as usize) - (PORT_START as usize) + 1;
        for _ in 0..PORT_COUNT {
            let port = self.next_port;
            self.next_port = if self.next_port == u16::MAX {
                PORT_START
            } else {
                self.next_port + 1
            };
            if !self.used_ports.contains(&port) {
                return Some(port);
            }
        }
        None
    }

    fn flush_tx(&mut self) {
        for pkt in self.device.tx.drain(..) {
            let _ = self.io.send_ip(&pkt);
        }
    }

    fn run(mut self, cmd_rx: smpsc::Receiver<Cmd>) {
        loop {
            let mut did_progress = false;
            loop {
                let now = self.now();
                let polled =
                    self.iface.poll(now, &mut self.device, &mut self.sockets) != PollResult::None;
                self.flush_tx();

                let serviced = self.service_sockets();
                let dns_done = self.service_dns();
                if polled || serviced || dns_done {
                    did_progress = true;
                }
                // service_sockets / service_dns 产生新发包、窗口打开或连接关闭时立即补 poll，
                // 消除每次写入被迫休眠 1ms 的人为延迟。
                if !serviced && !dns_done {
                    break;
                }
            }

            let now = self.now();
            let raw_delay = self
                .iface
                .poll_delay(now, &self.sockets)
                .map(|d| Duration::from_micros(d.total_micros()));

            let delay = match raw_delay {
                Some(d) if d.is_zero() && did_progress => {
                    while let Ok(cmd) = cmd_rx.try_recv() {
                        if self.handle_cmd(cmd) {
                            return;
                        }
                    }
                    continue;
                }
                Some(d) => d.clamp(Duration::from_millis(1), Duration::from_millis(200)),
                None => Duration::from_millis(200),
            };

            match cmd_rx.recv_timeout(delay) {
                Ok(cmd) => {
                    if self.handle_cmd(cmd) {
                        return;
                    }
                    // Drain any other queued commands before re-polling.
                    while let Ok(cmd) = cmd_rx.try_recv() {
                        if self.handle_cmd(cmd) {
                            return;
                        }
                    }
                }
                Err(smpsc::RecvTimeoutError::Timeout) => {}
                Err(smpsc::RecvTimeoutError::Disconnected) => break,
            }
        }
    }

    /// 返回 true 表示收到 Shutdown，调用方应立刻退出 actor 循环。
    fn handle_cmd(&mut self, cmd: Cmd) -> bool {
        match cmd {
            Cmd::Inbound(pkt) => {
                self.inbound_queued
                    .fetch_update(Ordering::AcqRel, Ordering::Acquire, |n| n.checked_sub(1))
                    .ok();
                self.device.rx.push_back(pkt);
            }
            Cmd::Connect {
                remote,
                from_net,
                rx_stalled,
                tx_budget,
                reply,
            } => self.handle_connect(remote, from_net, rx_stalled, tx_budget, reply),
            Cmd::Send {
                handle,
                data,
                permits,
            } => {
                if let Some(conn) = self.conns.get_mut(&handle) {
                    conn.out_buf.extend(data);
                    conn.borrowed_permits = conn.borrowed_permits.saturating_add(permits);
                }
            }
            Cmd::Close { handle } => {
                if let Some(conn) = self.conns.get_mut(&handle) {
                    conn.closing = true;
                }
            }
            Cmd::Abort { handle } => {
                if let Some(conn) = self.conns.remove(&handle) {
                    self.used_ports.remove(&conn.local_port);
                    self.sockets
                        .get_mut::<tcp::Socket>(conn.socket_handle)
                        .abort();
                    self.sockets.remove(conn.socket_handle);
                    drop(conn);
                }
            }
            Cmd::Handoff { handle } => {
                if let Some(conn) = self.conns.get_mut(&handle) {
                    conn.handed_off = true;
                }
            }
            Cmd::Resolve { name, reply } => self.handle_resolve(name, reply),
            Cmd::Wake => {}
            Cmd::TunnelClosed => {
                self.tunnel_closed = true;
                let handles: Vec<ConnectionHandle> = self.conns.keys().copied().collect();
                for handle in handles {
                    if let Some(mut conn) = self.conns.remove(&handle) {
                        if let Some(reply) = conn.connect_reply.take() {
                            let _ = reply.send(Err("tunnel closed".into()));
                        }
                        self.used_ports.remove(&conn.local_port);
                        self.sockets
                            .get_mut::<tcp::Socket>(conn.socket_handle)
                            .abort();
                        self.sockets.remove(conn.socket_handle);
                    }
                }
                for pending in self.dns_pending.drain(..) {
                    let _ = pending.reply.send(Err("tunnel closed".into()));
                }
            }
            Cmd::Shutdown => return true,
        }
        false
    }

    fn handle_connect(
        &mut self,
        remote: SocketAddr,
        from_net: tmpsc::Sender<Vec<u8>>,
        rx_stalled: Arc<AtomicBool>,
        tx_budget: Arc<Semaphore>,
        reply: oneshot::Sender<Result<ConnectionHandle, String>>,
    ) {
        if self.tunnel_closed {
            tx_budget.close();
            let _ = reply.send(Err("tunnel closed".into()));
            return;
        }
        let Some(connection_id) = self.next_connection_id.checked_add(1) else {
            tx_budget.close();
            let _ = reply.send(Err("connection ids exhausted".into()));
            return;
        };
        let Some(local_port) = self.next_ephemeral_port() else {
            tx_budget.close();
            let _ = reply.send(Err("ephemeral ports exhausted".into()));
            return;
        };
        self.next_connection_id = connection_id;
        let rx = tcp::SocketBuffer::new(vec![0u8; SOCK_RX_BUF]);
        let tx = tcp::SocketBuffer::new(vec![0u8; SOCK_TX_BUF]);
        let mut socket = tcp::Socket::new(rx, tx);
        socket.set_timeout(Some(TCP_SOCKET_TIMEOUT));
        socket.set_keep_alive(Some(TCP_KEEP_ALIVE));
        socket.set_nagle_enabled(false);
        socket.set_ack_delay(None);
        let handle = self.sockets.add(socket);
        let remote_ep = IpEndpoint::new(to_ip(remote.ip()), remote.port());
        let local_ep = IpListenEndpoint {
            addr: None,
            port: local_port,
        };

        let iface = &mut self.iface;
        let sock = self.sockets.get_mut::<tcp::Socket>(handle);
        match sock.connect(iface.context(), remote_ep, local_ep) {
            Ok(()) => {
                self.used_ports.insert(local_port);
                self.conns.insert(
                    ConnectionHandle(connection_id),
                    Conn {
                        socket_handle: handle,
                        local_port,
                        from_net: Some(from_net),
                        rx_stalled,
                        tx_budget,
                        borrowed_permits: 0,
                        out_buf: VecDeque::new(),
                        connect_reply: Some(reply),
                        handed_off: false,
                        closing: false,
                        closed_at: None,
                    },
                );
            }
            Err(e) => {
                self.sockets.remove(handle);
                tx_budget.close();
                let _ = reply.send(Err(format!("connect: {e}")));
            }
        }
    }

    fn handle_resolve(&mut self, name: String, reply: oneshot::Sender<Result<IpAddr, String>>) {
        if self.tunnel_closed {
            let _ = reply.send(Err("tunnel closed".into()));
            return;
        }
        let plan = plan_resolve(&name, self.preference, self.ipv6_enabled);
        let ResolvePlan::Lookup {
            preference,
            query_v4,
            query_v6,
        } = plan
        else {
            let ResolvePlan::Ready(result) = plan else {
                unreachable!();
            };
            let _ = reply.send(result);
            return;
        };
        let v4 = if query_v4 {
            self.start_dns(&name, DnsQueryType::A)
        } else {
            QuerySlot::Skip
        };
        let v6 = if query_v6 {
            self.start_dns(&name, DnsQueryType::Aaaa)
        } else {
            QuerySlot::Skip
        };
        self.dns_pending.push(PendingDns {
            reply,
            preference,
            v4,
            v6,
        });
        self.finish_ready_dns();
    }

    fn start_dns(&mut self, name: &str, kind: DnsQueryType) -> QuerySlot {
        let dns_handle = self.dns_handle;
        let iface = &mut self.iface;
        let sock = self.sockets.get_mut::<dns::Socket>(dns_handle);
        match sock.start_query(iface.context(), name, kind) {
            Ok(query) => QuerySlot::Pending(query),
            Err(err) => {
                eprintln!("[netstack] DNS 查询没有发出: {err:?}");
                QuerySlot::Failed
            }
        }
    }

    fn finish_ready_dns(&mut self) -> bool {
        let mut finished = false;
        let mut index = 0;
        while index < self.dns_pending.len() {
            if self.dns_pending[index].v4.pending() || self.dns_pending[index].v6.pending() {
                index += 1;
                continue;
            }
            let pending = self.dns_pending.remove(index);
            finished = true;
            let v4 = match pending.v4 {
                QuerySlot::Ready(addrs) => addrs,
                _ => Vec::new(),
            };
            let v6 = match pending.v6 {
                QuerySlot::Ready(addrs) => addrs,
                _ => Vec::new(),
            };
            let _ = pending.reply.send(select_ip(pending.preference, &v4, &v6));
        }
        finished
    }

    fn service_sockets(&mut self) -> bool {
        let mut did_work = false;
        self.scratch_handles.clear();
        self.scratch_handles.extend(self.conns.keys().copied());
        let count = self.scratch_handles.len();
        for idx in 0..count {
            let handle = self.scratch_handles[idx];
            let mut remove = false;
            {
                let conn = self.conns.get_mut(&handle).expect("conn for handle");
                let sock = self.sockets.get_mut::<tcp::Socket>(conn.socket_handle);

                // 入口请求被取消且没有任何 TcpConn/TcpWriter 接管时直接 abort，
                // 避免半开 socket 和 conns 项留在 actor 里直到远端超时：
                // 1) connect() 还没收到 reply；
                // 2) reply 已发出，但异步侧尚未发 Handoff 确认接管。
                let from_net_closed = conn.from_net.as_ref().is_some_and(|tx| tx.is_closed());
                let orphaned = conn
                    .connect_reply
                    .as_ref()
                    .is_some_and(|reply| reply.is_closed())
                    || (conn.connect_reply.is_none() && !conn.handed_off && from_net_closed);
                if orphaned {
                    sock.abort();
                    remove = true;
                }

                if !remove {
                    // Resolve the pending connect once established or failed.
                    if conn.connect_reply.is_some() {
                        if matches!(
                            sock.state(),
                            tcp::State::Established | tcp::State::CloseWait
                        ) {
                            if conn.connect_reply.take().unwrap().send(Ok(handle)).is_err() {
                                // 接收端恰好在 send 时被丢弃，同样没有接管者。
                                sock.abort();
                                remove = true;
                            }
                        } else if !sock.is_active() {
                            let _ = conn
                                .connect_reply
                                .take()
                                .unwrap()
                                .send(Err("connection refused".into()));
                            remove = true;
                        }
                    }

                    // socks -> net
                    while sock.can_send() && !conn.out_buf.is_empty() {
                        let (head, _) = conn.out_buf.as_slices();
                        match sock.send_slice(head) {
                            Ok(0) => break,
                            Ok(n) => {
                                drop(conn.out_buf.drain(..n));
                                let give_back = n.min(conn.borrowed_permits);
                                conn.borrowed_permits -= give_back;
                                if give_back > 0 {
                                    conn.tx_budget.add_permits(give_back);
                                }
                                did_work = true;
                            }
                            Err(_) => break,
                        }
                    }
                    if conn.out_buf.is_empty() && conn.out_buf.capacity() > OUT_BUF_SHRINK_THRESHOLD
                    {
                        conn.out_buf = VecDeque::new();
                    }

                    // net -> socks (bounded by the channel to apply TCP backpressure)
                    if let Some(from_net) = &conn.from_net {
                        while sock.can_recv() {
                            match from_net.try_reserve() {
                                Ok(permit) => {
                                    let want = sock.recv_queue().clamp(1, RECV_CHUNK);
                                    let mut buf = vec![0u8; want];
                                    match sock.recv_slice(&mut buf) {
                                        Ok(0) => break,
                                        Ok(n) => {
                                            buf.truncate(n);
                                            permit.send(buf);
                                            did_work = true;
                                        }
                                        Err(_) => break,
                                    }
                                }
                                Err(tmpsc::error::TrySendError::Full(_)) => {
                                    conn.rx_stalled.store(true, Ordering::Release);
                                    break;
                                }
                                Err(tmpsc::error::TrySendError::Closed(())) => break,
                            }
                        }
                    }

                    // 对端已发送 FIN 且接收缓冲已排空时，立刻释放 from_net 向上游传递 EOF。
                    // 仅在异步侧 Handoff 完成后释放，避免交棒窗口误判为孤儿连接或掩盖取消检测。
                    if conn.handed_off
                        && conn.from_net.is_some()
                        && matches!(
                            sock.state(),
                            tcp::State::CloseWait
                                | tcp::State::Closing
                                | tcp::State::LastAck
                                | tcp::State::TimeWait
                                | tcp::State::Closed
                        )
                        && !sock.can_recv()
                    {
                        conn.from_net = None;
                        did_work = true;
                    }

                    if conn.closing && conn.out_buf.is_empty() && sock.may_send() {
                        sock.close();
                        did_work = true;
                    }

                    // 本端读写均已结束但对端迟迟不完成四次挥手时，超时强收避免 FinWait 永久泄漏。
                    let reader_closed = conn.from_net.as_ref().is_none_or(|tx| tx.is_closed());
                    if conn.closing && reader_closed {
                        let started = *conn.closed_at.get_or_insert_with(StdInstant::now);
                        if started.elapsed() >= TCP_CLOSING_TIMEOUT {
                            sock.abort();
                            remove = true;
                        }
                    }

                    if sock.state() == tcp::State::Closed {
                        remove = true;
                    }
                }
            }
            if remove {
                let conn = self.conns.remove(&handle).expect("conn for handle");
                self.used_ports.remove(&conn.local_port);
                self.sockets.remove(conn.socket_handle);
                did_work = true;
            }
        }
        did_work
    }

    fn service_dns(&mut self) -> bool {
        let dns_handle = self.dns_handle;
        for pending in &mut self.dns_pending {
            for slot in [&mut pending.v4, &mut pending.v6] {
                let QuerySlot::Pending(query) = slot else {
                    continue;
                };
                let sock = self.sockets.get_mut::<dns::Socket>(dns_handle);
                match sock.get_query_result(*query) {
                    Ok(addrs) => {
                        *slot = QuerySlot::Ready(addrs.into_iter().map(from_ip).collect());
                    }
                    Err(dns::GetQueryResultError::Pending) => {}
                    Err(dns::GetQueryResultError::Failed) => *slot = QuerySlot::Failed,
                }
            }
        }
        self.finish_ready_dns()
    }
}

fn to_ip(ip: IpAddr) -> IpAddress {
    match ip {
        IpAddr::V4(a) => IpAddress::Ipv4(a),
        IpAddr::V6(a) => IpAddress::Ipv6(a),
    }
}

fn from_ip(ip: IpAddress) -> IpAddr {
    match ip {
        IpAddress::Ipv4(a) => IpAddr::V4(a),
        IpAddress::Ipv6(a) => IpAddr::V6(a),
    }
}

// ---- channel-backed smoltcp device -----------------------------------------

struct TunDevice {
    rx: VecDeque<Vec<u8>>,
    tx: Vec<Vec<u8>>,
    mtu: usize,
}

impl Device for TunDevice {
    type RxToken<'a> = RxTok;
    type TxToken<'a> = TxTok<'a>;

    fn receive(&mut self, _t: Instant) -> Option<(Self::RxToken<'_>, Self::TxToken<'_>)> {
        let buf = self.rx.pop_front()?;
        Some((RxTok { buf }, TxTok { tx: &mut self.tx }))
    }

    fn transmit(&mut self, _t: Instant) -> Option<Self::TxToken<'_>> {
        Some(TxTok { tx: &mut self.tx })
    }

    fn capabilities(&self) -> DeviceCapabilities {
        let mut caps = DeviceCapabilities::default();
        caps.medium = Medium::Ip;
        caps.max_transmission_unit = self.mtu;
        caps
    }
}

struct RxTok {
    buf: Vec<u8>,
}

impl RxToken for RxTok {
    fn consume<R, F: FnOnce(&[u8]) -> R>(self, f: F) -> R {
        f(&self.buf)
    }
}

struct TxTok<'a> {
    tx: &'a mut Vec<Vec<u8>>,
}

impl TxToken for TxTok<'_> {
    fn consume<R, F: FnOnce(&mut [u8]) -> R>(self, len: usize, f: F) -> R {
        let mut buf = vec![0u8; len];
        let r = f(&mut buf);
        self.tx.push(buf);
        r
    }
}

#[cfg(test)]
mod resolve_tests {
    use super::*;

    fn v4() -> IpAddr {
        IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4))
    }

    fn v6() -> IpAddr {
        IpAddr::V6(Ipv6Addr::LOCALHOST)
    }

    #[test]
    fn parses_resolve_preference_aliases() {
        assert_eq!(
            ResolvePreference::parse("auto").unwrap(),
            ResolvePreference::Auto
        );
        assert_eq!(
            ResolvePreference::parse("ipv6").unwrap(),
            ResolvePreference::Ipv6Only
        );
        assert_eq!(
            ResolvePreference::parse("v6").unwrap(),
            ResolvePreference::Ipv6Only
        );
        assert_eq!(
            ResolvePreference::parse("ipv6-prefer").unwrap(),
            ResolvePreference::Ipv6Prefer
        );
        assert_eq!(
            ResolvePreference::parse("ipv4_only").unwrap(),
            ResolvePreference::Ipv4Only
        );
        assert!(ResolvePreference::parse("both").is_err());
    }

    #[test]
    fn select_ip_covers_each_preference() {
        let v4s = [v4()];
        let v6s = [v6()];
        assert_eq!(
            select_ip(ResolvePreference::Auto, &v4s, &v6s).unwrap(),
            v4()
        );
        assert_eq!(
            select_ip(ResolvePreference::Ipv4Prefer, &v4s, &v6s).unwrap(),
            v4()
        );
        assert_eq!(
            select_ip(ResolvePreference::Ipv6Prefer, &v4s, &v6s).unwrap(),
            v6()
        );
        assert_eq!(
            select_ip(ResolvePreference::Ipv4Only, &v4s, &v6s).unwrap(),
            v4()
        );
        assert_eq!(
            select_ip(ResolvePreference::Ipv6Only, &v4s, &v6s).unwrap(),
            v6()
        );
        // 只有另一族时，prefer/auto 会回退；only 则失败。
        assert_eq!(select_ip(ResolvePreference::Auto, &[], &v6s).unwrap(), v6());
        assert_eq!(
            select_ip(ResolvePreference::Ipv6Prefer, &v4s, &[]).unwrap(),
            v4()
        );
        assert!(select_ip(ResolvePreference::Ipv4Only, &[], &v6s).is_err());
        assert!(select_ip(ResolvePreference::Ipv6Only, &v4s, &[]).is_err());
        assert!(select_ip(ResolvePreference::Ipv6Prefer, &[], &[]).is_err());
    }

    #[test]
    fn literal_ipv6_follows_preference_and_tunnel_capability() {
        let ip = "2001:db8::1";
        assert_eq!(
            plan_resolve(ip, ResolvePreference::Ipv6Prefer, true),
            ResolvePlan::Ready(Ok(ip.parse().unwrap()))
        );
        assert_eq!(
            plan_resolve(ip, ResolvePreference::Auto, true),
            ResolvePlan::Ready(Ok(ip.parse().unwrap()))
        );
        assert!(matches!(
            plan_resolve(ip, ResolvePreference::Ipv4Only, true),
            ResolvePlan::Ready(Err(_))
        ));
        assert!(matches!(
            plan_resolve(ip, ResolvePreference::Ipv6Only, false),
            ResolvePlan::Ready(Err(_))
        ));
        assert_eq!(
            plan_resolve("1.2.3.4", ResolvePreference::Ipv6Only, true),
            ResolvePlan::Ready(Err("地址族与解析偏好不符".into()))
        );
    }

    #[test]
    fn hostname_query_plan_selects_aaaa_only_when_ipv6_is_usable() {
        assert_eq!(
            plan_resolve("ipv6.google.com", ResolvePreference::Ipv6Only, true),
            ResolvePlan::Lookup {
                preference: ResolvePreference::Ipv6Only,
                query_v4: false,
                query_v6: true,
            }
        );
        assert_eq!(
            plan_resolve("ipv4.google.com", ResolvePreference::Ipv4Only, true),
            ResolvePlan::Lookup {
                preference: ResolvePreference::Ipv4Only,
                query_v4: true,
                query_v6: false,
            }
        );
        assert_eq!(
            plan_resolve("example.com", ResolvePreference::Ipv6Prefer, true),
            ResolvePlan::Lookup {
                preference: ResolvePreference::Ipv6Prefer,
                query_v4: true,
                query_v6: true,
            }
        );
        // 隧道没有 IPv6 时不能假装去查 AAAA。
        assert_eq!(
            plan_resolve("example.com", ResolvePreference::Ipv6Prefer, false),
            ResolvePlan::Lookup {
                preference: ResolvePreference::Ipv4Only,
                query_v4: true,
                query_v6: false,
            }
        );
        assert_eq!(
            plan_resolve("example.com", ResolvePreference::Ipv6Only, false),
            ResolvePlan::Ready(Err("隧道没有 IPv6 地址".into()))
        );
    }
}

#[cfg(test)]
mod cancellation_tests {
    use super::*;
    use std::net::Ipv4Addr;
    use std::sync::mpsc as smpsc;
    use tokio::sync::{mpsc as tmpsc, oneshot};

    fn connection_handle() -> ConnectionHandle {
        ConnectionHandle(1)
    }

    fn tcp_conn(cmd: &smpsc::Sender<Cmd>, handle: ConnectionHandle) -> TcpConn {
        let (_from_net_tx, from_net_rx) = tmpsc::channel(1);
        TcpConn {
            handle,
            cmd: cmd.clone(),
            from_net: from_net_rx,
            rx_stalled: Arc::new(AtomicBool::new(false)),
            tx_budget: Arc::new(Semaphore::new(TX_WINDOW_BYTES)),
            write_wait: None,
            read_buf: Vec::new(),
            read_pos: 0,
            abort_guard: AbortOnDropConn {
                cmd: cmd.clone(),
                handle,
                armed: AtomicBool::new(true),
            },
            lifecycle: None,
        }
    }

    #[test]
    fn dropping_unsplit_tcp_conn_aborts_actor_socket() {
        let (cmd, rx) = smpsc::channel();
        let handle = connection_handle();
        drop(tcp_conn(&cmd, handle));
        assert!(matches!(rx.try_recv(), Ok(Cmd::Abort { .. })));
    }

    struct ReusedSocket {
        actor: Actor,
        old_connection: TcpConn,
        queued: smpsc::Receiver<Cmd>,
        new_handle: ConnectionHandle,
        new_reader: tmpsc::Receiver<Vec<u8>>,
        new_reply: oneshot::Receiver<Result<ConnectionHandle, String>>,
    }

    fn reused_socket() -> ReusedSocket {
        let mut actor = Actor::new(
            TunnelIo::H2(crate::h2tunnel::dummy_h2_io()),
            1280,
            Ipv4Addr::new(172, 16, 0, 2),
            None,
            ResolvePreference::Auto,
        );
        let (cmd, queued) = smpsc::channel();
        let (old_from_net, old_reader) = tmpsc::channel(1);
        let (old_reply, _old_receiver) = oneshot::channel();
        actor.handle_cmd(Cmd::Connect {
            remote: "198.51.100.1:443".parse().unwrap(),
            from_net: old_from_net,
            rx_stalled: Arc::new(AtomicBool::new(false)),
            tx_budget: Arc::new(Semaphore::new(TX_WINDOW_BYTES)),
            reply: old_reply,
        });
        let old_handle = *actor.conns.keys().next().unwrap();
        actor.handle_cmd(Cmd::Handoff { handle: old_handle });
        assert!(actor
            .conns
            .get_mut(&old_handle)
            .unwrap()
            .connect_reply
            .take()
            .unwrap()
            .send(Ok(old_handle))
            .is_ok());
        let old_connection = TcpConn {
            handle: old_handle,
            cmd: cmd.clone(),
            from_net: old_reader,
            rx_stalled: Arc::new(AtomicBool::new(false)),
            tx_budget: Arc::new(Semaphore::new(TX_WINDOW_BYTES)),
            write_wait: None,
            read_buf: Vec::new(),
            read_pos: 0,
            abort_guard: AbortOnDropConn {
                cmd: cmd.clone(),
                handle: old_handle,
                armed: AtomicBool::new(true),
            },
            lifecycle: None,
        };
        let old_socket = actor.conns[&old_handle].socket_handle;
        actor.sockets.get_mut::<tcp::Socket>(old_socket).abort();
        actor.service_sockets();
        assert!(actor.conns.is_empty());

        let (new_from_net, new_reader) = tmpsc::channel(1);
        let (new_reply, new_receiver) = oneshot::channel();
        actor.handle_cmd(Cmd::Connect {
            remote: "198.51.100.2:443".parse().unwrap(),
            from_net: new_from_net,
            rx_stalled: Arc::new(AtomicBool::new(false)),
            tx_budget: Arc::new(Semaphore::new(TX_WINDOW_BYTES)),
            reply: new_reply,
        });
        let new_handle = *actor.conns.keys().next().unwrap();
        let new_socket = actor.conns[&new_handle].socket_handle;
        assert_eq!(old_socket, new_socket, "测试必须实际复用 socket 槽位");
        assert_ne!(old_handle, new_handle, "不同连接必须持有不同标识");
        ReusedSocket {
            actor,
            old_connection,
            queued,
            new_handle,
            new_reader,
            new_reply: new_receiver,
        }
    }

    #[test]
    fn dropping_old_tcp_conn_does_not_abort_reused_socket() {
        let mut reused = reused_socket();
        drop(reused.old_connection);
        reused.actor.handle_cmd(reused.queued.try_recv().unwrap());

        assert!(
            reused.actor.conns.contains_key(&reused.new_handle),
            "旧连接的 Drop 不应中断复用槽位的新连接"
        );
        let new_socket = reused.actor.conns[&reused.new_handle].socket_handle;
        assert!(reused
            .actor
            .sockets
            .get::<tcp::Socket>(new_socket)
            .is_active());
    }

    #[test]
    fn stale_split_connection_commands_do_not_affect_reused_socket() {
        let mut reused = reused_socket();
        let old_handle = reused.old_connection.handle;
        let old_abort = reused.old_connection.abort_handle();
        let (_old_reader, old_writer) = reused.old_connection.into_split();
        old_writer.send(b"stale data".to_vec());
        old_writer.close();
        drop(old_writer);
        old_abort.abort();
        reused.actor.handle_cmd(Cmd::Handoff { handle: old_handle });
        while let Ok(command) = reused.queued.try_recv() {
            reused.actor.handle_cmd(command);
        }

        let current = reused.actor.conns.get_mut(&reused.new_handle).unwrap();
        assert!(current.out_buf.is_empty(), "旧连接不得向新连接注入数据");
        assert!(!current.closing, "旧连接不得关闭新连接");
        assert!(!current.handed_off, "旧交接确认不得接管新连接");
        assert!(current
            .connect_reply
            .take()
            .unwrap()
            .send(Ok(reused.new_handle))
            .is_ok());
        drop(reused.new_reader);
        drop(reused.new_reply);
        reused.actor.service_sockets();
        assert!(
            reused.actor.conns.is_empty(),
            "旧交接确认不得阻止新连接取消后的清理"
        );
    }

    #[test]
    fn current_connection_commands_still_apply_after_socket_reuse() {
        let mut reused = reused_socket();
        drop(reused.old_connection);
        reused.actor.handle_cmd(reused.queued.try_recv().unwrap());
        reused.actor.handle_cmd(Cmd::Send {
            handle: reused.new_handle,
            data: b"current data".to_vec(),
            permits: 0,
        });
        reused.actor.handle_cmd(Cmd::Handoff {
            handle: reused.new_handle,
        });
        reused.actor.handle_cmd(Cmd::Close {
            handle: reused.new_handle,
        });
        let current = &reused.actor.conns[&reused.new_handle];
        assert_eq!(
            current.out_buf.iter().copied().collect::<Vec<_>>(),
            b"current data"
        );
        assert!(current.closing);
        assert!(current.handed_off);
        reused.actor.handle_cmd(Cmd::Abort {
            handle: reused.new_handle,
        });
        assert!(reused.actor.conns.is_empty());
        assert_eq!(reused.actor.sockets.iter().count(), 1);
    }

    #[test]
    fn exhausted_connection_ids_do_not_wrap_or_allocate_sockets() {
        let mut actor = Actor::new(
            TunnelIo::H2(crate::h2tunnel::dummy_h2_io()),
            1280,
            Ipv4Addr::new(172, 16, 0, 2),
            None,
            ResolvePreference::Auto,
        );
        actor.next_connection_id = u64::MAX;
        let (from_net, _reader) = tmpsc::channel(1);
        let (reply, mut receiver) = oneshot::channel();
        actor.handle_cmd(Cmd::Connect {
            remote: "198.51.100.1:443".parse().unwrap(),
            from_net,
            rx_stalled: Arc::new(AtomicBool::new(false)),
            tx_budget: Arc::new(Semaphore::new(TX_WINDOW_BYTES)),
            reply,
        });
        assert_eq!(
            receiver.try_recv().unwrap(),
            Err("connection ids exhausted".into())
        );
        assert_eq!(actor.next_connection_id, u64::MAX);
        assert!(actor.conns.is_empty());
        assert_eq!(actor.sockets.iter().count(), 1);
    }

    #[test]
    fn split_tcp_conn_leaves_close_to_writer() {
        let (cmd, rx) = smpsc::channel();
        let handle = connection_handle();
        let (reader, writer) = tcp_conn(&cmd, handle).into_split();
        drop((reader, writer));
        let mut saw_abort = false;
        while let Ok(queued) = rx.try_recv() {
            if matches!(queued, Cmd::Abort { .. }) {
                saw_abort = true;
            }
        }
        assert!(!saw_abort, "into_split 之后不应再发 Abort");
    }

    #[test]
    fn explicit_close_disarms_abort_guard() {
        let (cmd, rx) = smpsc::channel();
        let handle = connection_handle();
        let conn = tcp_conn(&cmd, handle);
        conn.close();
        drop(conn);
        let mut saw_abort = false;
        while let Ok(queued) = rx.try_recv() {
            if matches!(queued, Cmd::Abort { .. }) {
                saw_abort = true;
            }
        }
        assert!(!saw_abort, "优雅关闭后不应再发 Abort");
    }

    #[test]
    fn handed_off_connection_is_not_treated_as_orphan() {
        let mut actor = Actor::new(
            TunnelIo::H2(crate::h2tunnel::dummy_h2_io()),
            1280,
            Ipv4Addr::new(172, 16, 0, 2),
            None,
            ResolvePreference::Auto,
        );
        let (from_net, from_net_rx) = tmpsc::channel(1);
        let (reply, rx) = oneshot::channel();
        actor.handle_cmd(Cmd::Connect {
            remote: "198.51.100.1:443".parse().unwrap(),
            from_net,
            rx_stalled: Arc::new(AtomicBool::new(false)),
            tx_budget: Arc::new(Semaphore::new(TX_WINDOW_BYTES)),
            reply,
        });
        let handle = *actor.conns.keys().next().unwrap();
        actor.handle_cmd(Cmd::Handoff { handle });
        let sent = actor
            .conns
            .get_mut(&handle)
            .unwrap()
            .connect_reply
            .take()
            .unwrap();
        assert!(sent.send(Ok(handle)).is_ok());
        drop(rx);
        drop(from_net_rx);
        actor.service_sockets();
        assert_eq!(actor.conns.len(), 1, "已接管的连接不能被误判为孤儿");
    }

    #[test]
    fn connect_reply_sent_but_handoff_cancelled_is_cleaned_up() {
        let mut actor = Actor::new(
            TunnelIo::H2(crate::h2tunnel::dummy_h2_io()),
            1280,
            Ipv4Addr::new(172, 16, 0, 2),
            None,
            ResolvePreference::Auto,
        );
        let (from_net, from_net_rx) = tmpsc::channel(1);
        let (reply, rx) = oneshot::channel();
        actor.handle_cmd(Cmd::Connect {
            remote: "198.51.100.1:443".parse().unwrap(),
            from_net,
            rx_stalled: Arc::new(AtomicBool::new(false)),
            tx_budget: Arc::new(Semaphore::new(TX_WINDOW_BYTES)),
            reply,
        });
        let handle = *actor.conns.keys().next().unwrap();
        let sent = actor
            .conns
            .get_mut(&handle)
            .unwrap()
            .connect_reply
            .take()
            .unwrap();
        // actor 已发出 Ok，但异步侧在发 Handoff 前被取消。
        assert!(sent.send(Ok(handle)).is_ok());
        drop(rx);
        drop(from_net_rx);
        actor.service_sockets();
        assert!(actor.conns.is_empty(), "交棒窗口被取消的连接必须被清理");
    }

    #[test]
    fn cancelled_pending_connect_is_aborted_and_removed() {
        let mut actor = Actor::new(
            TunnelIo::H2(crate::h2tunnel::dummy_h2_io()),
            1280,
            Ipv4Addr::new(172, 16, 0, 2),
            None,
            ResolvePreference::Auto,
        );
        let (from_net, _from_net_rx) = tmpsc::channel(1);
        let (reply, rx) = oneshot::channel();
        actor.handle_cmd(Cmd::Connect {
            remote: "198.51.100.1:443".parse().unwrap(),
            from_net,
            rx_stalled: Arc::new(AtomicBool::new(false)),
            tx_budget: Arc::new(Semaphore::new(TX_WINDOW_BYTES)),
            reply,
        });
        assert_eq!(actor.conns.len(), 1);

        // 模拟入口请求在 connect() 返回前被排空超时取消。
        drop(rx);
        actor.service_sockets();
        assert!(actor.conns.is_empty(), "取消的半开连接必须被清理");
    }

    struct LoopbackPair {
        actor: Actor,
        handle: ConnectionHandle,
        from_net_rx: tmpsc::Receiver<Vec<u8>>,
        tx_budget: Arc<Semaphore>,
        peer_dev: TunDevice,
        peer_iface: Interface,
        peer_sockets: SocketSet<'static>,
        peer_handle: SocketHandle,
    }

    /// 用对端 smoltcp 协议栈在内存中完成真实 TCP 三次握手，返回建立好的连接标识与对端对象。
    fn establish_loopback_pair() -> LoopbackPair {
        let client_ip = Ipv4Addr::new(172, 16, 0, 2);
        let server_ip = Ipv4Addr::new(198, 51, 100, 10);
        let mut actor = Actor::new(
            TunnelIo::H2(crate::h2tunnel::dummy_h2_io()),
            1280,
            client_ip,
            None,
            ResolvePreference::Ipv4Only,
        );
        let mut peer_dev = TunDevice {
            rx: VecDeque::new(),
            tx: Vec::new(),
            mtu: 1280,
        };
        let mut peer_iface = Interface::new(
            Config::new(HardwareAddress::Ip),
            &mut peer_dev,
            Instant::from_millis(0),
        );
        peer_iface.update_ip_addrs(|addrs| {
            let _ = addrs.push(IpCidr::new(IpAddress::Ipv4(server_ip), 32));
        });
        let _ = peer_iface
            .routes_mut()
            .add_default_ipv4_route(Ipv4Addr::new(198, 51, 100, 1));
        let mut peer_sockets = SocketSet::new(Vec::new());
        let mut peer_sock = tcp::Socket::new(
            tcp::SocketBuffer::new(vec![0u8; 256 * 1024]),
            tcp::SocketBuffer::new(vec![0u8; 256 * 1024]),
        );
        peer_sock.listen(443).unwrap();
        let peer_handle = peer_sockets.add(peer_sock);

        let (from_net_tx, from_net_rx) = tmpsc::channel(CHAN_DEPTH);
        let rx_stalled = Arc::new(AtomicBool::new(false));
        let tx_budget = Arc::new(Semaphore::new(TX_WINDOW_BYTES));
        let (reply_tx, mut reply_rx) = oneshot::channel();
        actor.handle_cmd(Cmd::Connect {
            remote: SocketAddr::new(IpAddr::V4(server_ip), 443),
            from_net: from_net_tx,
            rx_stalled: Arc::clone(&rx_stalled),
            tx_budget: Arc::clone(&tx_budget),
            reply: reply_tx,
        });

        pump_pair(
            &mut actor,
            &mut peer_dev,
            &mut peer_iface,
            &mut peer_sockets,
            10,
        );
        let handle = reply_rx.try_recv().unwrap().unwrap();
        actor.handle_cmd(Cmd::Handoff { handle });
        LoopbackPair {
            actor,
            handle,
            from_net_rx,
            tx_budget,
            peer_dev,
            peer_iface,
            peer_sockets,
            peer_handle,
        }
    }

    fn pump_pair(
        actor: &mut Actor,
        peer_dev: &mut TunDevice,
        peer_iface: &mut Interface,
        peer_sockets: &mut SocketSet<'static>,
        rounds: usize,
    ) {
        for step in 0..rounds {
            let ts = Instant::from_millis((step as i64) * 5);
            actor.iface.poll(ts, &mut actor.device, &mut actor.sockets);
            for pkt in actor.device.tx.drain(..) {
                peer_dev.rx.push_back(pkt);
            }
            actor.service_sockets();

            peer_iface.poll(ts, peer_dev, peer_sockets);
            for pkt in peer_dev.tx.drain(..) {
                actor.device.rx.push_back(pkt);
            }
        }
    }

    #[test]
    fn tcp_socket_configures_timeout_keepalive_and_large_buffers() {
        let pair = establish_loopback_pair();
        let sock_handle = pair.actor.conns[&pair.handle].socket_handle;
        let sock = pair.actor.sockets.get::<tcp::Socket>(sock_handle);
        assert_eq!(sock.timeout(), Some(TCP_SOCKET_TIMEOUT));
        assert_eq!(sock.keep_alive(), Some(TCP_KEEP_ALIVE));
        assert!(!sock.nagle_enabled());
        assert_eq!(sock.ack_delay(), None);
        assert_eq!(sock.recv_capacity(), SOCK_RX_BUF);
        assert_eq!(sock.send_capacity(), SOCK_TX_BUF);
    }

    #[tokio::test]
    async fn remote_fin_delivers_eof_in_close_wait_before_local_close() {
        let mut pair = establish_loopback_pair();

        let peer_sock = pair.peer_sockets.get_mut::<tcp::Socket>(pair.peer_handle);
        peer_sock.send_slice(b"hello-close-wait").unwrap();
        peer_sock.close();

        pump_pair(
            &mut pair.actor,
            &mut pair.peer_dev,
            &mut pair.peer_iface,
            &mut pair.peer_sockets,
            10,
        );

        let sock_handle = pair.actor.conns[&pair.handle].socket_handle;
        assert_eq!(
            pair.actor.sockets.get::<tcp::Socket>(sock_handle).state(),
            tcp::State::CloseWait
        );
        let payload = pair.from_net_rx.recv().await.expect("应先收到远端载荷");
        assert_eq!(payload, b"hello-close-wait");
        assert_eq!(
            pair.from_net_rx.recv().await,
            None,
            "进入 CloseWait 且接收缓冲排空后必须立刻传递 EOF，不能等本端关闭"
        );
    }

    #[test]
    fn closing_socket_stuck_in_fin_wait2_is_reaped_after_timeout() {
        let mut pair = establish_loopback_pair();

        drop(pair.from_net_rx);
        pair.actor.handle_cmd(Cmd::Close {
            handle: pair.handle,
        });
        pump_pair(
            &mut pair.actor,
            &mut pair.peer_dev,
            &mut pair.peer_iface,
            &mut pair.peer_sockets,
            10,
        );

        // 对端只 ACK 了 FIN 但迟迟不发自己的 FIN，导致本端卡在 FinWait2。
        let sock_handle = pair.actor.conns[&pair.handle].socket_handle;
        assert_eq!(
            pair.actor.sockets.get::<tcp::Socket>(sock_handle).state(),
            tcp::State::FinWait2
        );
        pair.actor.conns.get_mut(&pair.handle).unwrap().closed_at =
            Some(StdInstant::now() - TCP_CLOSING_TIMEOUT - Duration::from_secs(1));
        pair.actor.service_sockets();
        assert!(
            pair.actor.conns.is_empty(),
            "超时僵死的 FinWait2 socket 必须回收"
        );
        assert!(pair.actor.used_ports.is_empty(), "回收后必须释放临时端口");
        assert_eq!(pair.actor.sockets.iter().count(), 1, "只应保留 DNS socket");
    }

    #[test]
    fn out_buf_shrinks_after_draining_large_upload_burst() {
        let mut pair = establish_loopback_pair();

        let burst = vec![0xAB; 128 * 1024];
        let permit = pair.tx_budget.try_acquire_many(burst.len() as u32).unwrap();
        permit.forget();
        pair.actor.handle_cmd(Cmd::Send {
            handle: pair.handle,
            data: burst.clone(),
            permits: burst.len(),
        });
        assert!(pair.actor.conns[&pair.handle].out_buf.capacity() > OUT_BUF_SHRINK_THRESHOLD);

        let mut received = 0usize;
        for _ in 0..40 {
            pump_pair(
                &mut pair.actor,
                &mut pair.peer_dev,
                &mut pair.peer_iface,
                &mut pair.peer_sockets,
                4,
            );
            let peer_sock = pair.peer_sockets.get_mut::<tcp::Socket>(pair.peer_handle);
            let mut tmp = [0u8; 16 * 1024];
            while let Ok(n) = peer_sock.recv_slice(&mut tmp) {
                if n == 0 {
                    break;
                }
                received += n;
            }
            if received >= burst.len() {
                break;
            }
        }
        assert_eq!(received, burst.len());
        let conn = &pair.actor.conns[&pair.handle];
        assert!(conn.out_buf.is_empty());
        assert!(
            conn.out_buf.capacity() <= OUT_BUF_SHRINK_THRESHOLD,
            "排空后应收缩 out_buf 容量，当前={}",
            conn.out_buf.capacity()
        );
        assert_eq!(
            pair.tx_budget.available_permits(),
            TX_WINDOW_BYTES,
            "排空后上行背压额度必须全部归还"
        );
    }

    #[test]
    fn ephemeral_port_skips_in_use_ports() {
        let mut actor = Actor::new(
            TunnelIo::H2(crate::h2tunnel::dummy_h2_io()),
            1280,
            Ipv4Addr::new(172, 16, 0, 2),
            None,
            ResolvePreference::Ipv4Only,
        );
        actor.next_port = 49152;
        actor.used_ports.insert(49152);
        assert_eq!(actor.next_ephemeral_port(), Some(49153));
    }

    #[tokio::test]
    async fn dropping_net_handle_terminates_actor_thread_without_h2_cycle_leak() {
        // 保持 _out_rx 与 _in_tx 存活，模拟远端未主动断开的 HTTP/2 连接。
        let (io, _out_rx, _in_tx) = crate::h2tunnel::test_h2_channel();
        let (net, thread) = spawn_for_test(TunnelIo::H2(io), Ipv4Addr::new(172, 16, 0, 2));
        drop(net);
        let joined = tokio::time::timeout(
            Duration::from_secs(2),
            tokio::task::spawn_blocking(move || thread.join()),
        )
        .await
        .expect("释放 NetHandle 后 warp-netstack 线程必须在超时内退出");
        assert!(joined.unwrap().is_ok());
    }

    #[tokio::test]
    async fn dropping_h2_tunnel_aborts_tasks_and_unblocks_pending_ops() {
        let (io, out_rx, in_tx) = crate::h2tunnel::test_h2_channel();
        let (_dead_tx, dead_rx) = tokio::sync::watch::channel(false);
        // 模拟 h2 reader/writer 任务持有通道两端，靠 AbortOnDrop 在 Tunnel 释放时打破循环。
        let fake_pump = AbortOnDrop(tokio::spawn(async move {
            let _keep_in = in_tx;
            let _keep_out = out_rx;
            std::future::pending::<()>().await;
        }));
        let tunnel = crate::tunnel::Tunnel::from_parts(
            TunnelIo::H2(io),
            http::StatusCode::OK,
            Ipv4Addr::new(172, 16, 0, 2),
            None,
            dead_rx,
            vec![Box::new(fake_pump)],
        );
        let (net, thread) = spawn_for_test(tunnel.io(), Ipv4Addr::new(172, 16, 0, 2));

        drop(tunnel);
        // Tunnel 释放会 abort 后台任务并关闭 in_tx，feeder 立刻通知 Actor TunnelClosed。
        let err = tokio::time::timeout(
            Duration::from_secs(2),
            net.connect("198.51.100.1:443".parse().unwrap()),
        )
        .await
        .expect("隧道关闭后 connect 不得永久阻塞")
        .err()
        .expect("隧道关闭后 connect 必须失败");
        assert!(err.contains("tunnel closed"), "unexpected err: {err}");

        drop(net);
        let joined = tokio::time::timeout(
            Duration::from_secs(2),
            tokio::task::spawn_blocking(move || thread.join()),
        )
        .await
        .expect("释放后 OS 线程必须退出");
        assert!(joined.unwrap().is_ok());
    }

    #[tokio::test]
    async fn upload_backpressure_blocks_when_tx_window_exhausted_and_resumes() {
        let (cmd, _rx) = smpsc::channel();
        let conn = tcp_conn(&cmd, connection_handle());
        let budget = Arc::clone(&conn.tx_budget);
        let (_reader, writer) = conn.into_split();

        // 写满整个上行窗口应立即完成。
        writer
            .send_async(&vec![1u8; TX_WINDOW_BYTES])
            .await
            .unwrap();
        assert_eq!(budget.available_permits(), 0);

        // 窗口已满时继续写入必须被背压阻塞，不能继续无限塞进通道。
        let blocked = tokio::spawn(async move { writer.send_async(&[2u8; 4096]).await });
        tokio::time::sleep(Duration::from_millis(30)).await;
        assert!(!blocked.is_finished(), "上行窗口耗尽时必须阻塞背压");

        // 模拟 Actor 消费 out_buf 后归还许可，写端立刻恢复完成。
        budget.add_permits(4096);
        let res = tokio::time::timeout(Duration::from_secs(1), blocked)
            .await
            .expect("归还许可后写端应立即恢复")
            .unwrap();
        assert!(res.is_ok());
    }

    #[tokio::test]
    async fn rx_stalled_reader_sends_wake_when_consuming() {
        let (cmd_tx, cmd_rx) = smpsc::channel();
        let (from_net_tx, from_net_rx) = tmpsc::channel(2);
        let stalled = Arc::new(AtomicBool::new(true));
        let mut reader = TcpReader {
            from_net: from_net_rx,
            cmd: cmd_tx,
            rx_stalled: Arc::clone(&stalled),
            _lifecycle: None,
        };
        from_net_tx.send(b"chunk".to_vec()).await.unwrap();
        assert_eq!(reader.recv().await.as_deref(), Some(b"chunk".as_slice()));
        assert!(!stalled.load(Ordering::Acquire));
        assert!(matches!(cmd_rx.try_recv(), Ok(Cmd::Wake)));
    }

    #[test]
    fn early_remote_fin_before_handoff_does_not_abort_connection() {
        let client_ip = Ipv4Addr::new(172, 16, 0, 2);
        let server_ip = Ipv4Addr::new(198, 51, 100, 10);
        let mut actor = Actor::new(
            TunnelIo::H2(crate::h2tunnel::dummy_h2_io()),
            1280,
            client_ip,
            None,
            ResolvePreference::Ipv4Only,
        );
        let mut peer_dev = TunDevice {
            rx: VecDeque::new(),
            tx: Vec::new(),
            mtu: 1280,
        };
        let mut peer_iface = Interface::new(
            Config::new(HardwareAddress::Ip),
            &mut peer_dev,
            Instant::from_millis(0),
        );
        peer_iface.update_ip_addrs(|addrs| {
            let _ = addrs.push(IpCidr::new(IpAddress::Ipv4(server_ip), 32));
        });
        let _ = peer_iface
            .routes_mut()
            .add_default_ipv4_route(Ipv4Addr::new(198, 51, 100, 1));
        let mut peer_sockets = SocketSet::new(Vec::new());
        let mut peer_sock = tcp::Socket::new(
            tcp::SocketBuffer::new(vec![0u8; 64 * 1024]),
            tcp::SocketBuffer::new(vec![0u8; 64 * 1024]),
        );
        peer_sock.listen(443).unwrap();
        let peer_handle = peer_sockets.add(peer_sock);

        let (from_net_tx, mut from_net_rx) = tmpsc::channel(CHAN_DEPTH);
        let (reply_tx, mut reply_rx) = oneshot::channel();
        actor.handle_cmd(Cmd::Connect {
            remote: SocketAddr::new(IpAddr::V4(server_ip), 443),
            from_net: from_net_tx,
            rx_stalled: Arc::new(AtomicBool::new(false)),
            tx_budget: Arc::new(Semaphore::new(TX_WINDOW_BYTES)),
            reply: reply_tx,
        });

        pump_pair(
            &mut actor,
            &mut peer_dev,
            &mut peer_iface,
            &mut peer_sockets,
            10,
        );
        let handle = reply_rx.try_recv().unwrap().unwrap();

        // 尚未发送 Cmd::Handoff 时，对端立即主动 FIN 进入 CloseWait。
        peer_sockets.get_mut::<tcp::Socket>(peer_handle).close();
        pump_pair(
            &mut actor,
            &mut peer_dev,
            &mut peer_iface,
            &mut peer_sockets,
            10,
        );
        assert!(
            actor.conns.contains_key(&handle),
            "交棒前对端 FIN 不得误杀连接"
        );

        // 交棒完成后立刻向下游传递 EOF。
        actor.handle_cmd(Cmd::Handoff { handle });
        actor.service_sockets();
        assert!(actor.conns.contains_key(&handle));
        assert_eq!(
            from_net_rx.try_recv(),
            Err(tmpsc::error::TryRecvError::Disconnected)
        );
    }
}
