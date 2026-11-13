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

use std::collections::{HashMap, VecDeque};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc as smpsc;
use std::task::{Context, Poll};
use std::time::{Duration, Instant as StdInstant};

use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

use smoltcp::iface::{Config, Interface, SocketHandle, SocketSet};
use smoltcp::phy::{Device, DeviceCapabilities, Medium, RxToken, TxToken};
use smoltcp::socket::{dns, tcp};
use smoltcp::time::Instant;
use smoltcp::wire::{
    DnsQueryType, HardwareAddress, IpAddress, IpCidr, IpEndpoint, IpListenEndpoint,
};
use tokio::sync::{mpsc as tmpsc, oneshot};

use crate::tunnel::TunnelIo;

const SOCK_BUF: usize = 64 * 1024;
const RECV_CHUNK: usize = 8 * 1024;
const CHAN_DEPTH: usize = 64;

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
        reply: oneshot::Sender<Result<ConnectionHandle, String>>,
    },
    Send {
        handle: ConnectionHandle,
        data: Vec<u8>,
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
}

/// A cloneable async handle to the netstack.
#[derive(Clone)]
pub struct NetHandle {
    cmd: smpsc::Sender<Cmd>,
}

/// 测试用：保留命令接收端但不启动 actor，让 resolve/connect 永远等不到回复。
#[cfg(test)]
pub(crate) struct PendingNetGuard {
    _cmd: smpsc::Receiver<Cmd>,
}

#[cfg(test)]
pub(crate) fn pending_test_handle() -> (NetHandle, PendingNetGuard) {
    let (cmd, rx) = smpsc::channel();
    (NetHandle { cmd }, PendingNetGuard { _cmd: rx })
}

impl NetHandle {
    #[cfg(test)]
    pub(crate) fn test_handle() -> Self {
        let (cmd, _receiver) = smpsc::channel();
        Self { cmd }
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
        let (reply, rx) = oneshot::channel();
        self.cmd
            .send(Cmd::Connect {
                remote,
                from_net: from_net_tx,
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
            read_buf: Vec::new(),
            read_pos: 0,
            abort_guard: AbortOnDrop {
                cmd: self.cmd.clone(),
                handle,
                armed: AtomicBool::new(true),
            },
        })
    }
}

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
        _cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        match self.cmd.send(Cmd::Send {
            handle: self.handle,
            data: buf.to_vec(),
        }) {
            Ok(()) => Poll::Ready(Ok(buf.len())),
            Err(_) => Poll::Ready(Err(std::io::ErrorKind::BrokenPipe.into())),
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
    read_buf: Vec<u8>,
    read_pos: usize,
    /// 若 TcpConn 在 into_split 之前被丢弃（例如排空超时取消请求），
    /// 没有 TcpWriter/TcpReader 会发 Close，必须直接 abort 清理 actor 里的 socket。
    abort_guard: AbortOnDrop,
}

impl TcpConn {
    /// Receive the next chunk of bytes from the remote, or `None` at EOF.
    pub async fn recv(&mut self) -> Option<Vec<u8>> {
        self.from_net.recv().await
    }

    /// Queue bytes to send to the remote.
    pub fn send(&self, data: Vec<u8>) {
        let _ = self.cmd.send(Cmd::Send {
            handle: self.handle,
            data,
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
        }
    }

    /// Split into independent read/write halves for concurrent relaying.
    pub fn into_split(self) -> (TcpReader, TcpWriter) {
        // 之后由 TcpWriter::drop 发 Close，不再需要守卫强制 abort。
        self.abort_guard.armed.store(false, Ordering::Relaxed);
        (
            TcpReader {
                from_net: self.from_net,
            },
            TcpWriter {
                handle: self.handle,
                cmd: self.cmd,
            },
        )
    }
}

/// Read half of a [`TcpConn`].
pub struct TcpReader {
    from_net: tmpsc::Receiver<Vec<u8>>,
}

impl TcpReader {
    /// Receive the next chunk from the remote, or `None` at EOF.
    pub async fn recv(&mut self) -> Option<Vec<u8>> {
        self.from_net.recv().await
    }
}

/// Write half of a [`TcpConn`]. Closes the connection when dropped.
pub struct TcpWriter {
    handle: ConnectionHandle,
    cmd: smpsc::Sender<Cmd>,
}

impl TcpWriter {
    /// Queue bytes to send to the remote.
    pub fn send(&self, data: Vec<u8>) {
        let _ = self.cmd.send(Cmd::Send {
            handle: self.handle,
            data,
        });
    }

    /// Close the sending half once drained.
    pub fn close(&self) {
        let _ = self.cmd.send(Cmd::Close {
            handle: self.handle,
        });
    }
}

pub struct TcpAbort {
    cmd: smpsc::Sender<Cmd>,
    handle: ConnectionHandle,
}

impl TcpAbort {
    pub fn abort(&self) {
        let _ = self.cmd.send(Cmd::Abort {
            handle: self.handle,
        });
    }
}

struct AbortOnDrop {
    cmd: smpsc::Sender<Cmd>,
    handle: ConnectionHandle,
    armed: AtomicBool,
}

impl Drop for AbortOnDrop {
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
    let mtu = io.max_ip_packet().clamp(576, 1280);
    let (cmd_tx, cmd_rx) = smpsc::channel::<Cmd>();

    // Feeder: read IP packets off the tunnel and hand them to the actor.
    let feeder_io = io.clone();
    let feeder_cmd = cmd_tx.clone();
    tokio::spawn(async move {
        while let Ok(pkt) = feeder_io.recv_ip().await {
            if feeder_cmd.send(Cmd::Inbound(pkt)).is_err() {
                break;
            }
        }
    });

    std::thread::Builder::new()
        .name("warp-netstack".into())
        .spawn(move || Actor::new(io, mtu, assigned_v4, assigned_v6, preference).run(cmd_rx))
        .expect("spawn netstack thread");

    NetHandle { cmd: cmd_tx }
}

// ---- the smoltcp actor -----------------------------------------------------

struct Conn {
    socket_handle: SocketHandle,
    from_net: tmpsc::Sender<Vec<u8>>,
    out_buf: VecDeque<u8>,
    connect_reply: Option<oneshot::Sender<Result<ConnectionHandle, String>>>,
    /// 异步侧已确认接管该 socket；未确认时 from_net 关闭说明请求被取消。
    handed_off: bool,
    closing: bool,
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
    dns_handle: SocketHandle,
    dns_pending: Vec<PendingDns>,
    preference: ResolvePreference,
    ipv6_enabled: bool,
}

impl Actor {
    fn new(
        io: TunnelIo,
        mtu: usize,
        v4: Ipv4Addr,
        v6: Option<Ipv6Addr>,
        preference: ResolvePreference,
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
            dns_handle,
            dns_pending: Vec::new(),
            preference,
            ipv6_enabled: v6.is_some(),
        }
    }

    fn now(&self) -> Instant {
        Instant::from_millis(self.start.elapsed().as_millis() as i64)
    }

    fn next_ephemeral_port(&mut self) -> u16 {
        let p = self.next_port;
        self.next_port = if self.next_port == 65535 {
            49152
        } else {
            self.next_port + 1
        };
        p
    }

    fn run(mut self, cmd_rx: smpsc::Receiver<Cmd>) {
        loop {
            let now = self.now();
            self.iface.poll(now, &mut self.device, &mut self.sockets);

            // Egress: flush packets smoltcp produced to the tunnel.
            for pkt in self.device.tx.drain(..) {
                let _ = self.io.send_ip(&pkt);
            }

            self.service_sockets();
            self.service_dns();

            let delay = self
                .iface
                .poll_delay(now, &self.sockets)
                .map(|d| Duration::from_micros(d.total_micros()))
                .unwrap_or(Duration::from_millis(500))
                .clamp(Duration::from_millis(1), Duration::from_millis(500));

            match cmd_rx.recv_timeout(delay) {
                Ok(cmd) => {
                    self.handle_cmd(cmd);
                    // Drain any other queued commands before re-polling.
                    while let Ok(cmd) = cmd_rx.try_recv() {
                        self.handle_cmd(cmd);
                    }
                }
                Err(smpsc::RecvTimeoutError::Timeout) => {}
                Err(smpsc::RecvTimeoutError::Disconnected) => break,
            }
        }
    }

    fn handle_cmd(&mut self, cmd: Cmd) {
        match cmd {
            Cmd::Inbound(pkt) => self.device.rx.push_back(pkt),
            Cmd::Connect {
                remote,
                from_net,
                reply,
            } => self.handle_connect(remote, from_net, reply),
            Cmd::Send { handle, data } => {
                if let Some(conn) = self.conns.get_mut(&handle) {
                    conn.out_buf.extend(data);
                }
            }
            Cmd::Close { handle } => {
                if let Some(conn) = self.conns.get_mut(&handle) {
                    conn.closing = true;
                }
            }
            Cmd::Abort { handle } => {
                if let Some(conn) = self.conns.remove(&handle) {
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
        }
    }

    fn handle_connect(
        &mut self,
        remote: SocketAddr,
        from_net: tmpsc::Sender<Vec<u8>>,
        reply: oneshot::Sender<Result<ConnectionHandle, String>>,
    ) {
        let Some(connection_id) = self.next_connection_id.checked_add(1) else {
            let _ = reply.send(Err("connection ids exhausted".into()));
            return;
        };
        self.next_connection_id = connection_id;
        let rx = tcp::SocketBuffer::new(vec![0u8; SOCK_BUF]);
        let tx = tcp::SocketBuffer::new(vec![0u8; SOCK_BUF]);
        let handle = self.sockets.add(tcp::Socket::new(rx, tx));
        let local_port = self.next_ephemeral_port();
        let remote_ep = IpEndpoint::new(to_ip(remote.ip()), remote.port());
        let local_ep = IpListenEndpoint {
            addr: None,
            port: local_port,
        };

        let iface = &mut self.iface;
        let sock = self.sockets.get_mut::<tcp::Socket>(handle);
        match sock.connect(iface.context(), remote_ep, local_ep) {
            Ok(()) => {
                self.conns.insert(
                    ConnectionHandle(connection_id),
                    Conn {
                        socket_handle: handle,
                        from_net,
                        out_buf: VecDeque::new(),
                        connect_reply: Some(reply),
                        handed_off: false,
                        closing: false,
                    },
                );
            }
            Err(e) => {
                self.sockets.remove(handle);
                let _ = reply.send(Err(format!("connect: {e}")));
            }
        }
    }

    fn handle_resolve(&mut self, name: String, reply: oneshot::Sender<Result<IpAddr, String>>) {
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

    fn finish_ready_dns(&mut self) {
        let mut index = 0;
        while index < self.dns_pending.len() {
            if self.dns_pending[index].v4.pending() || self.dns_pending[index].v6.pending() {
                index += 1;
                continue;
            }
            let pending = self.dns_pending.remove(index);
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
    }

    fn service_sockets(&mut self) {
        let handles: Vec<ConnectionHandle> = self.conns.keys().copied().collect();
        for handle in handles {
            let mut remove = false;
            {
                let conn = self.conns.get_mut(&handle).expect("conn for handle");
                let sock = self.sockets.get_mut::<tcp::Socket>(conn.socket_handle);

                // 入口请求被取消且没有任何 TcpConn/TcpWriter 接管时直接 abort，
                // 避免半开 socket 和 conns 项留在 actor 里直到远端超时：
                // 1) connect() 还没收到 reply；
                // 2) reply 已发出，但异步侧尚未发 Handoff 确认接管。
                let orphaned = conn
                    .connect_reply
                    .as_ref()
                    .is_some_and(|reply| reply.is_closed())
                    || (conn.connect_reply.is_none()
                        && !conn.handed_off
                        && conn.from_net.is_closed());
                if orphaned {
                    sock.abort();
                    remove = true;
                }

                if !remove {
                    // Resolve the pending connect once established or failed.
                    if conn.connect_reply.is_some() {
                        if sock.state() == tcp::State::Established {
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
                            Ok(n) => drop(conn.out_buf.drain(..n)),
                            Err(_) => break,
                        }
                    }

                    // net -> socks (bounded by the channel to apply TCP backpressure)
                    while sock.can_recv() {
                        let Ok(permit) = conn.from_net.try_reserve() else {
                            break;
                        };
                        let mut buf = [0u8; RECV_CHUNK];
                        match sock.recv_slice(&mut buf) {
                            Ok(0) => break,
                            Ok(n) => permit.send(buf[..n].to_vec()),
                            Err(_) => break,
                        }
                    }

                    if conn.closing && conn.out_buf.is_empty() {
                        sock.close();
                    }
                    if sock.state() == tcp::State::Closed {
                        remove = true;
                    }
                }
            }
            if remove {
                let conn = self.conns.remove(&handle).expect("conn for handle");
                self.sockets.remove(conn.socket_handle);
            }
        }
    }

    fn service_dns(&mut self) {
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
        self.finish_ready_dns();
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
            read_buf: Vec::new(),
            read_pos: 0,
            abort_guard: AbortOnDrop {
                cmd: cmd.clone(),
                handle,
                armed: AtomicBool::new(true),
            },
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
            read_buf: Vec::new(),
            read_pos: 0,
            abort_guard: AbortOnDrop {
                cmd: cmd.clone(),
                handle: old_handle,
                armed: AtomicBool::new(true),
            },
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
            reply,
        });
        assert_eq!(actor.conns.len(), 1);

        // 模拟入口请求在 connect() 返回前被排空超时取消。
        drop(rx);
        actor.service_sockets();
        assert!(actor.conns.is_empty(), "取消的半开连接必须被清理");
    }
}
