//! HTTP/2 fallback transport for QUIC-blocked networks (`usque --http2`).
//!
//! Over TCP+TLS (ALPN `h2`) with the same self-signed mTLS identity + endpoint
//! pinning as HTTP/3. Cloudflare's H2 endpoint does **not** advertise RFC 8441
//! extended CONNECT (`SETTINGS_ENABLE_CONNECT_PROTOCOL=false`), so this uses a
//! **plain CONNECT** to the authority plus a `cf-connect-proto: cf-connect-ip`
//! header to select connect-ip. IP packets travel as **DATAGRAM capsules**
//! (type `0x00`), and — Cloudflare's non-RFC quirk — the capsule value is the
//! **bare IP packet**: the connect-ip context id (0) is omitted, not included as
//! RFC 9297 would (matched to the `connect-ip-go` fork Cloudflare's client uses).

use std::net::{Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use bytes::{Buf, Bytes, BytesMut};
use tokio::net::TcpStream;
use tokio::sync::{mpsc, Mutex};

use crate::config::{WarpConfig, DEFAULT_ENDPOINT_H2_V4};
use crate::error::{Error, Result};
use crate::keys::DeviceKeypair;
use crate::tls::tunnel_client_config;
use crate::tunnel::{
    decode_varint, encode_varint, parse_assigned_v4, parse_assigned_v6, AbortOnDrop, Tunnel,
    TunnelIo, CONNECT_SNI, CONNECT_URI, MASQUE_PORT,
};

/// DATAGRAM capsule type (RFC 9297).
const CAPSULE_DATAGRAM: u64 = 0x00;
/// MTU for the HTTP/2 path (matches WARP; capsule size is not datagram-limited).
const H2_MTU: usize = 1280;
/// HTTP/2 收发队列上限（按 IP 包计），防止弱网/慢下游导致无界堆积。
const H2_QUEUE_CAP: usize = 256;
/// 单个 capsule 的最大合法载荷长度，避免畸形长度字段撑爆重组缓冲。
const MAX_CAPSULE_LEN: usize = 64 * 1024;
/// HTTP/2 数据面流控窗口与帧上限，避免默认 64 KiB 窗口锁死整条隧道吞吐。
const H2_STREAM_WINDOW: u32 = 4 * 1024 * 1024;
const H2_CONN_WINDOW: u32 = 16 * 1024 * 1024;
const H2_MAX_FRAME_SIZE: u32 = 64 * 1024;
/// HTTP/2 PING 保活周期与超时，及时发现 NAT/上游静默断连。
const H2_PING_INTERVAL: Duration = Duration::from_secs(20);
const H2_PING_TIMEOUT: Duration = Duration::from_secs(10);

/// HTTP/2 datagram I/O half: send/receive IP packets over the capsule stream.
#[derive(Clone)]
pub struct H2Io {
    out: mpsc::Sender<Vec<u8>>,
    in_rx: Arc<Mutex<mpsc::Receiver<Vec<u8>>>>,
}

/// 测试用：不连接真实隧道，只提供 actor 需要的通道。
#[cfg(test)]
pub(crate) fn dummy_h2_io() -> H2Io {
    let (out, _rx) = mpsc::channel(H2_QUEUE_CAP);
    let (_in_tx, in_rx) = mpsc::channel(H2_QUEUE_CAP);
    H2Io {
        out,
        in_rx: Arc::new(Mutex::new(in_rx)),
    }
}

/// 测试用：创建成对的 H2Io 与测试侧收发端，用于验证隧道丢弃和队列背压行为。
#[cfg(test)]
pub(crate) fn test_h2_channel() -> (H2Io, mpsc::Receiver<Vec<u8>>, mpsc::Sender<Vec<u8>>) {
    let (out, out_rx) = mpsc::channel(H2_QUEUE_CAP);
    let (in_tx, in_rx) = mpsc::channel(H2_QUEUE_CAP);
    (
        H2Io {
            out,
            in_rx: Arc::new(Mutex::new(in_rx)),
        },
        out_rx,
        in_tx,
    )
}

impl H2Io {
    /// The largest IP packet the HTTP/2 path carries in one capsule.
    pub fn max_ip_packet(&self) -> usize {
        H2_MTU
    }

    /// Queue one IP packet to send through the tunnel.
    pub fn send_ip(&self, packet: &[u8]) -> Result<()> {
        match self.out.try_send(packet.to_vec()) {
            Ok(()) => Ok(()),
            // 出口队列已满时按路由器丢包语义丢弃该 IP 包，让上层 TCP 拥塞控制降速而非无限吃内存。
            Err(mpsc::error::TrySendError::Full(_)) => Ok(()),
            Err(mpsc::error::TrySendError::Closed(_)) => {
                Err(Error::Tunnel("h2 tunnel closed".into()))
            }
        }
    }

    /// Receive one IP packet from the tunnel.
    pub async fn recv_ip(&self) -> Result<Vec<u8>> {
        self.in_rx
            .lock()
            .await
            .recv()
            .await
            .ok_or_else(|| Error::Tunnel("h2 tunnel closed".into()))
    }
}

/// Establish the MASQUE tunnel over HTTP/2.
pub async fn connect_h2(
    cfg: &WarpConfig,
    kp: &DeviceKeypair,
    upstream: Option<&crate::upstream::UpstreamProxy>,
) -> Result<Tunnel> {
    let ep = {
        let v4 = if cfg.endpoint_h2_v4.trim().is_empty() {
            DEFAULT_ENDPOINT_H2_V4
        } else {
            cfg.endpoint_h2_v4.trim()
        };
        let ip: Ipv4Addr = v4
            .parse()
            .map_err(|e| Error::Config(format!("endpoint_h2_v4 {v4:?}: {e}")))?;
        SocketAddr::from((ip, MASQUE_PORT))
    };

    // TCP + TLS (ALPN h2), same mTLS identity + endpoint pinning as HTTP/3.
    let tcp = if let Some(upstream) = upstream {
        crate::upstream::connect_via(upstream, ep)
            .await
            .map_err(|err| Error::Tunnel(format!("经上游连接 MASQUE 失败: {err}")))?
    } else {
        TcpStream::connect(ep).await?
    };
    tcp.set_nodelay(true).ok();
    let tls_cfg = tunnel_client_config(cfg, kp, &[b"h2"])?;
    let connector = tokio_rustls::TlsConnector::from(Arc::new(tls_cfg));
    let server_name = rustls::pki_types::ServerName::try_from(CONNECT_SNI)
        .map_err(|e| Error::Tunnel(format!("sni: {e}")))?;
    let tls = connector
        .connect(server_name, tcp)
        .await
        .map_err(|e| Error::Tunnel(format!("h2 tls handshake: {e}")))?;

    let mut builder = h2::client::Builder::new();
    builder
        .initial_window_size(H2_STREAM_WINDOW)
        .initial_connection_window_size(H2_CONN_WINDOW)
        .max_frame_size(H2_MAX_FRAME_SIZE)
        .max_send_buffer_size(1024 * 1024);
    let (mut send_req, mut connection) = builder
        .handshake(tls)
        .await
        .map_err(|e| Error::Tunnel(format!("h2 handshake: {e}")))?;
    let ping_pong = connection.ping_pong();
    // 连接结束或 PING 超时时立即发出死亡信号，并由 AbortOnDrop 在握手失败/释放时中止驱动任务。
    let (dead_tx, dead_rx) = tokio::sync::watch::channel(false);
    let dead_tx = Arc::new(dead_tx);
    let driver_dead = Arc::clone(&dead_tx);
    let conn_driver = AbortOnDrop(tokio::spawn(async move {
        let ping_loop = async move {
            let Some(mut ping_pong) = ping_pong else {
                std::future::pending::<()>().await;
                return;
            };
            let mut ticker = tokio::time::interval_at(
                tokio::time::Instant::now() + H2_PING_INTERVAL,
                H2_PING_INTERVAL,
            );
            ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
            loop {
                ticker.tick().await;
                match tokio::time::timeout(H2_PING_TIMEOUT, ping_pong.ping(h2::Ping::opaque()))
                    .await
                {
                    Ok(Ok(_)) => {}
                    _ => break,
                }
            }
        };
        tokio::select! {
            _ = connection => {}
            _ = ping_loop => {}
        }
        let _ = driver_dead.send(true);
    }));

    // Cloudflare's H2 endpoint does NOT advertise RFC 8441 extended CONNECT;
    // it uses a *plain* CONNECT to the authority plus the `cf-connect-proto`
    // header to select connect-ip (verified: the server sets
    // SETTINGS_ENABLE_CONNECT_PROTOCOL=false, so sending `:protocol` is RST'd).
    let req = http::Request::builder()
        .method(http::Method::CONNECT)
        .uri(CONNECT_URI)
        .header("user-agent", "")
        .header("cf-connect-proto", "cf-connect-ip")
        .header("pq-enabled", "false")
        .header("capsule-protocol", "?1")
        .body(())
        .map_err(|e| Error::Tunnel(format!("build request: {e}")))?;

    let (resp_fut, send_stream) = send_req
        .send_request(req, false)
        .map_err(|e| Error::Tunnel(format!("send extended CONNECT: {e}")))?;
    let resp = resp_fut
        .await
        .map_err(|e| Error::Tunnel(format!("recv response: {e}")))?;
    let status = resp.status();
    let recv_stream = resp.into_body();

    let (out_tx, out_rx) = mpsc::channel::<Vec<u8>>(H2_QUEUE_CAP);
    let (in_tx, in_rx) = mpsc::channel::<Vec<u8>>(H2_QUEUE_CAP);
    let writer = AbortOnDrop(tokio::spawn(writer_loop(
        send_stream,
        out_rx,
        Arc::clone(&dead_tx),
    )));
    let reader = AbortOnDrop(tokio::spawn(reader_loop(recv_stream, in_tx, dead_tx)));

    let io = H2Io {
        out: out_tx,
        in_rx: Arc::new(Mutex::new(in_rx)),
    };
    let assigned_v4 = parse_assigned_v4(&cfg.ipv4)?;
    let assigned_v6 = parse_assigned_v6(&cfg.ipv6);

    Ok(Tunnel::from_parts(
        TunnelIo::H2(io),
        status,
        assigned_v4,
        assigned_v6,
        dead_rx,
        vec![Box::new(conn_driver), Box::new(writer), Box::new(reader)],
    ))
}

/// Frame an IP packet as a DATAGRAM capsule. Cloudflare's H2 quirk: the capsule
/// value is the bare IP packet — the connect-ip context id (0) is NOT included
/// (verified against the `connect-ip-go` fork's `SendDatagram`).
fn encode_datagram_capsule(pkt: &[u8]) -> Vec<u8> {
    let mut cap = Vec::with_capacity(pkt.len() + 8);
    encode_varint(&mut cap, CAPSULE_DATAGRAM);
    encode_varint(&mut cap, pkt.len() as u64);
    cap.extend_from_slice(pkt);
    cap
}

#[derive(Debug, PartialEq, Eq)]
enum CapsuleParse {
    Incomplete,
    Ready(u64, usize, usize),
    TooLarge,
}

/// 解析缓冲区头部的单个 capsule；遇到超长异常帧时返回 TooLarge 以终止连接。
fn parse_capsule(buf: &[u8]) -> CapsuleParse {
    let mut p: &[u8] = buf;
    let before = p.len();
    let Some(ctype) = decode_varint(&mut p) else {
        return CapsuleParse::Incomplete;
    };
    let Some(raw_len) = decode_varint(&mut p) else {
        return CapsuleParse::Incomplete;
    };
    if raw_len > MAX_CAPSULE_LEN as u64 {
        return CapsuleParse::TooLarge;
    }
    let clen = raw_len as usize;
    let header = before - p.len();
    if p.len() < clen {
        return CapsuleParse::Incomplete;
    }
    CapsuleParse::Ready(ctype, header, header + clen)
}

/// Drain outbound IP packets and write them as DATAGRAM capsules, honouring
/// HTTP/2 flow control.
async fn writer_loop(
    mut send: h2::SendStream<Bytes>,
    mut out_rx: mpsc::Receiver<Vec<u8>>,
    dead_tx: Arc<tokio::sync::watch::Sender<bool>>,
) {
    while let Some(pkt) = out_rx.recv().await {
        let cap = encode_datagram_capsule(&pkt);

        send.reserve_capacity(cap.len());
        while send.capacity() < cap.len() {
            match std::future::poll_fn(|cx| send.poll_capacity(cx)).await {
                Some(Ok(_)) => {}
                _ => {
                    let _ = dead_tx.send(true);
                    return; // stream/connection closed
                }
            }
        }
        if send.send_data(Bytes::from(cap), false).is_err() {
            let _ = dead_tx.send(true);
            return;
        }
    }
}

/// Read DATA frames, reassemble capsules across frame boundaries, and forward
/// the IP packet from each DATAGRAM capsule.
async fn reader_loop(
    mut recv: h2::RecvStream,
    in_tx: mpsc::Sender<Vec<u8>>,
    dead_tx: Arc<tokio::sync::watch::Sender<bool>>,
) {
    let mut buf = BytesMut::with_capacity(8 * 1024);
    while let Some(chunk) = recv.data().await {
        let data = match chunk {
            Ok(d) => d,
            Err(_) => break,
        };
        let chunk_len = data.len();
        buf.extend_from_slice(&data);

        loop {
            match parse_capsule(&buf) {
                CapsuleParse::Incomplete => break,
                CapsuleParse::TooLarge => {
                    let _ = dead_tx.send(true);
                    return;
                }
                CapsuleParse::Ready(ctype, voff, total) => {
                    if ctype == CAPSULE_DATAGRAM {
                        // 在投递给有界队列后再归还流控额度，保持真正的 HTTP/2 下行背压。
                        let packet = buf[voff..total].to_vec();
                        buf.advance(total);
                        if in_tx.send(packet).await.is_err() {
                            let _ = dead_tx.send(true);
                            return;
                        }
                    } else {
                        buf.advance(total);
                    }
                }
            }
        }
        // 解析并投递完该分片后再归还 HTTP/2 流控额度，防止下行无界堆积。
        let _ = recv.flow_control().release_capacity(chunk_len);
        if buf.is_empty() && buf.capacity() > 64 * 1024 {
            buf = BytesMut::with_capacity(8 * 1024);
        }
    }
    let _ = dead_tx.send(true);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn datagram_capsule_roundtrips() {
        let pkt = b"\x45\x00\x00\x1c-fake-ip-packet";
        let cap = encode_datagram_capsule(pkt);
        let CapsuleParse::Ready(ctype, voff, total) = parse_capsule(&cap) else {
            panic!("应解析成功");
        };
        assert_eq!(ctype, CAPSULE_DATAGRAM);
        assert_eq!(total, cap.len());
        assert_eq!(&cap[voff..total], pkt);
        // A truncated buffer is not yet parseable.
        assert_eq!(
            parse_capsule(&cap[..cap.len() - 1]),
            CapsuleParse::Incomplete
        );
    }

    #[test]
    fn parses_back_to_back_capsules() {
        let mut buf = encode_datagram_capsule(b"aaa");
        buf.extend(encode_datagram_capsule(b"bbbb"));
        let CapsuleParse::Ready(_, v1, t1) = parse_capsule(&buf) else {
            panic!("第一包应解析成功");
        };
        assert_eq!(&buf[v1..t1], b"aaa");
        let CapsuleParse::Ready(_, v2, t2) = parse_capsule(&buf[t1..]) else {
            panic!("第二包应解析成功");
        };
        assert_eq!(&buf[t1..][v2..t2], b"bbbb");
    }

    #[test]
    fn rejects_oversized_capsule() {
        let mut buf = Vec::new();
        encode_varint(&mut buf, CAPSULE_DATAGRAM);
        encode_varint(&mut buf, (MAX_CAPSULE_LEN as u64) + 1);
        assert_eq!(parse_capsule(&buf), CapsuleParse::TooLarge);
    }

    #[test]
    fn h2_send_ip_drops_instead_of_growing_unbounded_when_queue_full() {
        let (io, mut out_rx, _in_tx) = test_h2_channel();
        for idx in 0..(H2_QUEUE_CAP + 32) {
            io.send_ip(&[idx as u8; 16]).unwrap();
        }
        let mut drained = 0;
        while out_rx.try_recv().is_ok() {
            drained += 1;
        }
        assert_eq!(drained, H2_QUEUE_CAP);
    }

    #[tokio::test]
    async fn h2_builder_configures_large_windows_and_abort_on_drop_closes_stream() {
        let (client_io, server_io) = tokio::io::duplex(256 * 1024);
        let server_task = tokio::spawn(async move {
            let mut server_builder = h2::server::Builder::new();
            server_builder.max_send_buffer_size(H2_STREAM_WINDOW as usize);
            let mut conn = server_builder
                .handshake::<_, Bytes>(server_io)
                .await
                .unwrap();
            let (req, mut respond) = conn.accept().await.unwrap().unwrap();
            let recv = req.into_body();
            let send = respond
                .send_response(http::Response::new(()), false)
                .unwrap();
            // 持续驱动连接，直到客户端释放 Tunnel 中止连接。
            let driver =
                tokio::spawn(async move { while let Some(Ok(_)) = conn.accept().await {} });
            (recv, send, driver)
        });

        let mut builder = h2::client::Builder::new();
        builder
            .initial_window_size(H2_STREAM_WINDOW)
            .initial_connection_window_size(H2_CONN_WINDOW)
            .max_frame_size(H2_MAX_FRAME_SIZE);
        let (mut send_req, connection) = builder.handshake(client_io).await.unwrap();
        let (dead_tx, dead_rx) = tokio::sync::watch::channel(false);
        let dead_tx = Arc::new(dead_tx);
        let driver_dead = Arc::clone(&dead_tx);
        let conn_driver = AbortOnDrop(tokio::spawn(async move {
            let _ = connection.await;
            let _ = driver_dead.send(true);
        }));

        let req = http::Request::builder()
            .method(http::Method::CONNECT)
            .uri(CONNECT_URI)
            .body(())
            .unwrap();
        let (resp_fut, send_stream) = send_req.send_request(req, false).unwrap();
        let (mut server_recv, mut server_send, server_driver) = server_task.await.unwrap();
        let resp = resp_fut.await.unwrap();
        let recv_stream = resp.into_body();

        // 服务端立即可用的单流发送窗口应达到我们配置的 4 MiB（远大于默认 64 KiB）。
        server_send.reserve_capacity(2 * 1024 * 1024);
        assert!(
            server_send.capacity() >= 1024 * 1024,
            "期望流窗口 >= 1 MiB，实际={}",
            server_send.capacity()
        );

        let (out_tx, out_rx) = mpsc::channel::<Vec<u8>>(H2_QUEUE_CAP);
        let (in_tx, in_rx) = mpsc::channel::<Vec<u8>>(H2_QUEUE_CAP);
        let writer = AbortOnDrop(tokio::spawn(writer_loop(
            send_stream,
            out_rx,
            Arc::clone(&dead_tx),
        )));
        let reader = AbortOnDrop(tokio::spawn(reader_loop(recv_stream, in_tx, dead_tx)));
        let io = H2Io {
            out: out_tx,
            in_rx: Arc::new(Mutex::new(in_rx)),
        };
        let tunnel = Tunnel::from_parts(
            TunnelIo::H2(io.clone()),
            http::StatusCode::OK,
            Ipv4Addr::new(172, 16, 0, 2),
            None,
            dead_rx,
            vec![Box::new(conn_driver), Box::new(writer), Box::new(reader)],
        );

        // 丢弃 Tunnel 后，即便外部仍持有 H2Io 克隆，所有后台任务也必须立刻中止并关闭 H2 流。
        drop(tunnel);
        assert!(tokio::time::timeout(Duration::from_secs(1), io.recv_ip())
            .await
            .expect("recv_ip 必须立刻返回错误而不是永久挂起")
            .is_err());
        let server_eof = tokio::time::timeout(Duration::from_secs(1), server_recv.data())
            .await
            .expect("服务端流应在客户端 Tunnel 释放后迅速感知关闭");
        assert!(matches!(server_eof, None | Some(Err(_))));
        server_driver.abort();
    }
}
