//! 本地入口代理。默认是 SOCKS5；mixed 模式下同一端口同时接受 HTTP 代理。
//!
//! 域名在隧道内解析，避免 DNS 泄漏。关闭 WARP 或访问本机回环时直接连接。

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Instant;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

use crate::netstack::{NetHandle, TcpConn};
use crate::pool::Pool;
use crate::schedule::PickFail;

const VER: u8 = 0x05;
const CMD_CONNECT: u8 = 0x01;
const ATYP_V4: u8 = 0x01;
const ATYP_DOMAIN: u8 = 0x03;
const ATYP_V6: u8 = 0x04;

/// 一条入口连接的访问日志字段。密码不会出现在这里。
pub(crate) struct AccessRecord {
    pub proto: &'static str,
    pub client: String,
    pub user: String,
    pub target: String,
    pub account: String,
    pub egress: String,
    pub result: String,
    pub up: u64,
    pub down: u64,
    pub millis: u64,
}

pub(crate) fn emit_access(enabled: bool, record: &AccessRecord) {
    if !enabled {
        return;
    }
    eprintln!(
        "[access] 协议={} 结果={} 客户端={} 用户={} 目标={} 账号={} 出口={} 上行={} 下行={} 耗时毫秒={}",
        record.proto,
        record.result,
        record.client,
        record.user,
        record.target,
        record.account,
        record.egress,
        record.up,
        record.down,
        record.millis
    );
}

/// 在 listener 上提供 SOCKS5，全部 CONNECT 走同一个 netstack。
pub async fn serve(listener: TcpListener, net: NetHandle) {
    loop {
        let Ok((client, _)) = listener.accept().await else {
            continue;
        };
        let net = net.clone();
        tokio::spawn(async move {
            let _ = handle_single(client, net).await;
        });
    }
}

async fn handle_single(mut client: TcpStream, net: NetHandle) -> std::io::Result<()> {
    let Some(request) = read_request(&mut client, None).await? else {
        return Ok(());
    };
    via_netstack(client, &net, &request.host, request.port).await
}

/// 在 listener 上提供入口代理，并在账号池之间调度。
pub async fn serve_pool(listener: TcpListener, pool: Arc<Pool>) {
    loop {
        let Ok((client, peer)) = listener.accept().await else {
            continue;
        };
        let pool = pool.clone();
        tokio::spawn(async move {
            handle_client(client, peer, pool).await;
        });
    }
}

async fn handle_client(client: TcpStream, peer: SocketAddr, pool: Arc<Pool>) {
    let client_addr = peer.to_string();
    if pool.mixed() {
        let mut first = [0u8; 1];
        if client.peek(&mut first).await.is_ok() && first[0] != VER {
            let record = crate::http_proxy::handle(client, pool.clone(), &client_addr).await;
            emit_access(pool.access_log(), &record);
            return;
        }
    }
    let record = handle_pool(client, peer, pool.clone()).await;
    emit_access(pool.access_log(), &record);
}

async fn handle_pool(mut client: TcpStream, peer: SocketAddr, pool: Arc<Pool>) -> AccessRecord {
    let started = Instant::now();
    let mut record = AccessRecord {
        proto: "socks",
        client: peer.to_string(),
        user: "-".into(),
        target: "-".into(),
        account: "-".into(),
        egress: "-".into(),
        result: "closed".into(),
        up: 0,
        down: 0,
        millis: 0,
    };
    let request = match read_request(&mut client, pool.proxy_auth()).await {
        Ok(Some(request)) => request,
        Ok(None) => {
            record.result = "rejected".into();
            record.millis = started.elapsed().as_millis() as u64;
            return record;
        }
        Err(_) => {
            record.result = "read-failed".into();
            record.millis = started.elapsed().as_millis() as u64;
            return record;
        }
    };
    if request.auth_failed {
        record.result = "auth".into();
        record.millis = started.elapsed().as_millis() as u64;
        return record;
    }
    if let Some(user) = request.user.filter(|user| !user.is_empty()) {
        record.user = user;
    }
    record.target = format!("{}:{}", request.host, request.port);

    if !pool.enabled() || is_loopback_host(&request.host) {
        match TcpStream::connect((request.host.as_str(), request.port)).await {
            Ok(upstream) => {
                if client.write_all(&reply(0x00)).await.is_err() {
                    record.result = "write-failed".into();
                } else {
                    let _ = relay_direct(client, upstream).await;
                    record.result = "direct".into();
                }
            }
            Err(_) => {
                let _ = client.write_all(&reply(0x05)).await;
                record.result = "connect".into();
            }
        }
        record.millis = started.elapsed().as_millis() as u64;
        return record;
    }

    let username = (record.user != "-").then(|| record.user.clone());
    let lease = match pool.checkout(username.as_deref(), &peer.ip().to_string()) {
        Ok(lease) => lease,
        Err(PickFail::NoWorker) => {
            let _ = client.write_all(&reply(0x01)).await;
            record.result = "no-worker".into();
            record.millis = started.elapsed().as_millis() as u64;
            return record;
        }
        Err(PickFail::StickyDown) => {
            let _ = client.write_all(&reply(0x01)).await;
            record.result = "sticky-down".into();
            record.millis = started.elapsed().as_millis() as u64;
            return record;
        }
    };
    record.account = lease.worker_id.to_string();
    record.egress = lease.egress.clone();
    match connect_target(&mut client, lease.net(), &request.host, request.port).await {
        Ok(conn) => {
            if client.write_all(&reply(0x00)).await.is_err() {
                record.result = "write-failed".into();
            } else {
                let (up, down) = relay_counted(client, conn).await;
                record.up = up;
                record.down = down;
                record.result = "ok".into();
            }
        }
        Err(result) => {
            record.result = result.into();
        }
    }
    record.millis = started.elapsed().as_millis() as u64;
    record
}

async fn connect_target(
    client: &mut TcpStream,
    net: &NetHandle,
    host: &str,
    port: u16,
) -> Result<TcpConn, &'static str> {
    let ip = match net.resolve(host).await {
        Ok(ip) => ip,
        Err(_) => {
            let _ = client.write_all(&reply(0x04)).await;
            return Err("resolve");
        }
    };
    match net.connect(SocketAddr::new(ip, port)).await {
        Ok(conn) => Ok(conn),
        Err(_) => {
            let _ = client.write_all(&reply(0x05)).await;
            Err("connect")
        }
    }
}

async fn via_netstack(
    mut client: TcpStream,
    net: &NetHandle,
    host: &str,
    port: u16,
) -> std::io::Result<()> {
    let conn = match connect_target(&mut client, net, host, port).await {
        Ok(conn) => conn,
        Err(_) => return Ok(()),
    };
    client.write_all(&reply(0x00)).await?;
    relay_counted(client, conn).await;
    Ok(())
}

pub(crate) async fn relay_counted(client: TcpStream, conn: TcpConn) -> (u64, u64) {
    let (mut reader_client, mut writer_client) = client.into_split();
    let (mut reader_net, writer_net) = conn.into_split();
    let up = Arc::new(AtomicU64::new(0));
    let down = Arc::new(AtomicU64::new(0));
    let up_count = up.clone();
    let down_count = down.clone();

    let net_to_client = async move {
        while let Some(chunk) = reader_net.recv().await {
            down_count.fetch_add(chunk.len() as u64, Ordering::Relaxed);
            if writer_client.write_all(&chunk).await.is_err() {
                break;
            }
        }
        let _ = writer_client.shutdown().await;
    };
    let client_to_net = async move {
        let mut buf = [0u8; 8192];
        loop {
            match reader_client.read(&mut buf).await {
                Ok(0) | Err(_) => break,
                Ok(n) => {
                    up_count.fetch_add(n as u64, Ordering::Relaxed);
                    writer_net.send(buf[..n].to_vec());
                }
            }
        }
        writer_net.close();
    };

    tokio::select! {
        _ = net_to_client => {}
        _ = client_to_net => {}
    }
    (up.load(Ordering::Relaxed), down.load(Ordering::Relaxed))
}

async fn relay_direct(mut client: TcpStream, mut upstream: TcpStream) {
    let _ = tokio::io::copy_bidirectional(&mut client, &mut upstream).await;
}

fn reply(status: u8) -> [u8; 10] {
    [VER, status, 0x00, ATYP_V4, 0, 0, 0, 0, 0, 0]
}

struct SocksRequest {
    user: Option<String>,
    host: String,
    port: u16,
    auth_failed: bool,
}

async fn read_request(
    client: &mut TcpStream,
    auth: Option<(String, String)>,
) -> std::io::Result<Option<SocksRequest>> {
    let mut head = [0u8; 2];
    client.read_exact(&mut head).await?;
    if head[0] != VER {
        return Ok(None);
    }
    let mut methods = vec![0u8; head[1] as usize];
    client.read_exact(&mut methods).await?;

    let user = if let Some((expect_user, expect_pass)) = auth {
        if !methods.contains(&0x02) {
            client.write_all(&[VER, 0xFF]).await?;
            return Ok(Some(failed_auth()));
        }
        client.write_all(&[VER, 0x02]).await?;
        match read_userpass(client).await? {
            Some((user, pass)) if user == expect_user && pass == expect_pass => {
                client.write_all(&[0x01, 0x00]).await?;
                Some(user)
            }
            _ => {
                client.write_all(&[0x01, 0x01]).await?;
                return Ok(Some(failed_auth()));
            }
        }
    } else if methods.contains(&0x02) {
        client.write_all(&[VER, 0x02]).await?;
        match read_userpass(client).await? {
            Some((user, _)) => {
                client.write_all(&[0x01, 0x00]).await?;
                if user.is_empty() {
                    None
                } else {
                    Some(user)
                }
            }
            None => {
                client.write_all(&[0x01, 0x01]).await?;
                return Ok(Some(failed_auth()));
            }
        }
    } else if methods.contains(&0x00) {
        client.write_all(&[VER, 0x00]).await?;
        None
    } else {
        client.write_all(&[VER, 0xFF]).await?;
        return Ok(None);
    };

    let mut req = [0u8; 4];
    client.read_exact(&mut req).await?;
    if req[0] != VER {
        return Ok(None);
    }
    if req[1] != CMD_CONNECT {
        client.write_all(&reply(0x07)).await?;
        return Ok(None);
    }
    let host = match req[3] {
        ATYP_V4 => {
            let mut addr = [0u8; 4];
            client.read_exact(&mut addr).await?;
            IpAddr::V4(Ipv4Addr::from(addr)).to_string()
        }
        ATYP_V6 => {
            let mut addr = [0u8; 16];
            client.read_exact(&mut addr).await?;
            IpAddr::V6(Ipv6Addr::from(addr)).to_string()
        }
        ATYP_DOMAIN => {
            let mut len = [0u8; 1];
            client.read_exact(&mut len).await?;
            let mut name = vec![0u8; len[0] as usize];
            client.read_exact(&mut name).await?;
            String::from_utf8_lossy(&name).into_owned()
        }
        _ => {
            client.write_all(&reply(0x08)).await?;
            return Ok(None);
        }
    };
    let mut port_bytes = [0u8; 2];
    client.read_exact(&mut port_bytes).await?;
    Ok(Some(SocksRequest {
        user,
        host,
        port: u16::from_be_bytes(port_bytes),
        auth_failed: false,
    }))
}

fn failed_auth() -> SocksRequest {
    SocksRequest {
        user: None,
        host: String::new(),
        port: 0,
        auth_failed: true,
    }
}

async fn read_userpass(client: &mut TcpStream) -> std::io::Result<Option<(String, String)>> {
    let mut version = [0u8; 1];
    client.read_exact(&mut version).await?;
    if version[0] != 0x01 {
        return Ok(None);
    }
    let mut user_len = [0u8; 1];
    client.read_exact(&mut user_len).await?;
    let mut user = vec![0u8; user_len[0] as usize];
    client.read_exact(&mut user).await?;
    let mut pass_len = [0u8; 1];
    client.read_exact(&mut pass_len).await?;
    let mut pass = vec![0u8; pass_len[0] as usize];
    client.read_exact(&mut pass).await?;
    Ok(Some((
        String::from_utf8_lossy(&user).into_owned(),
        String::from_utf8_lossy(&pass).into_owned(),
    )))
}

fn is_loopback_host(host: &str) -> bool {
    if host == "localhost" || host.ends_with(".localhost") {
        return true;
    }
    host.parse::<IpAddr>()
        .map(|ip| ip.is_loopback())
        .unwrap_or(false)
}
