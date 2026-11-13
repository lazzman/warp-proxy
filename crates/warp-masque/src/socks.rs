//! 本地入口代理。默认是 SOCKS5；mixed 模式下同一端口同时接受 HTTP 代理。
//!
//! 域名在隧道内解析，避免 DNS 泄漏。关闭 WARP 或访问本机回环时直接连接。

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::atomic::Ordering;
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
#[derive(Clone)]
pub(crate) struct AccessRecord {
    pub id: u64,
    pub proto: &'static str,
    pub client: String,
    pub user: String,
    pub target: String,
    pub account: String,
    pub egress: String,
    pub family: String,
    pub result: String,
    pub up: u64,
    pub down: u64,
    pub millis: u64,
}

/// 排空超时强制中断：记录访问日志，并让外层 select! 取消整个请求、释放 lease。
pub(crate) fn aborted_record(mut record: AccessRecord, started: Instant) -> AccessRecord {
    record.result = "drain-aborted".into();
    record.millis = started.elapsed().as_millis() as u64;
    record
}

/// 连接成功后写入实际地址族和对应出口。访问日志与活跃连接都读这份记录。
pub(crate) fn note_connected(
    record: &mut AccessRecord,
    family: &str,
    lease: &crate::pool::ConnLease,
) {
    record.family = family.to_string();
    record.egress = crate::pool::egress_for_family(
        family,
        lease.egress_v4(),
        lease.egress_v6(),
        &record.egress,
    )
    .to_string();
}

fn session_open(
    record: &AccessRecord,
    meter: Arc<crate::console::TrafficMeter>,
) -> crate::console::SessionOpen {
    crate::console::SessionOpen {
        protocol: record.proto.to_string(),
        client: record.client.clone(),
        user: record.user.clone(),
        target: record.target.clone(),
        egress: record.egress.clone(),
        family: record.family.clone(),
        account: record.account.parse().unwrap_or(0),
        meter,
    }
}

/// 一行访问日志。字段用 `|` 隔开，成功是 `↗`，其余是 `×`。没有会话编号时请求记为 `-`。
pub(crate) fn access_line(record: &AccessRecord) -> String {
    let family = if record.family.is_empty() {
        "-"
    } else {
        record.family.as_str()
    };
    let id = if record.id == 0 {
        "-".to_string()
    } else {
        record.id.to_string()
    };
    let proto = match record.proto {
        "http" => "HTTP",
        "socks" => "SOCKS",
        other => other,
    };
    format!(
        "[access] {} {} | 请求={} | 结果={} | 客户端={} | 用户={} | 目标={} | 账号={} | 地址族={} | 出口={} | 上行={} | 下行={} | 耗时毫秒={}",
        access_mark(&record.result),
        proto,
        id,
        record.result,
        record.client,
        record.user,
        record.target,
        record.account,
        family,
        record.egress,
        record.up,
        record.down,
        record.millis
    )
}

fn access_mark(result: &str) -> &'static str {
    match result {
        "ok" | "direct" => "↗",
        _ => "×",
    }
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
    if pool.mixed() {
        let mut first = [0u8; 1];
        if client.peek(&mut first).await.is_ok() && first[0] != VER {
            let record = crate::http_proxy::handle(client, pool.clone(), peer).await;
            pool.record_access(access_line(&record));
            return;
        }
    }
    let record = handle_pool(client, peer, pool.clone()).await;
    pool.record_access(access_line(&record));
}

pub(crate) async fn handle_pool(
    mut client: TcpStream,
    peer: SocketAddr,
    pool: Arc<Pool>,
) -> AccessRecord {
    let started = Instant::now();
    let mut record = AccessRecord {
        id: 0,
        proto: "socks",
        client: peer.to_string(),
        user: "-".into(),
        target: "-".into(),
        account: "-".into(),
        egress: "-".into(),
        family: String::new(),
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
    if let Some(user) = request
        .user
        .as_ref()
        .filter(|user| !user.is_empty())
        .cloned()
    {
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
    };
    record.account = lease.worker_id.to_string();
    record.egress = lease.egress.clone();
    // checkout 到建链、写响应都可能长期阻塞，由外层 select! 整体取消；
    // 进入转发后交给 relay_counted 自身的中断信号，保留会话流量与 netstack abort。
    let drain_signal = lease.drain_signal();
    let aborted = record.clone();
    let result = tokio::select! {
        biased;
        _ = drain_signal.aborted() => aborted_record(aborted, started),
        prepared = prepare_leased(client, &lease, request, record, started) => match prepared {
            LeasePrepared::Failed(record) => record,
            LeasePrepared::Relay { client, conn, mut record } => {
                let (up, down, aborted) =
                    relay_session(&pool, client, conn, &lease, &mut record).await;
                record.up = up;
                record.down = down;
                record.result = if aborted { "drain-aborted" } else { "ok" }.into();
                record.millis = started.elapsed().as_millis() as u64;
                record
            }
        },
    };
    drop(lease);
    result
}

enum LeasePrepared {
    Failed(AccessRecord),
    Relay {
        client: TcpStream,
        conn: TcpConn,
        record: AccessRecord,
    },
}

async fn prepare_leased(
    mut client: TcpStream,
    lease: &crate::pool::ConnLease,
    request: SocksRequest,
    mut record: AccessRecord,
    started: Instant,
) -> LeasePrepared {
    match connect_target(&mut client, lease.net(), &request.host, request.port).await {
        Ok((conn, family)) => {
            note_connected(&mut record, family, lease);
            if client.write_all(&reply(0x00)).await.is_err() {
                record.result = "write-failed".into();
                record.millis = started.elapsed().as_millis() as u64;
                LeasePrepared::Failed(record)
            } else {
                LeasePrepared::Relay {
                    client,
                    conn,
                    record,
                }
            }
        }
        Err(result) => {
            record.result = result.into();
            record.millis = started.elapsed().as_millis() as u64;
            LeasePrepared::Failed(record)
        }
    }
}

async fn connect_target(
    client: &mut TcpStream,
    net: &NetHandle,
    host: &str,
    port: u16,
) -> Result<(TcpConn, &'static str), &'static str> {
    let ip = match net.resolve(host).await {
        Ok(ip) => ip,
        Err(_) => {
            let _ = client.write_all(&reply(0x04)).await;
            return Err("resolve");
        }
    };
    let family = if ip.is_ipv4() { "ipv4" } else { "ipv6" };
    match net.connect(SocketAddr::new(ip, port)).await {
        Ok(conn) => Ok((conn, family)),
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
        Ok((conn, _)) => conn,
        Err(_) => return Ok(()),
    };
    client.write_all(&reply(0x00)).await?;
    let meter = Arc::new(crate::console::TrafficMeter::new());
    let signal = crate::pool::DrainSignal::never();
    relay_counted(client, conn, meter, signal).await;
    Ok(())
}

pub(crate) async fn relay_session(
    pool: &Arc<Pool>,
    client: TcpStream,
    conn: TcpConn,
    lease: &crate::pool::ConnLease,
    record: &mut AccessRecord,
) -> (u64, u64, bool) {
    let meter = std::sync::Arc::new(crate::console::TrafficMeter::new());
    let guard = pool.track_session(session_open(record, Arc::clone(&meter)));
    record.id = guard.id();
    let counts = relay_counted(client, conn, meter, lease.drain_signal()).await;
    drop(guard);
    counts
}

pub(crate) async fn relay_counted(
    client: TcpStream,
    conn: TcpConn,
    meter: Arc<crate::console::TrafficMeter>,
    drain_signal: crate::pool::DrainSignal,
) -> (u64, u64, bool) {
    let (mut reader_client, mut writer_client) = client.into_split();
    let net_abort = conn.abort_handle();
    let (mut reader_net, writer_net) = conn.into_split();
    let up_meter = Arc::clone(&meter);
    let down_meter = Arc::clone(&meter);

    let net_to_client = async move {
        while let Some(chunk) = reader_net.recv().await {
            down_meter
                .down
                .fetch_add(chunk.len() as u64, Ordering::Relaxed);
            down_meter.touch();
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
                    up_meter.up.fetch_add(n as u64, Ordering::Relaxed);
                    up_meter.touch();
                    writer_net.send(buf[..n].to_vec());
                }
            }
        }
        writer_net.close();
    };

    let mut aborted = false;
    tokio::select! {
        _ = net_to_client => {}
        _ = client_to_net => {}
        _ = drain_signal.aborted() => {
            net_abort.abort();
            aborted = true;
        }
    }
    (
        meter.up.load(Ordering::Relaxed),
        meter.down.load(Ordering::Relaxed),
        aborted,
    )
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

#[cfg(test)]
mod tests {
    use super::*;

    fn record(egress: &str) -> AccessRecord {
        AccessRecord {
            id: 7,
            proto: "http",
            client: "172.29.0.1:59868".into(),
            user: "grok".into(),
            target: "accounts.x.ai:443".into(),
            account: "1".into(),
            egress: egress.into(),
            family: String::new(),
            result: "ok".into(),
            up: 1,
            down: 2,
            millis: 3,
        }
    }

    fn shows(family: &str, v4: &str, v6: &str) -> (String, String, String) {
        let mut row = record(v4);
        let lease = crate::pool::test_lease(v4, v4, v6);
        note_connected(&mut row, family, &lease);
        let line = access_line(&row);
        let console = crate::console::Console::new();
        let meter = Arc::new(crate::console::TrafficMeter::new());
        let _guard = console.open_session(session_open(&row, meter));
        let live = console.sessions().remove(0);
        (line, live.family, live.egress)
    }

    #[test]
    fn log_and_live_session_use_the_connected_family() {
        let (line, family, egress) = shows("ipv6", "104.28.233.73", "2a09:bac::1");
        assert!(line.contains("[access] ↗ HTTP | "), "{line}");
        assert!(line.contains("地址族=ipv6 | 出口=2a09:bac::1 | "), "{line}");
        assert!(!line.contains("104.28.233.73"), "{line}");
        assert_eq!(family, "ipv6");
        assert_eq!(egress, "2a09:bac::1");

        let (line, family, egress) = shows("ipv4", "104.28.233.73", "2a09:bac::1");
        assert!(line.contains("地址族=ipv4"), "{line}");
        assert!(line.contains("出口=104.28.233.73 "), "{line}");
        assert!(!line.contains("2a09:bac::1"), "{line}");
        assert_eq!(family, "ipv4");
        assert_eq!(egress, "104.28.233.73");

        let (line, family, egress) = shows("ipv6", "104.28.233.73", "");
        assert!(line.contains("地址族=ipv6"), "{line}");
        assert!(line.contains("出口=- "), "{line}");
        assert!(!line.contains("104.28.233.73"), "{line}");
        assert_eq!(family, "ipv6");
        assert_eq!(egress, "-");
    }

    #[test]
    fn failed_access_line_marks_the_miss_and_hides_a_zero_id() {
        let mut row = record("-");
        row.id = 0;
        row.result = "bad-request".into();
        let line = access_line(&row);
        assert!(
            line.starts_with("[access] × HTTP | 请求=- | 结果=bad-request | "),
            "{line}"
        );
        assert!(line.contains("地址族=- | 出口=- | "), "{line}");
    }
}
