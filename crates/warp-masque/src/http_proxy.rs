//! 与 SOCKS5 同端口的 HTTP 代理。
//!
//! 支持 `CONNECT`（HTTPS）和绝对 URL 形式的普通 HTTP。认证与 SOCKS 共用同一组
//! 用户名密码；未配置密码时，请求里的 Basic 用户名只用于黏性，不拒绝匿名。

use std::net::SocketAddr;
use std::time::Instant;

use base64::Engine;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

use crate::pool::Pool;
use crate::schedule::PickFail;
use crate::socks::{self, AccessRecord};
use std::sync::Arc;

fn sticky_client_ip(peer: SocketAddr) -> String {
    peer.ip().to_string()
}

#[cfg(test)]
mod sticky_tests {
    use super::sticky_client_ip;

    #[test]
    fn client_port_does_not_change_ip_hash_key() {
        for (first, second, expected) in [
            ("198.51.100.7:12001", "198.51.100.7:62000", "198.51.100.7"),
            ("[2001:db8::7]:12001", "[2001:db8::7]:62000", "2001:db8::7"),
        ] {
            assert_eq!(sticky_client_ip(first.parse().unwrap()), expected);
            assert_eq!(sticky_client_ip(second.parse().unwrap()), expected);
        }
    }
}

/// 处理一条已经判定为 HTTP 的连接。`client` 尚未被读取。
pub async fn handle(mut client: TcpStream, pool: Arc<Pool>, peer: SocketAddr) -> AccessRecord {
    let started = Instant::now();
    let client_ip = sticky_client_ip(peer);
    let mut record = AccessRecord {
        id: 0,
        proto: "http",
        client: peer.to_string(),
        user: "-".into(),
        target: "-".into(),
        account: "-".into(),
        egress: "-".into(),
        family: String::new(),
        result: "bad-request".into(),
        up: 0,
        down: 0,
        millis: 0,
    };
    let request = match read_headers(&mut client).await {
        Ok(request) => request,
        Err(result) => {
            record.result = result.into();
            record.millis = started.elapsed().as_millis() as u64;
            return record;
        }
    };
    record.target = request.target.clone();
    match authenticate(&request, pool.proxy_auth()) {
        Auth::Anonymous => {}
        Auth::User(user) => record.user = user,
        Auth::Reject => {
            let _ = write_simple(
                &mut client,
                "407 Proxy Authentication Required",
                "Proxy-Authenticate: Basic realm=\"warp-proxy\"\r\n",
            )
            .await;
            record.result = "auth".into();
            record.millis = started.elapsed().as_millis() as u64;
            return record;
        }
    }

    let username = (record.user != "-").then(|| record.user.clone());
    let prepared = if request.method == "CONNECT" {
        let Some((host, port)) = split_connect_target(&request.target) else {
            let _ = write_simple(&mut client, "400 Bad Request", "").await;
            record.millis = started.elapsed().as_millis() as u64;
            return record;
        };
        record.target = format!("{host}:{port}");
        Prepared::Connect { host, port }
    } else {
        let Some(forward) = rewrite_origin(&request) else {
            let _ = write_simple(&mut client, "400 Bad Request", "").await;
            record.millis = started.elapsed().as_millis() as u64;
            return record;
        };
        record.target = format!("{}:{}", forward.host, forward.port);
        Prepared::Forward(forward)
    };

    let lease = match pool.checkout(username.as_deref(), &client_ip) {
        Ok(lease) => lease,
        Err(fail) => {
            let _ = write_simple(&mut client, "502 Bad Gateway", "").await;
            record.result = pick_result(fail).into();
            record.millis = started.elapsed().as_millis() as u64;
            return record;
        }
    };
    record.account = lease.worker_id.to_string();
    record.egress = lease.egress.clone();
    // 与 SOCKS5 入口一致：建链/写响应由外层 select! 整体取消；
    // 进入转发后交给 relay_counted 自身的中断信号，保留流量统计与 netstack abort。
    let drain_signal = lease.drain_signal();
    let aborted = record.clone();
    let result = tokio::select! {
        biased;
        _ = drain_signal.aborted() => socks::aborted_record(aborted, started),
        prepared = prepare_leased(client, &lease, request, prepared, record, started) => match prepared {
            LeasePrepared::Failed(record) => record,
            LeasePrepared::Relay { client, conn, mut record } => {
                let (up, down, aborted) =
                    socks::relay_session(&pool, client, conn, &lease, &mut record).await;
                record.up += up;
                record.down += down;
                record.result = if aborted { "drain-aborted" } else { "ok" }.into();
                record.millis = started.elapsed().as_millis() as u64;
                record
            }
        },
    };
    drop(lease);
    result
}

async fn prepare_leased(
    mut client: TcpStream,
    lease: &crate::pool::ConnLease,
    request: Request,
    prepared: Prepared,
    mut record: AccessRecord,
    started: Instant,
) -> LeasePrepared {
    match prepared {
        Prepared::Connect { host, port } => {
            let conn = match open_tunnel(lease.net(), &host, port).await {
                Ok((conn, family)) => {
                    socks::note_connected(&mut record, family, lease);
                    conn
                }
                Err(result) => {
                    let _ = write_simple(&mut client, "502 Bad Gateway", "").await;
                    record.result = result.into();
                    record.millis = started.elapsed().as_millis() as u64;
                    return LeasePrepared::Failed(record);
                }
            };
            if write_simple(&mut client, "200 Connection Established", "")
                .await
                .is_err()
            {
                record.result = "write-failed".into();
                record.millis = started.elapsed().as_millis() as u64;
                return LeasePrepared::Failed(record);
            }
            if !request.rest.is_empty() {
                let _ = conn_write(&conn, &request.rest);
                record.up += request.rest.len() as u64;
            }
            LeasePrepared::Relay {
                client,
                conn,
                record,
            }
        }
        Prepared::Forward(forward) => {
            let mut conn = match open_tunnel(lease.net(), &forward.host, forward.port).await {
                Ok((conn, family)) => {
                    socks::note_connected(&mut record, family, lease);
                    conn
                }
                Err(result) => {
                    let _ = write_simple(&mut client, "502 Bad Gateway", "").await;
                    record.result = result.into();
                    record.millis = started.elapsed().as_millis() as u64;
                    return LeasePrepared::Failed(record);
                }
            };
            if conn_write_all(&mut conn, &forward.head).await.is_err() {
                record.result = "connect".into();
                record.millis = started.elapsed().as_millis() as u64;
                return LeasePrepared::Failed(record);
            }
            record.up += forward.head.len() as u64;
            LeasePrepared::Relay {
                client,
                conn,
                record,
            }
        }
    }
}

struct Request {
    method: String,
    target: String,
    version: String,
    headers: Vec<(String, String)>,
    rest: Vec<u8>,
}

struct OriginRequest {
    host: String,
    port: u16,
    head: Vec<u8>,
}

enum Prepared {
    Connect { host: String, port: u16 },
    Forward(OriginRequest),
}

enum LeasePrepared {
    Failed(AccessRecord),
    Relay {
        client: TcpStream,
        conn: crate::netstack::TcpConn,
        record: AccessRecord,
    },
}

enum Auth {
    Anonymous,
    User(String),
    Reject,
}

fn authenticate(request: &Request, configured: Option<(String, String)>) -> Auth {
    let presented = basic_credentials(request);
    match (configured, presented) {
        (Some((user, pass)), Some((got_user, got_pass)))
            if user == got_user && pass == got_pass =>
        {
            Auth::User(got_user)
        }
        (Some(_), _) => Auth::Reject,
        (None, Some((user, _))) if !user.is_empty() => Auth::User(user),
        (None, _) => Auth::Anonymous,
    }
}

fn basic_credentials(request: &Request) -> Option<(String, String)> {
    let value = request.headers.iter().find_map(|(name, value)| {
        name.eq_ignore_ascii_case("proxy-authorization")
            .then_some(value.as_str())
    })?;
    let encoded = value
        .trim()
        .strip_prefix("Basic ")
        .or_else(|| value.trim().strip_prefix("basic "))?;
    let bytes = base64::engine::general_purpose::STANDARD
        .decode(encoded.trim())
        .ok()?;
    let text = String::from_utf8(bytes).ok()?;
    let (user, pass) = text.split_once(':')?;
    Some((user.to_string(), pass.to_string()))
}

async fn read_headers(client: &mut TcpStream) -> Result<Request, &'static str> {
    let mut buf = Vec::new();
    let mut tmp = [0u8; 2048];
    let split_at = loop {
        let n = client.read(&mut tmp).await.map_err(|_| "read-failed")?;
        if n == 0 {
            return Err("closed");
        }
        buf.extend_from_slice(&tmp[..n]);
        if let Some(pos) = find_header_end(&buf) {
            break pos;
        }
        if buf.len() > 64 * 1024 {
            return Err("bad-request");
        }
    };
    let head = std::str::from_utf8(&buf[..split_at]).map_err(|_| "bad-request")?;
    let mut lines = head.split("\r\n");
    let request_line = lines.next().unwrap_or("");
    let mut parts = request_line.split_whitespace();
    let method = parts.next().unwrap_or("").to_string();
    let target = parts.next().unwrap_or("").to_string();
    let version = parts.next().unwrap_or("HTTP/1.1").to_string();
    if method.is_empty() || target.is_empty() {
        return Err("bad-request");
    }
    let mut headers = Vec::new();
    for line in lines {
        if line.is_empty() {
            continue;
        }
        let Some((name, value)) = line.split_once(':') else {
            return Err("bad-request");
        };
        headers.push((name.trim().to_string(), value.trim().to_string()));
    }
    Ok(Request {
        method,
        target,
        version,
        headers,
        rest: buf[split_at + 4..].to_vec(),
    })
}

fn find_header_end(buf: &[u8]) -> Option<usize> {
    buf.windows(4).position(|window| window == b"\r\n\r\n")
}

fn rewrite_origin(request: &Request) -> Option<OriginRequest> {
    let (host, port, path) = split_http_url(&request.target)?;
    let mut head = format!("{} {path} {}\r\n", request.method, request.version).into_bytes();
    let mut saw_host = false;
    for (name, value) in &request.headers {
        if name.eq_ignore_ascii_case("proxy-authorization")
            || name.eq_ignore_ascii_case("proxy-connection")
        {
            continue;
        }
        if name.eq_ignore_ascii_case("host") {
            saw_host = true;
        }
        head.extend(name.as_bytes());
        head.extend(b": ");
        head.extend(value.as_bytes());
        head.extend(b"\r\n");
    }
    if !saw_host {
        let host_header = if port == 80 {
            format!("Host: {host}\r\n")
        } else {
            format!("Host: {host}:{port}\r\n")
        };
        head.extend(host_header.as_bytes());
    }
    head.extend(b"\r\n");
    head.extend(&request.rest);
    Some(OriginRequest { host, port, head })
}

fn split_http_url(url: &str) -> Option<(String, u16, String)> {
    let rest = url.strip_prefix("http://")?;
    let (hostport, path) = match rest.split_once('/') {
        Some((hostport, path)) => (hostport, format!("/{path}")),
        None => (rest, "/".to_string()),
    };
    if hostport.is_empty() {
        return None;
    }
    if let Some(body) = hostport.strip_prefix('[') {
        let (host, port) = body.split_once("]:")?;
        return Some((host.to_string(), port.parse().ok()?, path));
    }
    if let Some((host, port)) = hostport.rsplit_once(':') {
        if let Ok(port) = port.parse() {
            return Some((host.to_string(), port, path));
        }
    }
    Some((hostport.to_string(), 80, path))
}

fn split_connect_target(target: &str) -> Option<(String, u16)> {
    if let Some(body) = target.strip_prefix('[') {
        let (host, port) = body.split_once("]:")?;
        return Some((host.to_string(), port.parse().ok()?));
    }
    let (host, port) = target.rsplit_once(':')?;
    Some((host.to_string(), port.parse().ok()?))
}

async fn open_tunnel(
    net: &crate::netstack::NetHandle,
    host: &str,
    port: u16,
) -> Result<(crate::netstack::TcpConn, &'static str), &'static str> {
    let ip = net.resolve(host).await.map_err(|_| "resolve")?;
    let family = if ip.is_ipv4() { "ipv4" } else { "ipv6" };
    net.connect(std::net::SocketAddr::new(ip, port))
        .await
        .map(|conn| (conn, family))
        .map_err(|_| "connect")
}

fn conn_write(conn: &crate::netstack::TcpConn, bytes: &[u8]) -> std::io::Result<()> {
    conn.send(bytes.to_vec());
    Ok(())
}

async fn conn_write_all(conn: &mut crate::netstack::TcpConn, bytes: &[u8]) -> std::io::Result<()> {
    use tokio::io::AsyncWriteExt;
    conn.write_all(bytes).await
}

async fn write_simple(client: &mut TcpStream, status: &str, extra: &str) -> std::io::Result<()> {
    let body =
        format!("HTTP/1.1 {status}\r\n{extra}Content-Length: 0\r\nConnection: close\r\n\r\n");
    client.write_all(body.as_bytes()).await
}

fn pick_result(fail: PickFail) -> &'static str {
    match fail {
        PickFail::NoWorker => "no-worker",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rewrites_absolute_url_and_strips_proxy_headers() {
        let request = Request {
            method: "GET".into(),
            target: "http://example.com:8080/a?b=1".into(),
            version: "HTTP/1.1".into(),
            headers: vec![
                ("Host".into(), "example.com:8080".into()),
                ("Proxy-Authorization".into(), "Basic eHh4".into()),
                ("Proxy-Connection".into(), "keep-alive".into()),
                ("Accept".into(), "*/*".into()),
            ],
            rest: b"".to_vec(),
        };
        let origin = rewrite_origin(&request).unwrap();
        let head = String::from_utf8(origin.head).unwrap();
        assert_eq!(origin.host, "example.com");
        assert_eq!(origin.port, 8080);
        assert!(head.starts_with("GET /a?b=1 HTTP/1.1\r\n"));
        assert!(!head.to_ascii_lowercase().contains("proxy-"));
        assert!(head.contains("Accept: */*"));
    }

    #[test]
    fn connect_target_accepts_bracketed_ipv6() {
        assert_eq!(
            split_connect_target("[2001:db8::1]:443").unwrap(),
            ("2001:db8::1".into(), 443)
        );
    }
}
