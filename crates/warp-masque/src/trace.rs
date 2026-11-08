//! Egress trace: fetch `cdn-cgi/trace` through a worker's netstack to report its
//! current egress IP / colo and whether WARP is active.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use serde::Serialize;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

use crate::netstack::NetHandle;
use crate::tls::insecure_client_config;

/// Parsed result of Cloudflare's `cdn-cgi/trace` for one account.
#[derive(Clone, Debug, Default, Serialize)]
pub struct TraceInfo {
    pub ip: String,
    pub colo: String,
    /// Cloudflare trace 的 loc，例如 US。
    pub loc: String,
    /// `"on"` / `"off"` / `"plus"`.
    pub warp: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub err: Option<String>,
}

const TRACE_HOST: &str = "www.cloudflare.com";
/// 固定的 Cloudflare IPv4，用来观察 IPv4 出口，不经过隧道内 DNS。
pub const TRACE_V4: SocketAddr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(104, 16, 124, 96)), 443);
/// 固定的 Cloudflare IPv6。和 MicroWARP 的双栈观测使用同一个地址。
pub const TRACE_V6: SocketAddr = SocketAddr::new(
    IpAddr::V6(Ipv6Addr::new(0x2606, 0x4700, 0, 0, 0, 0, 0, 0x11)),
    443,
);

/// Fetch the egress trace through the tunnel.
pub async fn fetch_trace(net: &NetHandle) -> TraceInfo {
    fetch_trace_timeout(net, Duration::from_secs(15)).await
}

/// 在指定时间内拉取出口 trace。超时或失败都写进结果，不向外抛错。
pub async fn fetch_trace_timeout(net: &NetHandle, timeout: Duration) -> TraceInfo {
    let ip = match net.resolve(TRACE_HOST).await {
        Ok(ip) => ip,
        Err(err) => {
            return TraceInfo {
                err: Some(err),
                ..Default::default()
            }
        }
    };
    fetch_trace_at(net, SocketAddr::new(ip, 443), timeout).await
}

/// 连到指定地址拉取 trace，SNI 和 Host 仍是 www.cloudflare.com。
pub async fn fetch_trace_at(net: &NetHandle, target: SocketAddr, timeout: Duration) -> TraceInfo {
    match tokio::time::timeout(timeout, fetch_on(net, target)).await {
        Ok(Ok(info)) => info,
        Ok(Err(err)) => TraceInfo {
            err: Some(err),
            ..Default::default()
        },
        Err(_) => TraceInfo {
            err: Some("trace timeout".into()),
            ..Default::default()
        },
    }
}

/// 同时探测 IPv4 和 IPv6 出口。一条失败不影响另一条。
pub async fn fetch_egress(net: &NetHandle, timeout: Duration) -> (TraceInfo, TraceInfo) {
    tokio::join!(
        fetch_trace_at(net, TRACE_V4, timeout),
        fetch_trace_at(net, TRACE_V6, timeout),
    )
}

async fn fetch_on(net: &NetHandle, target: SocketAddr) -> Result<TraceInfo, String> {
    let conn = net.connect(target).await?;

    let cfg = insecure_client_config(&[b"http/1.1"]).map_err(|e| e.to_string())?;
    let connector = tokio_rustls::TlsConnector::from(Arc::new(cfg));
    let sni = rustls::pki_types::ServerName::try_from(TRACE_HOST).map_err(|e| e.to_string())?;
    let mut tls = connector
        .connect(sni, conn)
        .await
        .map_err(|e| e.to_string())?;

    let req = format!(
        "GET /cdn-cgi/trace HTTP/1.1\r\nHost: {TRACE_HOST}\r\nUser-Agent: warp-proxy\r\nAccept: */*\r\nConnection: close\r\n\r\n"
    );
    tls.write_all(req.as_bytes())
        .await
        .map_err(|e| e.to_string())?;

    let mut buf = Vec::new();
    tls.read_to_end(&mut buf).await.map_err(|e| e.to_string())?;
    let text = String::from_utf8_lossy(&buf);
    let body = text.split("\r\n\r\n").nth(1).unwrap_or("");

    parse_trace_body(body)
}

fn parse_trace_body(body: &str) -> Result<TraceInfo, String> {
    let mut info = TraceInfo::default();
    for line in body.lines() {
        if let Some((k, v)) = line.split_once('=') {
            match k {
                "ip" => info.ip = v.trim().to_string(),
                "warp" => info.warp = v.trim().to_string(),
                "colo" => info.colo = v.trim().to_string(),
                "loc" => info.loc = v.trim().to_string(),
                _ => {}
            }
        }
    }
    if info.ip.is_empty() && info.warp.is_empty() {
        return Err("no trace fields in response".into());
    }
    Ok(info)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_trace_fields() {
        let info = parse_trace_body(
            "ip=1.2.3.4
warp=on
loc=US
colo=SJC
",
        )
        .unwrap();
        assert_eq!(info.ip, "1.2.3.4");
        assert_eq!(info.warp, "on");
        assert_eq!(info.loc, "US");
        assert_eq!(info.colo, "SJC");
    }

    #[test]
    fn dual_stack_targets_are_numeric() {
        assert!(TRACE_V4.is_ipv4());
        assert_eq!(TRACE_V6.ip().to_string(), "2606:4700::11");
    }
}
