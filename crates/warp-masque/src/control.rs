//! 本机回环上的控制接口，用来查看状态、开关 WARP、轮换账号、重连、
//! 保身份重启、检测出口 IP，以及增删账号。`GET /` 同时提供管理页面。
//!
//! 只实现了够用的 HTTP/1.1，避免再加一套网页框架。除了管理页面本身，
//! 每个接口都要带 `X-Warp-Token`。页面可以被浏览器直接打开，但不能在里面
//! 放令牌，否则其它网站拿到页面就等于拿到控制权。

use std::sync::Arc;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

use crate::pool::Pool;

/// Serve the control API on `listener`, guarded by `token`.
pub async fn serve(listener: TcpListener, pool: Arc<Pool>, token: String) {
    let token = Arc::new(token);
    loop {
        let Ok((conn, _)) = listener.accept().await else {
            continue;
        };
        let pool = pool.clone();
        let token = token.clone();
        tokio::spawn(async move {
            let _ = handle(conn, pool, token).await;
        });
    }
}

async fn handle(mut conn: TcpStream, pool: Arc<Pool>, token: Arc<String>) -> std::io::Result<()> {
    // Read the request head (we don't need a body — args are query params).
    let mut buf = Vec::new();
    let mut tmp = [0u8; 2048];
    loop {
        let n = conn.read(&mut tmp).await?;
        if n == 0 {
            break;
        }
        buf.extend_from_slice(&tmp[..n]);
        if buf.windows(4).any(|w| w == b"\r\n\r\n") || buf.len() > 16 * 1024 {
            break;
        }
    }
    let head = String::from_utf8_lossy(&buf);
    let mut lines = head.split("\r\n");
    let request_line = lines.next().unwrap_or("");
    let mut parts = request_line.split_whitespace();
    let method = parts.next().unwrap_or("");
    let target = parts.next().unwrap_or("");

    // 浏览器预检不带令牌。
    if method == "OPTIONS" {
        return write_resp(&mut conn, "204 No Content", "").await;
    }

    let (path, query) = target.split_once('?').unwrap_or((target, ""));
    // 管理页面必须能被地址栏打开，所以这里不校验令牌。页面里没有密钥。
    if method == "GET" && is_panel_path(path) {
        return write_html(&mut conn, PANEL_HTML).await;
    }
    if method == "GET" {
        if let Some((content_type, body)) = panel_asset(path) {
            return write_asset(&mut conn, content_type, body).await;
        }
    }
    if method == "GET" && path == "/favicon.ico" {
        return write_resp(&mut conn, "204 No Content", "").await;
    }

    let presented = lines
        .find_map(|l| {
            let (k, v) = l.split_once(':')?;
            k.trim()
                .eq_ignore_ascii_case("x-warp-token")
                .then(|| v.trim().to_string())
        })
        .unwrap_or_default();
    if presented != *token {
        return write_json(&mut conn, "403 Forbidden", "{\"error\":\"forbidden\"}").await;
    }

    match route(&pool, path, query).await {
        Ok(body) => write_json(&mut conn, "200 OK", &body).await,
        Err(msg) => {
            let body = format!("{{\"error\":{}}}", json_string(&msg));
            write_json(&mut conn, "400 Bad Request", &body).await
        }
    }
}

/// Dispatch one API call, returning the JSON body to send.
async fn route(pool: &Arc<Pool>, path: &str, query: &str) -> Result<String, String> {
    match path {
        "/api/status" => {}
        "/api/sessions" => {
            return serde_json::to_string(&pool.sessions()).map_err(|e| e.to_string());
        }
        "/api/logs" => {
            return serde_json::to_string(&pool.logs()).map_err(|e| e.to_string());
        }
        "/api/toggle" => pool.set_enabled(bool_param(query, "on", true)),
        "/api/reconnect" => pool.reconnect(int_param(query, "slot").unwrap_or(0) as usize),
        "/api/restart" => {
            pool.restart(int_param(query, "slot").unwrap_or(0) as usize)
                .await?
        }
        "/api/restart-graceful" => {
            let queued = pool.queue_graceful_restart_all();
            return Ok(serde_json::json!({ "queued": queued }).to_string());
        }
        "/api/restart-plan" => {
            return Err("旧定时计划已移除，请使用 /api/restart-policy 配置三个独立阈值".into())
        }
        "/api/restart-policy" => {
            if param(query, "mode").is_some() || param(query, "threshold").is_some() {
                return Err("旧 mode/threshold 参数已移除，请使用 max_uptime_seconds、max_users、max_connections".into());
            }
            let uptime = u64_param(query, "max_uptime_seconds")?;
            let users = usize_param(query, "max_users")?;
            let connections = u64_param(query, "max_connections")?;
            let drain_timeout = u64_param(query, "drain_timeout_seconds")?;
            if uptime.is_none()
                && users.is_none()
                && connections.is_none()
                && drain_timeout.is_none()
            {
                return Err("至少需要 max_uptime_seconds、max_users、max_connections 或 drain_timeout_seconds".into());
            }
            pool.set_restart_policy(
                uptime.map(std::time::Duration::from_secs),
                users,
                connections,
                drain_timeout.map(std::time::Duration::from_secs),
            )?;
        }
        "/api/rotate" => pool
            .rotate(int_param(query, "slot").unwrap_or(0) as usize)
            .await
            .map_err(|e| e.to_string())?,
        "/api/http2" => pool.set_http2(bool_param(query, "on", false)),
        "/api/interval" => {
            let secs = int_param(query, "seconds").unwrap_or(0).max(0) as u64;
            pool.set_rotate_interval(secs);
        }
        "/api/trace" => {
            pool.refresh_trace(int_param(query, "slot").unwrap_or(0) as usize)
                .await
        }
        "/api/account/add" => {
            let count = int_param(query, "count").unwrap_or(1);
            if count < 1 {
                return Err("添加数量至少为 1".into());
            }
            pool.add_accounts(bool_param(query, "temporary", false), count as usize)
                .await
                .map_err(|e| e.to_string())?;
        }
        "/api/account/manual" => {
            let slot = int_param(query, "slot").ok_or("missing slot")? as usize;
            pool.set_manual(slot, bool_param(query, "on", true))
                .map_err(|e| e.to_string())?;
        }
        "/api/account/remove" => {
            let slot = int_param(query, "slot").ok_or("missing slot")? as usize;
            pool.remove_account(slot).map_err(|e| e.to_string())?;
        }
        _ => return Err(format!("no such endpoint {path}")),
    }
    serde_json::to_string(&pool.status()).map_err(|e| e.to_string())
}

fn bool_param(query: &str, key: &str, default: bool) -> bool {
    match param(query, key).as_deref() {
        Some("1" | "true" | "on" | "yes") => true,
        Some("0" | "false" | "off" | "no") => false,
        _ => default,
    }
}

fn int_param(query: &str, key: &str) -> Option<i64> {
    param(query, key)?.parse().ok()
}

fn u64_param(query: &str, key: &str) -> Result<Option<u64>, String> {
    param(query, key)
        .map(|value| {
            value
                .parse::<u64>()
                .map_err(|_| format!("{key} 必须是非负整数"))
        })
        .transpose()
}

fn usize_param(query: &str, key: &str) -> Result<Option<usize>, String> {
    param(query, key)
        .map(|value| {
            value
                .parse::<usize>()
                .map_err(|_| format!("{key} 必须是非负整数"))
        })
        .transpose()
}

fn param(query: &str, key: &str) -> Option<String> {
    query.split('&').find_map(|pair| {
        let (k, v) = pair.split_once('=')?;
        (k == key).then(|| v.to_string())
    })
}

fn json_string(s: &str) -> String {
    let escaped = s
        .replace('\\', "\\\\")
        .replace('"', "\\\"")
        .replace('\n', " ");
    format!("\"{escaped}\"")
}

async fn write_json(conn: &mut TcpStream, status: &str, body: &str) -> std::io::Result<()> {
    let resp = format!(
        "HTTP/1.1 {status}\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\
         Access-Control-Allow-Origin: *\r\nAccess-Control-Allow-Headers: content-type, x-warp-token\r\n\
         Access-Control-Allow-Methods: GET, POST, OPTIONS\r\nCache-Control: no-store\r\nConnection: close\r\n\r\n{body}",
        body.len()
    );
    conn.write_all(resp.as_bytes()).await
}

const PANEL_HTML: &str = include_str!("panel.html");

fn panel_asset(path: &str) -> Option<(&'static str, &'static [u8])> {
    match path {
        "/assets/bootstrap.min.css" => Some((
            "text/css; charset=utf-8",
            include_bytes!("assets/bootstrap.min.css"),
        )),
        "/assets/bootstrap.bundle.min.js" => Some((
            "text/javascript; charset=utf-8",
            include_bytes!("assets/bootstrap.bundle.min.js"),
        )),
        _ => None,
    }
}

/// 管理页面只挂在这两个路径上，避免把接口误当成网页。
fn is_panel_path(path: &str) -> bool {
    matches!(path, "/" | "/panel" | "/panel/")
}

async fn write_asset(conn: &mut TcpStream, content_type: &str, body: &[u8]) -> std::io::Result<()> {
    let head = format!(
        "HTTP/1.1 200 OK
Content-Type: {content_type}
Content-Length: {}
Cache-Control: public, max-age=86400
Connection: close

",
        body.len()
    );
    conn.write_all(head.as_bytes()).await?;
    conn.write_all(body).await
}

async fn write_html(conn: &mut TcpStream, body: &str) -> std::io::Result<()> {
    let resp = format!(
        "HTTP/1.1 200 OK
Content-Type: text/html; charset=utf-8
Content-Length: {}
         Cache-Control: no-store
Connection: close

{body}",
        body.len()
    );
    conn.write_all(resp.as_bytes()).await
}

async fn write_resp(conn: &mut TcpStream, status: &str, body: &str) -> std::io::Result<()> {
    let resp = format!(
        "HTTP/1.1 {status}\r\nContent-Length: {}\r\nAccess-Control-Allow-Origin: *\r\n\
         Access-Control-Allow-Headers: content-type, x-warp-token\r\n\
         Access-Control-Allow-Methods: GET, POST, OPTIONS\r\nConnection: close\r\n\r\n{body}",
        body.len()
    );
    conn.write_all(resp.as_bytes()).await
}

#[cfg(test)]
mod tests {
    use super::{is_panel_path, panel_asset, PANEL_HTML};

    #[tokio::test]
    async fn graceful_restart_route_returns_queue_count() {
        let pool = crate::pool::Pool::start(Vec::new(), crate::pool::PoolOptions::basic(false))
            .await
            .unwrap();
        let response = super::route(&pool, "/api/restart-graceful", "")
            .await
            .unwrap();
        assert_eq!(response, r#"{"queued":0}"#);
    }

    #[tokio::test]
    async fn restart_policy_route_accepts_drain_timeout_alone() {
        let pool = crate::pool::Pool::start(Vec::new(), crate::pool::PoolOptions::basic(false))
            .await
            .unwrap();
        let response = super::route(&pool, "/api/restart-policy", "drain_timeout_seconds=10")
            .await
            .unwrap();
        assert!(response.contains("\"restart_drain_timeout_seconds\":10"));
    }

    #[test]
    fn panel_paths_are_only_the_html_pages() {
        assert!(is_panel_path("/"));
        assert!(is_panel_path("/panel"));
        assert!(is_panel_path("/panel/"));
        assert!(!is_panel_path("/api/status"));
        assert!(!is_panel_path("/panel/extra"));
    }

    #[test]
    fn panel_html_uses_the_control_api_without_embedding_a_token() {
        for path in [
            "/api/status",
            "/api/toggle",
            "/api/restart",
            "/api/restart-graceful",
            "/api/restart-policy",
            "/api/account/add",
            "/api/account/manual",
            "/api/logs",
            "/api/sessions",
            "/api/account/remove",
        ] {
            assert!(PANEL_HTML.contains(path), "{path}");
        }
        assert!(PANEL_HTML.contains("X-Warp-Token"));
        assert!(PANEL_HTML.contains("立即触发重启"));
        assert!(PANEL_HTML.contains("检测出口 IP"));
        assert!(PANEL_HTML.contains("restart-drain-timeout"));
        assert!(PANEL_HTML.contains("drain_timeout_seconds="));
        assert!(!PANEL_HTML.contains("rotate-seconds"));
        assert!(!PANEL_HTML.contains(r#"data-act="rotate""#));
        assert!(!PANEL_HTML.contains(r#"data-act="interval""#));
        assert!(PANEL_HTML.contains("temporary=1&count="));
        assert!(PANEL_HTML.contains("localStorage"));
        assert!(PANEL_HTML.contains("warp-token"));
        assert!(PANEL_HTML.contains("writeCachedToken(state.token)"));
        assert!(PANEL_HTML.contains("/assets/bootstrap.min.css"));
        assert!(PANEL_HTML.contains("/assets/bootstrap.bundle.min.js"));
        assert!(!PANEL_HTML.contains("controlToken"));
        assert!(panel_asset("/assets/bootstrap.min.css").is_some());
        assert!(panel_asset("/assets/bootstrap.bundle.min.js").is_some());
        assert!(panel_asset("/api/status").is_none());
    }
}
