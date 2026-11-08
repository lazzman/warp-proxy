//! 标准 SOCKS5 CONNECT 上游。只走 TCP，不使用 UDP Associate。
//!
//! 注册请求和 MASQUE HTTP/2 都经这里拨到 Cloudflare。探测失败时调用方必须
//! 拒绝直连，不能静默退回本机网络。

use std::fmt;
use std::net::SocketAddr;
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

/// 一个上游 SOCKS5 代理。密码只用于拨号，日志请用 [`UpstreamProxy::redacted`]。
#[derive(Clone)]
pub struct UpstreamProxy {
    pub host: String,
    pub port: u16,
    pub username: Option<String>,
    pub password: Option<String>,
}

impl fmt::Debug for UpstreamProxy {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.redacted())
    }
}

impl UpstreamProxy {
    /// 不含密码的地址，可写入日志。
    pub fn redacted(&self) -> String {
        match &self.username {
            Some(user) => format!("socks5://{user}:***@{}:{}", self.host, self.port),
            None => format!("socks5://{}:{}", self.host, self.port),
        }
    }

    /// reqwest 使用的 URL。`socks5h` 把注册域名交给上游解析。
    pub fn reqwest_url(&self) -> String {
        let host = if self.host.contains(':') {
            format!("[{}]", self.host)
        } else {
            self.host.clone()
        };
        match (&self.username, &self.password) {
            (Some(user), Some(pass)) => format!(
                "socks5h://{}:{}@{host}:{}",
                encode_userinfo(user),
                encode_userinfo(pass),
                self.port
            ),
            _ => format!("socks5h://{host}:{}", self.port),
        }
    }
}

/// 按账号稳定分配的上游列表。
#[derive(Clone, Debug, Default)]
pub struct UpstreamSet {
    proxies: Vec<UpstreamProxy>,
}

impl UpstreamSet {
    pub fn parse(raw: &str) -> Result<Self, String> {
        let mut proxies = Vec::new();
        for part in raw.split([',', '\n', ' ']) {
            let part = part.trim();
            if part.is_empty() {
                continue;
            }
            proxies.push(parse_proxy(part)?);
        }
        Ok(Self { proxies })
    }

    pub fn is_empty(&self) -> bool {
        self.proxies.is_empty()
    }

    /// `index` 从 0 开始。同一序号始终落到同一上游。
    pub fn for_index(&self, index: usize) -> Option<UpstreamProxy> {
        if self.proxies.is_empty() {
            None
        } else {
            Some(self.proxies[index % self.proxies.len()].clone())
        }
    }

    /// 对每个不同的上游做一次 SOCKS5 CONNECT，确认 TCP 路径可用。
    pub async fn probe(&self, target: SocketAddr, timeout: Duration) -> Result<(), String> {
        let mut seen = Vec::new();
        for proxy in &self.proxies {
            if seen
                .iter()
                .any(|item: &UpstreamProxy| same_proxy(item, proxy))
            {
                continue;
            }
            seen.push(proxy.clone());
            let proxy = proxy.clone();
            let result = tokio::time::timeout(timeout, connect_via(&proxy, target)).await;
            match result {
                Ok(Ok(stream)) => drop(stream),
                Ok(Err(err)) => {
                    return Err(format!("{} 连接 {target} 失败: {err}", proxy.redacted()));
                }
                Err(_) => {
                    return Err(format!("{} 连接 {target} 超时", proxy.redacted()));
                }
            }
        }
        Ok(())
    }
}

fn same_proxy(left: &UpstreamProxy, right: &UpstreamProxy) -> bool {
    left.host == right.host && left.port == right.port && left.username == right.username
}

/// 经 SOCKS5 CONNECT 连到 `target`。调用方拿到的是已接通的 TCP 流。
pub async fn connect_via(proxy: &UpstreamProxy, target: SocketAddr) -> std::io::Result<TcpStream> {
    let connect = TcpStream::connect((proxy.host.as_str(), proxy.port));
    let mut stream = tokio::time::timeout(Duration::from_secs(20), connect)
        .await
        .map_err(|_| std::io::Error::new(std::io::ErrorKind::TimedOut, "连接上游超时"))??;
    stream.set_nodelay(true).ok();

    let method = if proxy.username.is_some() { 0x02 } else { 0x00 };
    stream.write_all(&[0x05, 0x01, method]).await?;
    let mut chosen = [0u8; 2];
    stream.read_exact(&mut chosen).await?;
    if chosen[0] != 0x05 {
        return Err(proto("上游返回了非 SOCKS5 握手"));
    }
    if chosen[1] == 0x02 {
        write_userpass(&mut stream, proxy).await?;
    } else if chosen[1] != 0x00 {
        return Err(proto("上游拒绝了提供的认证方式"));
    }

    stream.write_all(&connect_request(target)).await?;
    let mut header = [0u8; 4];
    stream.read_exact(&mut header).await?;
    if header[1] != 0x00 {
        return Err(proto(format!("上游 CONNECT 失败，回复码 {}", header[1])));
    }
    let addr_len = match header[3] {
        0x01 => 4,
        0x04 => 16,
        0x03 => {
            let mut len = [0u8; 1];
            stream.read_exact(&mut len).await?;
            len[0] as usize
        }
        other => return Err(proto(format!("上游返回了未知地址类型 {other}"))),
    };
    let mut bound = vec![0u8; addr_len + 2];
    stream.read_exact(&mut bound).await?;
    Ok(stream)
}

async fn write_userpass(stream: &mut TcpStream, proxy: &UpstreamProxy) -> std::io::Result<()> {
    let user = proxy.username.as_deref().unwrap_or("");
    let pass = proxy.password.as_deref().unwrap_or("");
    if user.len() > 255 || pass.len() > 255 {
        return Err(proto("上游用户名或密码超过 255 字节"));
    }
    let mut body = Vec::with_capacity(3 + user.len() + pass.len());
    body.push(0x01);
    body.push(user.len() as u8);
    body.extend_from_slice(user.as_bytes());
    body.push(pass.len() as u8);
    body.extend_from_slice(pass.as_bytes());
    stream.write_all(&body).await?;
    let mut reply = [0u8; 2];
    stream.read_exact(&mut reply).await?;
    if reply[1] != 0x00 {
        return Err(proto("上游认证失败"));
    }
    Ok(())
}

fn connect_request(target: SocketAddr) -> Vec<u8> {
    let mut req = vec![0x05, 0x01, 0x00];
    match target {
        SocketAddr::V4(addr) => {
            req.push(0x01);
            req.extend_from_slice(&addr.ip().octets());
        }
        SocketAddr::V6(addr) => {
            req.push(0x04);
            req.extend_from_slice(&addr.ip().octets());
        }
    }
    req.extend_from_slice(&target.port().to_be_bytes());
    req
}

fn parse_proxy(raw: &str) -> Result<UpstreamProxy, String> {
    let raw = raw
        .trim()
        .trim_start_matches("socks5h://")
        .trim_start_matches("socks5://");
    let (auth, hostport) = match raw.rsplit_once('@') {
        Some((auth, hostport)) => (Some(auth), hostport),
        None => (None, raw),
    };
    let (host, port) = split_host_port(hostport)?;
    let (username, password) = match auth {
        Some(auth) => {
            let (user, pass) = auth.split_once(':').unwrap_or((auth, ""));
            (Some(percent_decode(user)?), Some(percent_decode(pass)?))
        }
        None => (None, None),
    };
    if host.is_empty() {
        return Err(format!("上游地址缺少主机: {raw}"));
    }
    Ok(UpstreamProxy {
        host,
        port,
        username,
        password,
    })
}

fn split_host_port(raw: &str) -> Result<(String, u16), String> {
    if let Some(rest) = raw.strip_prefix('[') {
        let (host, port) = rest
            .split_once(']')
            .ok_or_else(|| format!("IPv6 上游地址缺少括号: {raw}"))?;
        let port = port
            .strip_prefix(':')
            .ok_or_else(|| format!("IPv6 上游地址缺少端口: {raw}"))?;
        let port = port.parse().map_err(|_| format!("上游端口无效: {raw}"))?;
        return Ok((host.to_string(), port));
    }
    let (host, port) = raw
        .rsplit_once(':')
        .ok_or_else(|| format!("上游地址缺少端口: {raw}"))?;
    let port = port.parse().map_err(|_| format!("上游端口无效: {raw}"))?;
    Ok((host.to_string(), port))
}

fn encode_userinfo(value: &str) -> String {
    let mut out = String::new();
    for byte in value.bytes() {
        match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'.' | b'_' | b'~' => {
                out.push(byte as char)
            }
            _ => out.push_str(&format!("%{byte:02X}")),
        }
    }
    out
}

fn percent_decode(value: &str) -> Result<String, String> {
    let bytes = value.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut index = 0;
    while index < bytes.len() {
        if bytes[index] == b'%' {
            if index + 2 >= bytes.len() {
                return Err(format!("上游地址百分号编码不完整: {value}"));
            }
            let hex = std::str::from_utf8(&bytes[index + 1..index + 3])
                .map_err(|_| format!("上游地址百分号编码无效: {value}"))?;
            let byte = u8::from_str_radix(hex, 16)
                .map_err(|_| format!("上游地址百分号编码无效: {value}"))?;
            out.push(byte);
            index += 3;
        } else {
            out.push(bytes[index]);
            index += 1;
        }
    }
    String::from_utf8(out).map_err(|_| format!("上游地址不是 UTF-8: {value}"))
}

fn proto(message: impl Into<String>) -> std::io::Error {
    std::io::Error::new(std::io::ErrorKind::InvalidData, message.into())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_single_and_list() {
        let one = UpstreamSet::parse("10.0.160.176:20120").unwrap();
        assert_eq!(one.for_index(0).unwrap().port, 20120);
        assert!(one.for_index(0).unwrap().username.is_none());

        let many = UpstreamSet::parse(
            "socks5://alice:p%40ss@10.0.0.1:1080, socks5://bob:secret@[2001:db8::1]:1080",
        )
        .unwrap();
        let first = many.for_index(0).unwrap();
        assert_eq!(first.username.as_deref(), Some("alice"));
        assert_eq!(first.password.as_deref(), Some("p@ss"));
        assert_eq!(many.for_index(1).unwrap().host, "2001:db8::1");
        assert_eq!(many.for_index(2).unwrap().host, first.host);
        assert!(!first.redacted().contains("p@ss"));
        assert!(first
            .reqwest_url()
            .starts_with("socks5h://alice:p%40ss@10.0.0.1:1080"));
    }

    #[test]
    fn connect_request_uses_numeric_address() {
        let req = connect_request("162.159.198.2:443".parse().unwrap());
        assert_eq!(req, vec![5, 1, 0, 1, 162, 159, 198, 2, 0x01, 0xbb]);
    }
}
