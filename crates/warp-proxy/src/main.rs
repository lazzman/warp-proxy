//! warp-proxy 守护进程：注册或加载一组 WARP 账号，前面放一个本地代理，并用控制接口管理出口。
//!
//! 启动后往 stdout 打一行 JSON，方便父进程发现端口和令牌：
//!
//! {"socksPort":1080,"controlUrl":"http://127.0.0.1:47100","controlToken":"…","panelUrl":"http://127.0.0.1:47100/"}
//!
//! 其余日志都在 stderr。收到 SIGINT 或 SIGTERM 后退出。

use std::net::{Ipv4Addr, SocketAddr};
use std::path::PathBuf;
use std::time::Duration;

use anyhow::Context;
use tokio::net::TcpListener;

use warp_masque::{
    control, parse_misfire, parse_sticky, parse_strategy, socks, Misfire, Policy, Pool,
    PoolOptions, ProxyAuth, RegistrationClient, ResolvePreference, RestartConfig, UpstreamProxy,
    UpstreamSet, WarpConfig,
};

struct Args {
    accounts: usize,
    socks: String,
    control: String,
    state_dir: Option<PathBuf>,
    microwarp_dir: Option<PathBuf>,
    microwarp_scan_interval: Duration,
    http2: bool,
    upstream: String,
    access_log: bool,
    strategy: String,
    sticky: String,
    lb_rotate: Duration,
    restart_interval: Duration,
    restart_force_after: Duration,
    restart_misfire: Misfire,
    restart_probe: Duration,
    restart_concurrency: usize,
    restart_batch: usize,
    restart_defer: Duration,
    resolve: String,
    socks_user: Option<String>,
    socks_pass: Option<String>,
    control_password: String,
    mixed: bool,
    upstream_probe: Duration,
    health_interval: Duration,
    health_timeout: Duration,
}

fn parse_args() -> anyhow::Result<Args> {
    let env_force_after = env_string("ROTATE_RESTART_FORCE_AFTER");
    let env_drain_timeout = env_string("ROTATE_RESTART_DRAIN_TIMEOUT");
    let mut args = Args {
        accounts: env_usize("INSTANCE_COUNT", 2),
        socks: env_string("BIND_ADDR").unwrap_or_else(|| "127.0.0.1".into()),
        control: env_string("CONTROL_ADDR").unwrap_or_else(|| "127.0.0.1".into()),
        state_dir: env_string("STATE_DIR").map(PathBuf::from),
        microwarp_dir: env_string("MICROWARP_DIR").map(PathBuf::from),
        microwarp_scan_interval: env_duration("MICROWARP_SCAN_INTERVAL", Duration::from_secs(60))?,
        http2: env_bool("MASQUE_HTTP2", false),
        upstream: env_string("UPSTREAM_SOCKS5").unwrap_or_default(),
        access_log: env_bool("LB_ACCESS_LOG", false),
        strategy: env_string("LB_STRATEGY").unwrap_or_else(|| "round".into()),
        sticky: env_string("LB_STICKY_MODE").unwrap_or_else(|| "username-round".into()),
        lb_rotate: env_duration("LB_ROTATE_INTERVAL", Duration::from_secs(300))?,
        restart_interval: env_duration("ROTATE_RESTART_INTERVAL", Duration::ZERO)?,
        restart_force_after: Duration::from_secs(600),
        restart_misfire: parse_misfire(
            &env_string("ROTATE_RESTART_MISFIRE").unwrap_or_else(|| "fire".into()),
        )
        .map_err(anyhow::Error::msg)?,
        restart_probe: env_duration("ROTATE_RESTART_PROBE_TIMEOUT", Duration::from_secs(90))?,
        restart_concurrency: env_usize("ROTATE_RESTART_CONCURRENCY", 1).max(1),
        restart_batch: env_usize("ROTATE_RESTART_BATCH", 1),
        restart_defer: env_duration("ROTATE_RESTART_DEFER", Duration::ZERO)?,
        resolve: env_string("RESOLVE_PREFERENCE").unwrap_or_else(|| "auto".into()),
        socks_user: env_string("SOCKS_USER"),
        socks_pass: env_string("SOCKS_PASS"),
        control_password: resolve_control_password(env_string("CONTROL_PASSWORD").as_deref()),
        mixed: matches!(
            env_string("PROXY_MODE")
                .unwrap_or_else(|| "socks5".into())
                .to_ascii_lowercase()
                .as_str(),
            "mixed" | "http"
        ),
        upstream_probe: env_duration("UPSTREAM_PROBE_TIMEOUT", Duration::from_secs(8))?,
        health_interval: env_duration("HEALTH_CHECK_INTERVAL", Duration::from_secs(60))?,
        health_timeout: env_duration("HEALTH_CHECK_TIMEOUT", Duration::from_secs(20))?,
    };
    // BIND_PORT / CONTROL_PORT 覆盖端口。地址可以只写主机，也可以写成 host:port。
    let socks_port = env_string("BIND_PORT");
    let control_port = env_string("CONTROL_PORT");
    args.socks = apply_bind(&args.socks, socks_port.as_deref(), "1080");
    args.control = apply_bind(&args.control, control_port.as_deref(), "47100");

    let mut it = std::env::args().skip(1);
    let mut force_after_flag = None;
    let mut drain_flag = None;
    while let Some(arg) = it.next() {
        match arg.as_str() {
            "--accounts" => {
                args.accounts = next_value(&mut it, &arg)?.parse().context("--accounts")?
            }
            "--socks" => args.socks = next_value(&mut it, &arg)?,
            "--control" => args.control = next_value(&mut it, &arg)?,
            "--state-dir" => args.state_dir = Some(PathBuf::from(next_value(&mut it, &arg)?)),
            "--microwarp-dir" => {
                args.microwarp_dir = Some(PathBuf::from(next_value(&mut it, &arg)?))
            }
            "--microwarp-scan-interval" => {
                args.microwarp_scan_interval = parse_duration(&next_value(&mut it, &arg)?)?
            }
            "--http2" => args.http2 = true,
            "--upstream" => args.upstream = next_value(&mut it, &arg)?,
            "--access-log" => args.access_log = true,
            "--no-access-log" => args.access_log = false,
            "--strategy" => args.strategy = next_value(&mut it, &arg)?,
            "--sticky" => args.sticky = next_value(&mut it, &arg)?,
            "--lb-rotate" => args.lb_rotate = parse_duration(&next_value(&mut it, &arg)?)?,
            "--restart-interval" => {
                args.restart_interval = parse_duration(&next_value(&mut it, &arg)?)?
            }
            "--restart-force-after" => {
                remember_force_after_flag(
                    &arg,
                    parse_duration(&next_value(&mut it, &arg)?)?,
                    &mut force_after_flag,
                    &mut drain_flag,
                );
            }
            "--restart-drain" => {
                remember_force_after_flag(
                    &arg,
                    parse_duration(&next_value(&mut it, &arg)?)?,
                    &mut force_after_flag,
                    &mut drain_flag,
                );
            }
            "--restart-retries" => {
                let _ = next_value(&mut it, &arg)?;
                eprintln!("[warp-proxy] 已忽略 --restart-retries：会一直重试，直到 warp=on");
            }
            "--restart-misfire" => {
                args.restart_misfire = parse_misfire(&next_value(&mut it, &arg)?)
                    .map_err(anyhow::Error::msg)
                    .context("--restart-misfire")?;
            }
            "--restart-probe-timeout" => {
                args.restart_probe = parse_duration(&next_value(&mut it, &arg)?)?
            }
            "--restart-concurrency" => {
                args.restart_concurrency = next_value(&mut it, &arg)?
                    .parse::<usize>()
                    .context("--restart-concurrency")?
                    .max(1)
            }
            "--restart-batch" => {
                args.restart_batch = next_value(&mut it, &arg)?
                    .parse()
                    .context("--restart-batch")?
            }
            "--restart-defer" => args.restart_defer = parse_duration(&next_value(&mut it, &arg)?)?,
            "--resolve" => args.resolve = next_value(&mut it, &arg)?,
            "--socks-user" => args.socks_user = Some(next_value(&mut it, &arg)?),
            "--socks-pass" => args.socks_pass = Some(next_value(&mut it, &arg)?),
            "--control-password" => args.control_password = next_value(&mut it, &arg)?,
            "--proxy-mode" => {
                let mode = next_value(&mut it, &arg)?.to_ascii_lowercase();
                args.mixed = match mode.as_str() {
                    "socks5" | "socks" => false,
                    "mixed" | "http" => true,
                    other => anyhow::bail!("未知 PROXY_MODE={other}（socks5|mixed）"),
                };
            }
            "--upstream-probe-timeout" => {
                args.upstream_probe = parse_duration(&next_value(&mut it, &arg)?)?
            }
            "--health-interval" => {
                args.health_interval = parse_duration(&next_value(&mut it, &arg)?)?
            }
            "--health-timeout" => {
                args.health_timeout = parse_duration(&next_value(&mut it, &arg)?)?
            }
            other => eprintln!("[warp-proxy] 忽略未知参数 {other:?}"),
        }
    }
    let (force_after, notices) = resolve_force_after_sources(
        force_after_flag,
        env_force_after.as_deref(),
        drain_flag,
        env_drain_timeout.as_deref(),
    )?;
    args.restart_force_after = force_after;
    for notice in notices {
        eprintln!("[warp-proxy] {notice}");
    }
    if std::env::var_os("ROTATE_RESTART_RETRIES").is_some() {
        eprintln!("[warp-proxy] 已忽略 ROTATE_RESTART_RETRIES：会一直重试，直到 warp=on");
    }
    args.accounts = args.accounts.max(1);
    if env_flag_off("ROTATE_RESTART_ENABLED") {
        args.restart_interval = Duration::ZERO;
    }
    Ok(args)
}

/// 新旧名字同时出现时保留新值，命令行再覆盖同名的环境变量。
/// 只有旧名字时仍采用旧值。新值来源优先于旧值，坏的旧值不会顶替合法的新值。
fn resolve_force_after_sources(
    cli_current: Option<Duration>,
    env_current: Option<&str>,
    cli_legacy: Option<Duration>,
    env_legacy: Option<&str>,
) -> anyhow::Result<(Duration, Vec<String>)> {
    let current = match cli_current {
        Some(value) => Some(value),
        None => parse_optional_duration(env_current)?,
    };
    if let Some(value) = current {
        let mut notices = Vec::new();
        if env_legacy.is_some() {
            notices.push(
                "已忽略 ROTATE_RESTART_DRAIN_TIMEOUT：请改用 ROTATE_RESTART_FORCE_AFTER".into(),
            );
        }
        if cli_legacy.is_some() {
            notices.push("已忽略 --restart-drain：请改用 --restart-force-after".into());
        }
        return Ok((value, notices));
    }
    if let Some(value) = cli_legacy {
        return Ok((
            value,
            vec!["--restart-drain 已弃用，请改用 --restart-force-after".into()],
        ));
    }
    if let Some(value) = parse_optional_duration(env_legacy)? {
        return Ok((
            value,
            vec!["ROTATE_RESTART_DRAIN_TIMEOUT 已弃用，请改用 ROTATE_RESTART_FORCE_AFTER".into()],
        ));
    }
    Ok((Duration::from_secs(660), Vec::new()))
}

fn parse_optional_duration(value: Option<&str>) -> anyhow::Result<Option<Duration>> {
    value.map(parse_duration).transpose()
}

fn remember_force_after_flag(
    name: &str,
    value: Duration,
    current: &mut Option<Duration>,
    legacy: &mut Option<Duration>,
) {
    match name {
        "--restart-force-after" => *current = Some(value),
        "--restart-drain" => *legacy = Some(value),
        _ => {}
    }
}

/// 把主机或 host:port 收成最终监听地址。端口环境变量优先于地址里自带的端口。
fn apply_bind(addr: &str, port_override: Option<&str>, default_port: &str) -> String {
    let addr = addr.trim();
    let (host, port) = match addr.rsplit_once(':') {
        Some((host, port))
            if !port.is_empty() && port.bytes().all(|byte| byte.is_ascii_digit()) =>
        {
            let host = if host.is_empty() { "0.0.0.0" } else { host };
            (host, port)
        }
        _ => {
            let host = if addr.is_empty() { "0.0.0.0" } else { addr };
            (host, default_port)
        }
    };
    let port = port_override
        .filter(|port| !port.is_empty())
        .unwrap_or(port);
    format!("{host}:{port}")
}

fn next_value(it: &mut impl Iterator<Item = String>, flag: &str) -> anyhow::Result<String> {
    it.next().with_context(|| format!("{flag} 缺少取值"))
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let mut args = parse_args()?;
    if args.microwarp_dir.is_some() && args.state_dir.is_none() {
        anyhow::bail!("使用 MICROWARP_DIR/--microwarp-dir 时必须设置 STATE_DIR/--state-dir");
    }
    let microwarp_source = args.state_dir.as_ref().map(|state_dir| {
        args.microwarp_dir
            .clone()
            .unwrap_or_else(|| state_dir.join("instances"))
    });
    if let (Some(state_dir), Some(source)) = (&args.state_dir, &microwarp_source) {
        warp_masque::migration::migrate_microwarp(state_dir, source, args.accounts)
            .with_context(|| format!("迁移 MicroWARP 目录 {}", source.display()))?;
    }
    let upstream = UpstreamSet::parse(&args.upstream)
        .map_err(anyhow::Error::msg)
        .context("解析 UPSTREAM_SOCKS5")?;
    if !upstream.is_empty() && !args.http2 {
        eprintln!("[warp-proxy] 检测到上游 SOCKS5，自动启用 HTTP/2");
        args.http2 = true;
    }
    if !upstream.is_empty() {
        let target = SocketAddr::from((Ipv4Addr::new(162, 159, 198, 2), 443));
        upstream
            .probe(target, args.upstream_probe)
            .await
            .map_err(anyhow::Error::msg)
            .context("上游 SOCKS5 探测失败，已拒绝直连")?;
    }

    let configs = load_or_register(args.state_dir.as_deref(), args.accounts, &upstream)
        .await
        .context("准备账号")?;
    let auth = match (args.socks_user.clone(), args.socks_pass.clone()) {
        (Some(username), Some(password)) => Some(ProxyAuth { username, password }),
        (None, None) => None,
        _ => anyhow::bail!("SOCKS_USER 和 SOCKS_PASS 需要同时设置"),
    };
    let options = PoolOptions {
        http2: args.http2,
        upstream,
        upstream_probe_timeout: args.upstream_probe,
        policy: Policy {
            strategy: parse_strategy(&args.strategy).map_err(anyhow::Error::msg)?,
            sticky: parse_sticky(&args.sticky).map_err(anyhow::Error::msg)?,
            rotate_every: args.lb_rotate,
        },
        resolve: ResolvePreference::parse(&args.resolve).map_err(anyhow::Error::msg)?,
        auth,
        mixed: args.mixed,
        access_log: args.access_log,
        restart: RestartConfig {
            interval: args.restart_interval,
            probe_timeout: args.restart_probe,
            misfire: args.restart_misfire,
            force_after: args.restart_force_after,
            concurrency: args.restart_concurrency,
            batch: args.restart_batch,
            defer: args.restart_defer,
        },
        health_interval: args.health_interval,
        health_timeout: args.health_timeout,
        device_name: "warp-proxy".into(),
        state_dir: args.state_dir.clone(),
        auto_restore_limit: Some(args.accounts),
    };
    let pool = Pool::start(configs, options).await.context("启动连接池")?;

    let token = args.control_password.clone();
    let socks_listener = TcpListener::bind(&args.socks)
        .await
        .with_context(|| format!("绑定代理 {}", args.socks))?;
    let control_listener = TcpListener::bind(&args.control)
        .await
        .with_context(|| format!("绑定控制接口 {}", args.control))?;
    let socks_addr = socks_listener.local_addr()?;
    pool.set_listen(socks_addr.to_string());
    let socks_port = socks_addr.port();
    let control_addr = control_listener.local_addr()?;
    let handshake = serde_json::json!({
        "socksPort": socks_port,
        "controlUrl": format!("http://{control_addr}"),
        "controlToken": token,
        "panelUrl": format!("http://{control_addr}/"),
    });
    println!("{handshake}");
    use std::io::Write;
    let _ = std::io::stdout().flush();
    let health = if args.health_interval.is_zero() {
        "关".to_string()
    } else {
        format!("{}s", args.health_interval.as_secs())
    };
    eprintln!(
        "[warp-proxy] 代理 {} · 控制 http://{control_addr} · 面板 http://{control_addr}/ · http2={} · mixed={} · 出口检查={health}",
        socks_listener.local_addr()?,
        args.http2,
        args.mixed
    );

    if let Some(source) = microwarp_source.filter(|_| !args.microwarp_scan_interval.is_zero()) {
        let pool = pool.clone();
        let interval = args.microwarp_scan_interval;
        tokio::spawn(async move {
            let mut timer =
                tokio::time::interval_at(tokio::time::Instant::now() + interval, interval);
            loop {
                timer.tick().await;
                if let Err(err) = pool.scan_microwarp(&source).await {
                    eprintln!(
                        "[migration] 扫描 {} 失败，稍后重试: {err}",
                        source.display()
                    );
                }
            }
        });
    }

    tokio::spawn(control::serve(control_listener, pool.clone(), token));
    tokio::spawn(socks::serve_pool(socks_listener, pool));
    shutdown_signal().await;
    eprintln!("[warp-proxy] 正在退出");
    Ok(())
}

async fn load_or_register(
    state_dir: Option<&std::path::Path>,
    count: usize,
    upstream: &UpstreamSet,
) -> anyhow::Result<Vec<WarpConfig>> {
    let mut out = Vec::with_capacity(count);
    for index in 1..=count {
        let opts = warp_masque::RegisterOptions {
            device_name: Some(format!("warp-proxy-{index}")),
            ..Default::default()
        };
        if let Some(dir) = state_dir {
            let path = dir.join(format!("account-{index}.json"));
            if path.exists() {
                eprintln!("[warp-proxy] 加载账号 {index}: {}", path.display());
                out.push(
                    WarpConfig::load(&path).with_context(|| format!("加载 {}", path.display()))?,
                );
                continue;
            }
            eprintln!("[warp-proxy] 注册账号 {index}");
            let cfg = register_one(upstream.for_index(index - 1).as_ref(), &opts).await?;
            std::fs::create_dir_all(dir).ok();
            cfg.save(&path)
                .with_context(|| format!("保存 {}", path.display()))?;
            out.push(cfg);
        } else {
            eprintln!("[warp-proxy] 注册临时账号 {index}");
            out.push(register_one(upstream.for_index(index - 1).as_ref(), &opts).await?);
        }
    }
    Ok(out)
}

async fn register_one(
    upstream: Option<&UpstreamProxy>,
    opts: &warp_masque::RegisterOptions,
) -> anyhow::Result<WarpConfig> {
    let cfg = if let Some(upstream) = upstream {
        eprintln!("[warp-proxy] 注册走上游 {}", upstream.redacted());
        RegistrationClient::with_socks5(upstream)
            .context("创建上游注册客户端")?
            .register(opts)
            .await
    } else {
        RegistrationClient::register_auto(opts).await
    };
    cfg.context("注册 WARP 账号")
}

async fn shutdown_signal() {
    #[cfg(unix)]
    {
        use tokio::signal::unix::{signal, SignalKind};
        let mut term = signal(SignalKind::terminate()).expect("安装 SIGTERM 处理");
        tokio::select! {
            _ = tokio::signal::ctrl_c() => {}
            _ = term.recv() => {}
        }
    }
    #[cfg(not(unix))]
    {
        let _ = tokio::signal::ctrl_c().await;
    }
}

const DEFAULT_CONTROL_PASSWORD: &str = "admin";

/// 管理面板和控制接口共用的密码。环境变量优先，否则使用默认密码。
fn resolve_control_password(value: Option<&str>) -> String {
    match value.map(str::trim).filter(|value| !value.is_empty()) {
        Some(value) => value.to_string(),
        None => DEFAULT_CONTROL_PASSWORD.to_string(),
    }
}

fn env_string(key: &str) -> Option<String> {
    let value = std::env::var(key).ok()?;
    let value = value.trim();
    if value.is_empty() {
        None
    } else {
        Some(value.to_string())
    }
}

fn env_bool(key: &str, default: bool) -> bool {
    match env_string(key).as_deref() {
        Some("1" | "true" | "on" | "yes") => true,
        Some("0" | "false" | "off" | "no") => false,
        _ => default,
    }
}

fn env_flag_off(key: &str) -> bool {
    matches!(
        env_string(key).as_deref(),
        Some("0" | "false" | "off" | "no")
    )
}

fn env_usize(key: &str, default: usize) -> usize {
    env_string(key)
        .and_then(|value| value.parse().ok())
        .unwrap_or(default)
}

fn env_duration(key: &str, default: Duration) -> anyhow::Result<Duration> {
    match env_string(key) {
        Some(value) => parse_duration(&value),
        None => Ok(default),
    }
}

fn parse_duration(value: &str) -> anyhow::Result<Duration> {
    let value = value.trim();
    if value.is_empty() || value == "0" {
        return Ok(Duration::ZERO);
    }
    let split = value
        .find(|ch: char| ch.is_ascii_alphabetic())
        .unwrap_or(value.len());
    let (number, unit) = value.split_at(split);
    let number: u64 = number
        .parse()
        .with_context(|| format!("无法解析时长 {value}"))?;
    let duration = match unit {
        "" | "s" => Duration::from_secs(number),
        "m" => Duration::from_secs(number.saturating_mul(60)),
        "h" => Duration::from_secs(number.saturating_mul(3600)),
        "ms" => Duration::from_millis(number),
        _ => anyhow::bail!("无法解析时长 {value}"),
    };
    Ok(duration)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_duration_units() {
        assert_eq!(parse_duration("30m").unwrap(), Duration::from_secs(1800));
        assert_eq!(parse_duration("90").unwrap(), Duration::from_secs(90));
        assert_eq!(parse_duration("2h").unwrap(), Duration::from_secs(7200));
    }

    #[test]
    fn control_password_uses_environment_or_default() {
        assert_eq!(resolve_control_password(None), DEFAULT_CONTROL_PASSWORD);
        assert_eq!(
            resolve_control_password(Some("   ")),
            DEFAULT_CONTROL_PASSWORD
        );
        assert_eq!(
            resolve_control_password(Some("panel-secret")),
            "panel-secret"
        );
    }

    #[test]
    fn bind_address_accepts_host_or_host_port() {
        assert_eq!(apply_bind("0.0.0.0", Some("1080"), "1"), "0.0.0.0:1080");
        assert_eq!(apply_bind("127.0.0.1:1080", None, "1"), "127.0.0.1:1080");
        assert_eq!(
            apply_bind("127.0.0.1:1080", Some("1110"), "1"),
            "127.0.0.1:1110"
        );
        assert_eq!(apply_bind("", None, "47100"), "0.0.0.0:47100");
    }

    #[test]
    fn new_force_after_wins_and_reports_the_ignored_old_name() {
        let (value, notices) =
            resolve_force_after_sources(None, Some("30s"), None, Some("10s")).unwrap();
        assert_eq!(value, Duration::from_secs(30));
        assert_eq!(
            notices,
            vec!["已忽略 ROTATE_RESTART_DRAIN_TIMEOUT：请改用 ROTATE_RESTART_FORCE_AFTER"]
        );
        assert!(resolve_force_after_sources(None, Some("nope"), None, Some("10s")).is_err());

        let (value, notices) =
            resolve_force_after_sources(None, Some("30s"), Some(Duration::from_secs(10)), None)
                .unwrap();
        assert_eq!(value, Duration::from_secs(30));
        assert_eq!(
            notices,
            vec!["已忽略 --restart-drain：请改用 --restart-force-after"]
        );

        let (value, notices) =
            resolve_force_after_sources(Some(Duration::from_secs(30)), None, None, Some("90s"))
                .unwrap();
        assert_eq!(value, Duration::from_secs(30));
        assert_eq!(
            notices,
            vec!["已忽略 ROTATE_RESTART_DRAIN_TIMEOUT：请改用 ROTATE_RESTART_FORCE_AFTER"]
        );
    }

    #[test]
    fn old_force_after_still_applies_with_a_deprecation_notice() {
        let (value, notices) = resolve_force_after_sources(None, None, None, Some("90s")).unwrap();
        assert_eq!(value, Duration::from_secs(90));
        assert_eq!(
            notices,
            vec!["ROTATE_RESTART_DRAIN_TIMEOUT 已弃用，请改用 ROTATE_RESTART_FORCE_AFTER"]
        );

        let (value, notices) =
            resolve_force_after_sources(None, None, Some(Duration::from_secs(10)), Some("90s"))
                .unwrap();
        assert_eq!(value, Duration::from_secs(10));
        assert_eq!(
            notices,
            vec!["--restart-drain 已弃用，请改用 --restart-force-after"]
        );

        let (value, notices) = resolve_force_after_sources(None, None, None, None).unwrap();
        assert_eq!(value, Duration::from_secs(660));
        assert!(notices.is_empty());

        let (value, notices) = resolve_force_after_sources(None, Some("15s"), None, None).unwrap();
        assert_eq!(value, Duration::from_secs(15));
        assert!(notices.is_empty());
    }

    #[test]
    fn restart_flags_keep_the_new_name_whichever_is_written_last() {
        for flags in [
            [("--restart-force-after", 30u64), ("--restart-drain", 10)],
            [("--restart-drain", 10), ("--restart-force-after", 30)],
        ] {
            let mut current = None;
            let mut legacy = None;
            for (name, secs) in flags {
                remember_force_after_flag(
                    name,
                    Duration::from_secs(secs),
                    &mut current,
                    &mut legacy,
                );
            }
            let (value, notices) =
                resolve_force_after_sources(current, None, legacy, None).unwrap();
            assert_eq!(value, Duration::from_secs(30));
            assert_eq!(
                notices,
                vec!["已忽略 --restart-drain：请改用 --restart-force-after"]
            );
        }
    }
}
