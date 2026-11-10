//! warp-proxy 守护进程：注册或加载一组 WARP 账号，前面放一个本地代理，并用控制接口管理出口。
//!
//! 启动后往 stdout 打一行 JSON，方便父进程发现端口和令牌：
//!
//! {"socksPort":1080,"controlUrl":"http://127.0.0.1:47100","controlToken":"…","panelUrl":"http://127.0.0.1:47100/"}
//!
//! 其余日志都在 stderr。收到 SIGINT 或 SIGTERM 后退出。

use std::net::{Ipv4Addr, SocketAddr};
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use anyhow::Context;
use tokio::net::TcpListener;
use tokio::sync::Semaphore;
use tokio::task::JoinSet;

use warp_masque::{
    control, parse_sticky, parse_strategy, socks, Policy, Pool, PoolOptions, ProxyAuth,
    RegistrationClient, ResolvePreference, RestartConfig, UpstreamProxy, UpstreamSet, WarpConfig,
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
    restart_max_uptime: Duration,
    restart_max_users: usize,
    restart_max_connections: u64,
    restart_drain_check_interval: Duration,
    restart_probe: Duration,
    restart_concurrency: usize,
    resolve: String,
    socks_user: Option<String>,
    socks_pass: Option<String>,
    control_password: String,
    mixed: bool,
    upstream_probe: Duration,
    health_interval: Duration,
    health_timeout: Duration,
}

const REGISTRATION_CONCURRENCY: usize = 4;

fn parse_args() -> anyhow::Result<Args> {
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
        restart_max_uptime: env_duration("RESTART_MAX_UPTIME", Duration::ZERO)?,
        restart_max_users: env_usize_checked("RESTART_MAX_USERS", 0)?,
        restart_max_connections: env_u64("RESTART_MAX_CONNECTIONS", 0)?,
        restart_drain_check_interval: env_duration(
            "RESTART_DRAIN_CHECK_INTERVAL",
            Duration::from_secs(10),
        )?,
        restart_probe: env_duration("RESTART_PROBE_TIMEOUT", Duration::from_secs(90))?,
        restart_concurrency: env_usize_checked("RESTART_CONCURRENCY", 1)?.max(1),
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
            "--restart-max-uptime" => {
                args.restart_max_uptime = parse_duration(&next_value(&mut it, &arg)?)?
            }
            "--restart-max-users" => {
                args.restart_max_users = next_value(&mut it, &arg)?
                    .parse()
                    .context("--restart-max-users")?
            }
            "--restart-max-connections" => {
                args.restart_max_connections = next_value(&mut it, &arg)?
                    .parse()
                    .context("--restart-max-connections")?
            }
            "--restart-drain-check-interval" => {
                args.restart_drain_check_interval = parse_duration(&next_value(&mut it, &arg)?)?
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
            // 遗留 CLI 参数直接报错，避免静默套用旧的重启语义。
            "--restart-interval"
            | "--restart-mode"
            | "--restart-threshold"
            | "--restart-drain-timeout"
            | "--restart-force-after"
            | "--restart-drain"
            | "--restart-retries"
            | "--restart-misfire"
            | "--restart-batch"
            | "--restart-defer" => {
                anyhow::bail!("{arg} 已移除，请改用 --restart-max-uptime、--restart-max-users、--restart-max-connections")
            }
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
            other => anyhow::bail!("未知参数 {other:?}"),
        }
    }
    for key in [
        "ROTATE_RESTART_ENABLED",
        "ROTATE_RESTART_MODE",
        "ROTATE_RESTART_THRESHOLD",
        "ROTATE_RESTART_INTERVAL",
        "ROTATE_RESTART_BATCH",
        "ROTATE_RESTART_MISFIRE",
        "ROTATE_RESTART_DEFER",
        "ROTATE_RESTART_FORCE_AFTER",
        "ROTATE_RESTART_DRAIN_TIMEOUT",
        "ROTATE_RESTART_PROBE_TIMEOUT",
        "ROTATE_RESTART_CONCURRENCY",
        "ROTATE_RESTART_RETRIES",
    ] {
        if std::env::var_os(key).is_some() {
            eprintln!("[warp-proxy] 已忽略旧配置 {key}；请改用 RESTART_MAX_UPTIME、RESTART_MAX_USERS、RESTART_MAX_CONNECTIONS 等新配置");
        }
    }
    args.accounts = args.accounts.max(1);
    if args.restart_drain_check_interval.is_zero() {
        anyhow::bail!("RESTART_DRAIN_CHECK_INTERVAL 必须大于 0");
    }
    Ok(args)
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
    let upstream = UpstreamSet::parse(&args.upstream)
        .map_err(anyhow::Error::msg)
        .context("解析 UPSTREAM_SOCKS5")?;
    if !upstream.is_empty() && !args.http2 {
        eprintln!("[warp-proxy] 检测到上游 SOCKS5，自动启用 HTTP/2");
        args.http2 = true;
    }
    let auth = match (args.socks_user.clone(), args.socks_pass.clone()) {
        (Some(username), Some(password)) => Some(ProxyAuth { username, password }),
        (None, None) => None,
        _ => anyhow::bail!("SOCKS_USER 和 SOCKS_PASS 需要同时设置"),
    };
    let options = PoolOptions {
        http2: args.http2,
        upstream: upstream.clone(),
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
            max_uptime: args.restart_max_uptime,
            max_users: args.restart_max_users,
            max_connections: args.restart_max_connections,
            drain_check_interval: args.restart_drain_check_interval,
            probe_timeout: args.restart_probe,
            concurrency: args.restart_concurrency,
        },
        health_interval: args.health_interval,
        health_timeout: args.health_timeout,
        device_name: "warp-proxy".into(),
        state_dir: args.state_dir.clone(),
        auto_restore_limit: Some(args.accounts),
    };
    let pool = Pool::start_deferred(options, args.accounts).context("启动连接池")?;

    let token = args.control_password.clone();
    let control_listener = TcpListener::bind(&args.control)
        .await
        .with_context(|| format!("绑定控制接口 {}", args.control))?;
    let socks_listener = TcpListener::bind(&args.socks)
        .await
        .with_context(|| format!("绑定代理 {}", args.socks))?;
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

    tokio::spawn(control::serve(control_listener, pool.clone(), token));
    tokio::spawn(socks::serve_pool(socks_listener, pool.clone()));
    tokio::spawn(initialize_accounts(
        pool,
        args.accounts,
        args.state_dir,
        microwarp_source,
        args.microwarp_scan_interval,
        upstream,
        args.upstream_probe,
    ));
    shutdown_signal().await;
    eprintln!("[warp-proxy] 正在退出");
    Ok(())
}

async fn initialize_accounts(
    pool: Arc<Pool>,
    count: usize,
    state_dir: Option<PathBuf>,
    microwarp_source: Option<PathBuf>,
    microwarp_scan_interval: Duration,
    upstream: UpstreamSet,
    upstream_probe_timeout: Duration,
) {
    if let Some(source) = &microwarp_source {
        let source = source.clone();
        let pool_for_migration = pool.clone();
        let migration =
            tokio::task::spawn_blocking(move || pool_for_migration.import_microwarp(&source)).await;
        match migration {
            Ok(Ok(_)) => {}
            Ok(Err(err)) => pool.log_initialization(format!("迁移失败: {err}")),
            Err(err) => pool.log_initialization(format!("迁移任务异常: {err}")),
        }
    }
    if !upstream.is_empty() {
        let target = SocketAddr::from((Ipv4Addr::new(162, 159, 198, 2), 443));
        let probe_set = upstream.clone();
        let probe_pool = Arc::downgrade(&pool);
        tokio::spawn(async move {
            if let Err(err) = probe_set.probe(target, upstream_probe_timeout).await {
                if let Some(pool) = probe_pool.upgrade() {
                    pool.log_initialization(format!("上游 SOCKS5 探测失败，节点将自行重试: {err}"));
                }
            }
        });
    }
    if let Some(source) = microwarp_source
        .as_ref()
        .filter(|_| !microwarp_scan_interval.is_zero())
    {
        let source = source.clone();
        let pool = pool.clone();
        tokio::spawn(async move {
            let mut timer = tokio::time::interval_at(
                tokio::time::Instant::now() + microwarp_scan_interval,
                microwarp_scan_interval,
            );
            loop {
                timer.tick().await;
                if let Err(err) = pool.scan_microwarp(&source).await {
                    pool.log_initialization(format!("扫描 {} 失败: {err}", source.display()));
                }
            }
        });
    }

    let register_limit = Arc::new(Semaphore::new(REGISTRATION_CONCURRENCY));
    let mut registrations = JoinSet::new();
    for index in 1..=count {
        let state_dir = state_dir.clone();
        let upstream = upstream.for_index(index - 1);
        let register_limit = register_limit.clone();
        let pool = Arc::downgrade(&pool);
        registrations.spawn(async move {
            let mut previous_error = String::new();
            loop {
                let permit = register_limit.acquire().await.expect("注册信号量未关闭");
                let result =
                    load_or_register_one(state_dir.as_deref(), index, upstream.as_ref()).await;
                drop(permit);
                match result {
                    Ok(config) => return (index, config),
                    Err(err) => {
                        let message = format!("{err:#}");
                        if message != previous_error {
                            if let Some(pool) = pool.upgrade() {
                                pool.log_initialization(format!(
                                    "账号 {index} 准备失败，30 秒后重试: {message}"
                                ));
                            }
                            previous_error = message;
                        }
                        tokio::time::sleep(Duration::from_secs(30)).await;
                    }
                }
            }
        });
    }
    while let Some(result) = registrations.join_next().await {
        match result {
            Ok((id, config)) => {
                if let Err(err) = pool.attach_base_account(id, config).await {
                    pool.log_initialization(format!("账号 {id} 加入连接池失败: {err}"));
                }
            }
            Err(err) => pool.log_initialization(format!("准备账号任务异常退出: {err}")),
        }
    }
    pool.finish_initialization().await;
}

async fn load_or_register_one(
    state_dir: Option<&std::path::Path>,
    index: usize,
    upstream: Option<&UpstreamProxy>,
) -> anyhow::Result<WarpConfig> {
    let opts = warp_masque::RegisterOptions {
        device_name: Some(format!("warp-proxy-{index}")),
        ..Default::default()
    };
    if let Some(dir) = state_dir {
        let path = dir.join(format!("account-{index}.json"));
        if path.exists() {
            return WarpConfig::load(&path).with_context(|| format!("加载 {}", path.display()));
        }
        let config = register_one(upstream, &opts).await?;
        std::fs::create_dir_all(dir).ok();
        config
            .save(&path)
            .with_context(|| format!("保存 {}", path.display()))?;
        Ok(config)
    } else {
        register_one(upstream, &opts).await
    }
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

fn env_usize(key: &str, default: usize) -> usize {
    env_string(key)
        .and_then(|value| value.parse().ok())
        .unwrap_or(default)
}

fn env_usize_checked(key: &str, default: usize) -> anyhow::Result<usize> {
    env_string(key)
        .map(|value| {
            value
                .parse::<usize>()
                .with_context(|| format!("{key} 必须是非负整数"))
        })
        .transpose()
        .map(|value| value.unwrap_or(default))
}

fn env_u64(key: &str, default: u64) -> anyhow::Result<u64> {
    env_string(key)
        .map(|value| {
            value
                .parse::<u64>()
                .with_context(|| format!("{key} 必须是非负整数"))
        })
        .transpose()
        .map(|value| value.unwrap_or(default))
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

    #[tokio::test]
    async fn prepares_saved_accounts_without_waiting_for_tunnels() {
        let dir = std::env::temp_dir().join(format!(
            "warp-proxy-async-start-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        for id in 1..=2 {
            WarpConfig {
                id: format!("saved-{id}"),
                ..WarpConfig::default()
            }
            .save(dir.join(format!("account-{id}.json")))
            .unwrap();
        }
        let mut options = PoolOptions::basic(false);
        options.state_dir = Some(dir.clone());
        let pool = Pool::start_deferred(options, 2).unwrap();
        tokio::time::timeout(
            Duration::from_secs(1),
            initialize_accounts(
                pool.clone(),
                2,
                Some(dir.clone()),
                None,
                Duration::ZERO,
                UpstreamSet::default(),
                Duration::from_secs(1),
            ),
        )
        .await
        .unwrap();
        let status = pool.status();
        assert!(!status.initializing);
        assert_eq!(status.accounts.len(), 2);
        assert!(status.accounts.iter().all(|account| !account.ready));
        std::fs::remove_dir_all(dir).unwrap();
    }

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
}
