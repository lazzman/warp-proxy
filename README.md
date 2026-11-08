# warp-proxy

[![CI](https://github.com/akumaginkou/warp-proxy/actions/workflows/ci.yml/badge.svg)](https://github.com/akumaginkou/warp-proxy/actions/workflows/ci.yml)

A clean-room, portable **Cloudflare WARP over MASQUE** proxy in Rust.

It registers free WARP accounts, runs one MASQUE (CONNECT-IP / HTTP-3) tunnel
per account, fronts the pool with a local SOCKS5 load-balancer, and exposes a
small control API to switch/rotate egress IPs live — no external `usque` binary,
no system VPN, no admin rights. Usable as a **Rust library** or a **standalone
daemon** any project can launch as a subprocess.

> Independent reimplementation of the WARP MASQUE engine. Protocol behaviour is
> referenced from public clients and RFCs; no third-party source is copied. See
> [`DESIGN.md`](DESIGN.md).

## Status

Built bottom-up (see the repo plan). Current state:

- [x] Device identity (P-256) and `config.json` schema
- [x] Two-step device registration + key enroll (`warp-masque`)
- [x] QUIC dial with self-signed mTLS + endpoint pubkey pinning (live-verified)
- [x] HTTP/3 Extended CONNECT `:protocol=cf-connect-ip` → **HTTP 200** (live-verified)
- [x] IP-packet ⇄ HTTP-datagram forwarding (`Tunnel::send_ip`/`recv_ip`)
- [x] userspace netstack (`smoltcp`) + local **SOCKS5 proxy with remote DNS** —
      `curl --socks5-hostname … /cdn-cgi/trace` reports **`warp=on`** at a WARP
      egress IP (live-verified via the `proxy` example)
- [x] DoH-bypass registration (pin `api.cloudflareclient.com` via DoH over
      1.1.1.1 for DNS-filtered networks) — `register_auto` / `--doh`
- [x] IP rotation via re-registration (`register_auto` yields a fresh account;
      live per-slot rotation lands with the pool)
- [x] HTTP/2 fallback (`--http2`) for QUIC-blocked networks: plain CONNECT +
      `cf-connect-proto` → 200, DATAGRAM capsules with Cloudflare's bare-IP quirk.
      Live-verified: `proxy --http2` → `warp=on`
- [x] multi-account pool (N tunnels = N egress IPs) + front SOCKS5
      load-balancer (round-robin / pin, WARP off = direct) + token-guarded
      control HTTP API + egress trace — live-verified (`pool` example)
- [x] `warp-proxy` daemon (handshake JSON on stdout, account persistence,
      graceful SIGINT/SIGTERM) — usable from any language as a subprocess
- [x] per-worker supervisor (auto-reconnect with exponential backoff on tunnel
      death), auto-rotate timer (`/api/interval`), and GitHub Actions CI
      (fmt · clippy · build · test on Linux + Windows)

The CONNECT-IP handshake uses a one-variant vendored patch to `h3` (see
[`vendor/h3/PATCH.md`](vendor/h3/PATCH.md)) so `:protocol` can carry Cloudflare's
non-standard `cf-connect-ip` token.

## Quick start — the daemon

```sh
cargo run -p warp-proxy -- --accounts 2 --socks 127.0.0.1:1080 --control 127.0.0.1:47100
```

It registers (or, with `--state-dir DIR`, loads) N accounts, starts the SOCKS5
load-balancer + control API, and prints one JSON line to **stdout** so a parent
process can wire itself up:

```json
{"socksPort":1080,"controlUrl":"http://127.0.0.1:47100","controlToken":"…","panelUrl":"http://127.0.0.1:47100/"}
```

Then point any app at `socks5h://127.0.0.1:1080` and drive egress over the
control API. Flags: `--accounts N`, `--socks ADDR`, `--control ADDR`,
`--state-dir DIR` (persist accounts across restarts), `--http2`. Ports may be
`:0` to auto-assign (read the real port from the handshake). Stops on
SIGINT/SIGTERM.

**As a Rust library:** `use warp_masque::{Pool, RegistrationClient, socks, control};`
— register configs, `Pool::new(configs, http2).await`, then `socks::serve_pool`
and `control::serve`.

### Try the tunnel handshake

```sh
cargo run -p warp-masque --example register     -- ./warp-config.json
cargo run -p warp-masque --example tunnel_poc   -- ./warp-config.json  # handshake -> HTTP 200
cargo run -p warp-masque --example egress_probe -- ./warp-config.json  # DNS through the tunnel -> WARP egress IP
```

### Run the SOCKS5 proxy

```sh
cargo run -p warp-masque --example proxy -- ./warp-config.json 127.0.0.1:1080
# in another shell:
curl --socks5-hostname 127.0.0.1:1080 https://www.cloudflare.com/cdn-cgi/trace   # -> warp=on
```

### Run a multi-account pool + control API

```sh
cargo run -p warp-masque --example pool -- 2 127.0.0.1:1080 127.0.0.1:47100
# round-robins across 2 egress IPs; drive it live (token printed on start):
curl -H "X-Warp-Token: <token>" http://127.0.0.1:47100/api/status
curl -H "X-Warp-Token: <token>" "http://127.0.0.1:47100/api/select?slot=1"   # pin account 1
curl -H "X-Warp-Token: <token>" "http://127.0.0.1:47100/api/rotate?slot=1"   # new egress IP
```

Control endpoints (loopback, JSON, `X-Warp-Token` required): `/api/status`,
`/api/toggle`, `/api/select`, `/api/rotate`, `/api/reconnect`, `/api/http2`,
`/api/interval` (auto-rotate seconds), `/api/trace`, `/api/account/add`,
`/api/account/remove`. Open `panelUrl` (the control address itself) in a browser
for the same actions. The panel password is `CONTROL_PASSWORD` (default `admin`) and is sent as `X-Warp-Token`. The page does not embed it.


## 入口、上游和调度

这些参数也可以用同名环境变量。配置了上游时会自动改走 HTTP/2，启动前先做 SOCKS5 CONNECT 探测，失败就退出，不会改走直连。

```sh
cargo run -p warp-proxy -- --http2 --accounts 2 \
  --upstream socks5://10.0.160.176:20120 \
  --socks 0.0.0.0:1110 \
  --proxy-mode mixed \
  --strategy round \
  --sticky username-round \
  --lb-rotate 5m \
  --resolve ipv6_prefer \
  --access-log \
  --restart-interval 30m \
  --restart-drain 660s \
  --restart-probe-timeout 90s \
  --restart-retries 2
```

- `--upstream`：一个或多个 SOCKS5 地址，用逗号分隔。可以写主机和端口，也可以带用户名和密码。按账号序号固定分配，只支持 TCP CONNECT。
- `--proxy-mode mixed`：同一端口同时接受 SOCKS5 和 HTTP 代理。未配置 `--socks-user/--socks-pass` 时允许匿名；客户端如果带了用户名，会用于黏性。
- `--strategy`：`round`、`random`、`hash`、`rotate`。匿名连接走这里。`rotate` 的窗口是 `--lb-rotate`。
- `--sticky`：`username-round`、`username-least`、`username-hash`、`ip-hash`、`none`。带用户名的连接优先黏住；目标账号重启或离线时不为这个用户改派。
- `--resolve`：`auto`、`ipv4_prefer`、`ipv6_prefer`、`ipv4_only`、`ipv6_only`。只影响隧道里的目标域名。
- `--access-log`：把来源、用户、目标、账号和出口写到 stderr。不记录密码。
- `--restart-interval`：到点后按批次保身份重连。会先停止接新连接，等现有连接结束或排空超时，再重连并确认 `warp=on` 或 `warp=plus`。这和 `/api/rotate` 不同，不会重新注册。
- `--restart-batch`：每一轮重启几个账号，默认 1。`0` 表示这一轮包含全部账号。同时进行的数量由 `--restart-concurrency` 限制。下一轮从上次停下的位置继续。
- `--restart-defer`：计划重启时，账号如果还有连接，就延后这段时间再试。到点仍然有连接会继续延后，不进入排空。`0` 表示不延后，到点就排空。手动重启不受这个设置影响。
- `/api/restart-plan?seconds=1800&batch=2&defer=300`：运行中修改上面的计划。`seconds=0` 关闭计划。修改后按新间隔重新计时，并取消已经延后的重启。
- `/api/restart?slot=1`：手动做一次保身份重启。`slot=0` 会按顺序处理全部账号。
- 管理面板就是控制地址本身（stdout 里的 `panelUrl`）。浏览器打开后输入管理密码，可以看状态、开关代理、固定账号、重连、保身份重启、刷新出口、换新身份和增删账号。页面放在进程里，不需要另外的脚本。

## Docker

镜像在 GitHub Actions 里构建并推到 GHCR，同时包含 `linux/amd64` 和 `linux/arm64`。推送到 `main` 会打 `latest`，推送到 `dev` 会打 `dev`，发布 `v*` 标签或 Release 会打对应版本号。容器里不需要启动脚本，所有配置都是环境变量，名字和 MicroWARP 里能对应的保持一致。

```sh
docker compose up -d
docker logs warp-proxy
```

代理默认只发布在 `127.0.0.1:1080`，管理面板在 `127.0.0.1:47100`。管理密码用 `CONTROL_PASSWORD` 设置，未设置时是 `admin`。标准输出里的 `controlToken` 就是这个密码。账号保存在 `warp-proxy-state` 卷里。

| 变量 | 默认 | 作用 |
| :--- | :--- | :--- |
| `INSTANCE_COUNT` | 容器 `1`，本机二进制 `2` | 账号数量 |
| `BIND_ADDR` / `BIND_PORT` | 容器 `0.0.0.0:1080` | 代理监听地址。可以只写主机，端口用 `BIND_PORT` |
| `CONTROL_ADDR` / `CONTROL_PORT` | 容器 `0.0.0.0:47100` | 管理面板和控制接口 |
| `STATE_DIR` | 容器 `/var/lib/warp-proxy` | 账号身份目录 |
| `PROXY_MODE` | `socks5` | `mixed` 时同一端口同时接受 HTTP 代理 |
| `MASQUE_HTTP2` | `0` | `1` 改用 HTTP/2。配置了上游时会自动打开 |
| `UPSTREAM_SOCKS5` | 空 | 上游 SOCKS5，多个用逗号分隔 |
| `UPSTREAM_PROBE_TIMEOUT` | `8s` | 启动前探测上游的时间 |
| `SOCKS_USER` / `SOCKS_PASS` | 空 | 入口认证。两个要一起设置 |
| `CONTROL_PASSWORD` | `admin` | 管理面板和控制接口密码。请求头仍然是 `X-Warp-Token` |
| `RESOLVE_PREFERENCE` | `auto` | `auto`、`ipv4_prefer`、`ipv6_prefer`、`ipv4_only`、`ipv6_only` |
| `LB_STRATEGY` | `round` | `round`、`random`、`hash`、`rotate` |
| `LB_STICKY_MODE` | `username-round` | `none`、`username-round`、`username-least`、`username-hash`、`ip-hash` |
| `LB_ROTATE_INTERVAL` | `5m` | `rotate` 策略的时间窗 |
| `LB_ACCESS_LOG` | `0` | `1` 把连接记到标准错误，不记录密码 |
| `ROTATE_RESTART_ENABLED` | `1` | `0` 关闭保身份重启计划 |
| `ROTATE_RESTART_INTERVAL` | `0` | 计划间隔，`0` 表示不定时重启 |
| `ROTATE_RESTART_BATCH` | `1` | 每一轮重启几个账号，`0` 表示全部 |
| `ROTATE_RESTART_DEFER` | `0` | 账号仍有连接时延后多久再试，`0` 表示立即排空 |
| `ROTATE_RESTART_DRAIN_TIMEOUT` | `660s` | 开始重启后最多等待现有连接的时间 |
| `ROTATE_RESTART_PROBE_TIMEOUT` | `90s` | 重连后确认 `warp=on` 的时间 |
| `ROTATE_RESTART_RETRIES` | `2` | 探测失败后的额外次数 |
| `ROTATE_RESTART_CONCURRENCY` | `1` | 同一轮最多同时重启几个账号 |

时长可以写秒数，也可以写 `30s`、`5m`、`1h`。命令行参数仍然可以覆盖这些环境变量。

## Layout

```
crates/warp-masque/   # library: keys · registration · tunnel (H3 + H2) · netstack
                      #          · SOCKS5 · pool · control API · DoH · trace
crates/warp-proxy/    # the `warp-proxy` daemon binary
vendor/h3/            # h3 0.0.8 + one-variant cf-connect-ip patch (see PATCH.md)
DESIGN.md             # protocol spec + clean-room provenance
```

## Build

```sh
cargo build --release          # -> target/release/warp-proxy
cargo test                     # OS-independent unit tests
```

Pure Rust on the `ring` crypto provider — no C toolchain needed for a native
Linux/macOS build. Cross-building to Windows works too, but `ring` needs a
Windows C compiler for that target (e.g. `x86_64-w64-mingw32-gcc`):

```sh
rustup target add x86_64-pc-windows-gnu
CC_x86_64_pc_windows_gnu=x86_64-w64-mingw32-gcc cargo build --release --target x86_64-pc-windows-gnu
```

## License

Licensed under either of

- MIT license ([LICENSE-MIT](LICENSE-MIT))
- Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE))

at your option. Unless you explicitly state otherwise, any contribution
intentionally submitted for inclusion in this project by you, as defined in the
Apache-2.0 license, shall be dual licensed as above, without any additional
terms or conditions.

Bundles a patched copy of [`h3`](vendor/h3) (Apache-2.0 OR MIT); see
[`vendor/h3/PATCH.md`](vendor/h3/PATCH.md).
