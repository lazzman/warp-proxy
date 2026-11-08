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
`/api/sessions`, `/api/logs`, `/api/toggle`, `/api/select`, `/api/rotate`,
`/api/reconnect`, `/api/restart`, `/api/restart-plan`, `/api/http2`,
`/api/interval` (auto-rotate seconds), `/api/trace`, `/api/account/add`,
`/api/account/manual`, `/api/account/remove`. Open `panelUrl` in a browser for
the same actions, plus live connections and the log ring. The panel password is
`CONTROL_PASSWORD` (default `admin`) and is sent as `X-Warp-Token`. The page does not embed it.


## 入口、上游和调度

命令行参数会覆盖同名配置对应的环境变量。配置了上游时会自动改走 HTTP/2，启动前先做 SOCKS5 CONNECT 探测，失败就退出，不会改走直连。

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

- `--upstream` / `UPSTREAM_SOCKS5`：一个或多个 SOCKS5 地址，用逗号分隔。可以写主机和端口，也可以带用户名和密码。按账号序号固定分配，只支持 TCP CONNECT。启动前会探测，失败就退出，不会改走直连。
- `--proxy-mode` / `PROXY_MODE`：默认 `socks5`。`mixed` 和 `http` 都表示同一端口同时接受 SOCKS5 和 HTTP 代理。未配置入口密码时允许匿名；客户端如果带了用户名，会用于黏性。
- `--strategy` / `LB_STRATEGY`：见「调度」。
- `--sticky` / `LB_STICKY_MODE`：见「黏性」。
- `--lb-rotate` / `LB_ROTATE_INTERVAL`：只在 `rotate` 策略下使用，见「调度」。
- `--resolve` / `RESOLVE_PREFERENCE`：见「解析」。
- `--access-log` / `LB_ACCESS_LOG`：把来源、用户、目标、账号和出口写到标准错误。不记录密码。
- `--restart-*` / `ROTATE_RESTART_*`：保身份重连，见「保身份重启」。它不重新注册。
- 管理面板就是控制地址本身（stdout 里的 `panelUrl`）。浏览器打开后输入管理密码。总览看入口、流量和定时重启；实例可以筛选、停用、重连、添加临时实例；连接和日志分别看正在转发的会话和最近 300 行。页面放在进程里，不需要另外的脚本。

### 调度

`LB_STRATEGY` 只处理没有被黏性接走的连接。`LB_STICKY_MODE=none` 时每条连接都走这里；其他黏性模式下，除 `ip-hash` 外，没有用户名的连接也走这里。

- `round`：在可接流量的账号之间轮流分配。`round-robin` 是同一个值。
- `random`：每次在可接流量的账号里随机选一个。
- `hash`：用客户端 IP 做稳定哈希，在当前可接流量的账号里选择。账号不可用时会在剩下的账号里重算。算法和 `ip-hash` 相同，但 `hash` 不覆盖已经按用户名黏住的连接。
- `rotate`：走这个策略的连接在一个时间窗里共用同一个账号。时间窗是 `LB_ROTATE_INTERVAL`，也就是 `--lb-rotate`，默认 `5m`。时间到了就按当前账号顺序换到下一个。这个账号不能接流量时，临时使用下一个可用账号，时间窗的指针不往前拨；它恢复后，仍回到这个窗口原来的账号。设为 `0` 时不再按时间换，退回 `round`。

`LB_ROTATE_INTERVAL` 只决定新连接进入哪个现有账号，不重连隧道，也不重新注册。保身份重连由 `ROTATE_RESTART_INTERVAL` 控制。面板里的「换出口」和 `/api/interval?seconds=300` 是第三件事：到点后重新注册账号以更换出口 IP。这项启动时是关闭的，`0` 表示关闭，其他值至少按 60 秒计。`/api/rotate?slot=1` 会立刻重新注册指定账号，`slot=0` 重新注册当前固定的账号，没有固定时使用第一个。重新注册得到的新身份只在当前进程里生效，不会写回 `STATE_DIR`。

### 黏性

`LB_STICKY_MODE` 就是 `--sticky`。它决定一条连接第一次落到哪个账号，以及之后是否还走这个账号。映射只在进程内存里，重启进程后重新分配。

用户名从入口认证来。没有设置 `SOCKS_USER` / `SOCKS_PASS` 时，SOCKS5 用户名密码方法里的用户名，或 HTTP 代理 Basic 里的用户名，只用于黏性，密码不校验。设置了入口账号密码后，客户端必须使用这一组；这时所有连接都是同一个用户名，按用户名黏住就会进同一个账号。除 `ip-hash` 外，没有用户名的连接按 `LB_STRATEGY` 调度。

- `none`：不黏。每条连接都走 `LB_STRATEGY`。
- `username-round`：记住用户名第一次分到的账号。第一次在可接流量的账号里，选已经黏住的用户名最少的；数量相同就按顺序轮转。
- `username-least`：同样记住第一次的结果。第一次选的是当前活跃连接最少的账号，数量相同按顺序轮转。之后连接变少也不会改派。
- `username-hash`：用用户名做稳定哈希，只在当前可接流量的账号里选择。不保存映射。原来的账号停用、排空或离线后，下次会在剩下的账号里重算，出口可能变化。
- `ip-hash`：忽略用户名，用客户端 IP 做同样的哈希。匿名连接也按 IP 黏住。`client-ip-hash` 是同一个值。账号不可用时会在剩下的账号里重算。

`username-round` 和 `username-least` 记住的账号如果还在，但正在排空、已停用或隧道不在，这条连接直接失败，不会临时改到其他账号。账号被删除后映射作废，下一次按新用户重新分配。面板上的用户数只统计这两种模式记住的用户名；两种哈希模式不记这张表，用户数是 0。

### 解析

`RESOLVE_PREFERENCE` 就是 `--resolve`，只影响隧道里的目标地址。别名可以用减号。`ipv4`、`v4` 等于 `ipv4_only`，`ipv6`、`v6` 等于 `ipv6_only`。

- `auto` 和 `ipv4_prefer`：同时查询 IPv4 和 IPv6。两者都有时用 IPv4，只有 IPv6 时用 IPv6。
- `ipv6_prefer`：两者都有时用 IPv6，没有 IPv6 时退回 IPv4。
- `ipv4_only`：只使用 IPv4。字面量 IPv6 会被拒绝。
- `ipv6_only`：只使用 IPv6。字面量 IPv4 会被拒绝。隧道没有 IPv6 地址时解析失败。

### 保身份重启

这些设置只重连现有隧道，不重新注册，出口身份保持不变。`ROTATE_RESTART_ENABLED=0` 会忽略下面的间隔，等于关闭计划。

- `ROTATE_RESTART_INTERVAL` / `--restart-interval`：多久开始一轮。默认 `0`，表示不定时重启。
- `ROTATE_RESTART_BATCH` / `--restart-batch`：每一轮几个账号，默认 1。`0` 表示这一轮包含当前全部账号。下一轮从上次停下的位置继续。
- `ROTATE_RESTART_CONCURRENCY` / `--restart-concurrency`：同一轮最多同时进行几个，默认 1。小于 1 时仍按 1 处理。
- `ROTATE_RESTART_DEFER` / `--restart-defer`：计划到点时账号还有连接，就延后这段时间再试。到点仍然有连接会继续延后，不进入排空。`0` 表示不延后，到点就排空。手动重启不受这个设置影响。
- `ROTATE_RESTART_DRAIN_TIMEOUT` / `--restart-drain`：已经开始重启后，最多等待现有连接的时间，默认 `660s`。
- `ROTATE_RESTART_PROBE_TIMEOUT` / `--restart-probe-timeout`：重连后确认 `warp=on` 或 `warp=plus` 的时间，默认 `90s`。
- `ROTATE_RESTART_RETRIES` / `--restart-retries`：探测失败后的额外次数，默认 2。每次重启最多尝试 3 次。

`/api/restart-plan?seconds=1800&batch=2&defer=300` 可以在运行中修改间隔、批量和延后。`seconds=0` 关闭计划。修改后按新间隔重新计时，并取消已经延后的重启。`/api/restart?slot=1` 手动做一次保身份重启。`slot=0` 会按顺序处理全部账号。

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
| `PROXY_MODE` | `socks5` | `mixed` 或 `http` 时同一端口同时接受 HTTP 代理 |
| `MASQUE_HTTP2` | `0` | `1` 改用 HTTP/2。配置了上游时会自动打开 |
| `UPSTREAM_SOCKS5` | 空 | 上游 SOCKS5，多个用逗号分隔 |
| `UPSTREAM_PROBE_TIMEOUT` | `8s` | 启动前探测上游的时间 |
| `SOCKS_USER` / `SOCKS_PASS` | 空 | 入口认证。两个要一起设置 |
| `CONTROL_PASSWORD` | `admin` | 管理面板和控制接口密码。请求头仍然是 `X-Warp-Token` |
| `RESOLVE_PREFERENCE` | `auto` | 隧道内目标地址的地址族，见「解析」 |
| `LB_STRATEGY` | `round` | 没有被黏性接走的连接如何选账号，见「调度」 |
| `LB_STICKY_MODE` | `username-round` | 见上方「黏性」。`client-ip-hash` 与 `ip-hash` 相同 |
| `LB_ROTATE_INTERVAL` | `5m` | 仅 `LB_STRATEGY=rotate` 时的换账号时间窗，见「调度」 |
| `LB_ACCESS_LOG` | `0` | `1` 把连接记到标准错误，不记录密码 |
| `ROTATE_RESTART_ENABLED` | `1` | `0` 关闭保身份重启计划 |
| `ROTATE_RESTART_INTERVAL` | `0` | 保身份重连的间隔，不是 `LB_ROTATE_INTERVAL`。见「保身份重启」 |
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
