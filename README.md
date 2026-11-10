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
- [x] 多账号池（每个实例一条隧道、一个出口 IP）、前置 SOCKS5 负载均衡（轮询和用户名黏性）、
      带令牌保护的 HTTP 管理接口和出口探测；已通过 `pool` 示例验证
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

启动后立即监听管理页面和代理端口，并向 **stdout** 输出一行 JSON，方便父进程发现入口。
账号从 `--state-dir DIR` 加载，缺失时在后台注册；最多同时准备 4 个账号，
每次最多并发连接 4 条 WARP 隧道。管理页面不等待账号注册或连接，
登录后可以看到账号准备进度、连接中状态和失败日志。失败的账号会在后台退避重试，
已连接的账号可以直接提供代理服务；在没有可用账号前，代理端口虽然已监听，但不能转发。

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
curl -H "X-Warp-Token: <token>" "http://127.0.0.1:47100/api/rotate?slot=1"   # new egress IP
```

控制接口（需通过 `X-Warp-Token` 认证）：`/api/status`、`/api/sessions`、`/api/logs`、`/api/toggle`、`/api/rotate`、`/api/reconnect`、`/api/restart`、`/api/restart-policy`、`/api/http2`、`/api/interval`、`/api/trace`、`/api/account/add`、`/api/account/manual`、`/api/account/remove`。
浏览器打开 `panelUrl` 可以执行同样的操作，还可以查看活跃连接和环形日志。管理密码由 `CONTROL_PASSWORD` 设置，默认 `admin`；页面不会嵌入密码。


## 入口、上游和调度

命令行参数会覆盖同名配置对应的环境变量。配置了上游时会自动改走 HTTP/2；管理页面启动后会后台探测 SOCKS5 CONNECT，失败仅记录错误，不阻塞其他节点。每个节点仍然必须经过对应上游，连接失败会独立重试，不会改走直连。

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
  --restart-max-uptime 24h \
  --restart-max-users 1000 \
  --restart-max-connections 10000 \
  --restart-drain-check-interval 10s \
  --restart-probe-timeout 90s \
  --restart-concurrency 2
```

- `--upstream` / `UPSTREAM_SOCKS5`：一个或多个 SOCKS5 地址，用逗号分隔。可以写主机和端口，也可以带用户名和密码。按账号序号固定分配，只支持 TCP CONNECT。后台探测失败只记录错误；节点通过自己的上游连接，失败则重试，不会改走直连。注册请求对齐 usque 的请求头和 Go `net/http` 的 HTTP/2 窗口。遇到 HTTP 429、503 或 Cloudflare `1015` 时，按 `Retry-After` 或递增间隔等待后重试，最多 6 次，不会马上退出再打。
- `--proxy-mode` / `PROXY_MODE`：默认 `socks5`。`mixed` 和 `http` 都表示同一端口同时接受 SOCKS5 和 HTTP 代理。未配置入口密码时允许匿名；客户端如果带了用户名，会用于黏性。
- `--strategy` / `LB_STRATEGY`：见「调度」。
- `--sticky` / `LB_STICKY_MODE`：见「黏性」。
- `--lb-rotate` / `LB_ROTATE_INTERVAL`：只在 `rotate` 策略下使用，见「调度」。
- `--resolve` / `RESOLVE_PREFERENCE`：见「解析」。
- `--access-log` / `LB_ACCESS_LOG`：把来源、用户、目标、账号和出口写到标准错误。一行里用 `|` 分开，成功是 `↗`，失败是 `×`。不记录密码。
- `--restart-max-uptime` / `RESTART_MAX_UPTIME`：实例成功连接后的运行时长阈值，例如 `24h`。
- `--restart-max-users` / `RESTART_MAX_USERS`：本轮去重用户阈值，例如 `1000`。
- `--restart-max-connections` / `RESTART_MAX_CONNECTIONS`：本轮累计分配连接数阈值，例如 `10000`。
- `--restart-drain-check-interval` / `RESTART_DRAIN_CHECK_INTERVAL`：排空检测间隔，默认 `10s`；排空没有超时。
- `--restart-concurrency` / `RESTART_CONCURRENCY`：最多同时重连实例数，默认 `1`。
- `--health-interval` / `HEALTH_CHECK_INTERVAL`：多久经隧道检查一次出口，默认 `60s`。`0` 关闭。见「出口检查」。
- `--health-timeout` / `HEALTH_CHECK_TIMEOUT`：单次出口检查的最长时间，默认 `20s`。
- 管理面板就是控制地址本身（stdout 里的 `panelUrl`）。浏览器打开后输入管理密码。登录成功后密码记在这个浏览器里，下次打开会直接用它认证。总览看入口、流量和重启策略；实例可以筛选、停用、重连、按数量添加临时实例；连接页滚动展示最近 300 条连接（包括已关闭的连接、活跃状态与流量），最新连接在前；日志展示最近 300 行。连接历史仅保存在当前进程内，重启后清空。页面放在进程里，不需要另外的脚本。
- 内存占用：连接历史最多保留 300 条已关闭记录，活跃连接按实际数量保留；面板日志最多 300 条、每条不超过 2 KiB。只在启用用户阈值时保留本轮去重用户哈希（触发阈值后冻结）；用户名黏性映射最多约 10 万条，满额后新用户名仍能选路但不再记住绑定。队列中每个实例最多占一个位置，等待排空不额外创建常驻任务。

临时实例的身份同样写在 `STATE_DIR` 的 `account-<编号>.json`，待恢复的编号记在 `temporary.json`。守护进程启动时最多自动加载 `INSTANCE_COUNT` 个账号，超额身份会保留等待空位；手动在面板添加账号仍可超过这个数量。移除临时实例只把它移出当前进程和这份名单，不删除已保存的身份；之后再添加时优先用回这些身份。

### 从 MicroWARP 迁移账号

MicroWARP 的账号配置位于 `instances/0/masque-config.json`、`instances/1/masque-config.json` 等目录中，与本项目使用相同的 JSON 格式。设置了 `STATE_DIR` 后，启动时自动检查 `STATE_DIR/instances`；运行时默认每 `60s` 再扫描一次。也可使用 `MICROWARP_DIR` / `--microwarp-dir` 指定独立的 MicroWARP 数据目录（既支持包含 `instances` 的根目录，也支持直接指向 `instances` 目录）。`MICROWARP_SCAN_INTERVAL` / `--microwarp-scan-interval` 配置扫描周期，`0` 表示只在启动时迁移。

迁移会将账号复制为 `STATE_DIR/account-<编号>.json`，不修改 MicroWARP 的原始文件。编号从 1 开始分配，遇到已有账号会自动跳过已占用编号；按配置中的设备 `id` 去重，不会重复注册或覆盖已保存的身份。启动时仅加载前 `INSTANCE_COUNT` 个基础实例；其余导入账号加入 `temporary.json`，不自动超额启动。运行中检测到新配置时也会先持久化并标记完成，只有运行实例数低于上限时才自动加入连接池。超额账号仍可通过管理面板手动添加，或调高 `INSTANCE_COUNT` 后重启使用。

完成记录保存在 `STATE_DIR/microwarp-migrations.json`，同一来源、同一设备身份只迁移一次；即使移除运行中的实例，也不会在后续扫描中反复添加。缺失或尚未写完的配置会跳过并在后续扫描重试。修改已迁移设备的 JSON 内容不会覆盖已有账号；如果该目录换成新的设备 `id`，会按新增身份处理。迁移记录和账号文件应一起保留在持久化卷中。

Docker 中建议将原 MicroWARP 的 `instances` 目录**只读**挂载到 `/var/lib/warp-proxy/instances`：

```yaml
services:
  warp-proxy:
    volumes:
      - warp-proxy-state:/var/lib/warp-proxy
      - /你的路径/lb-microwarp/instances:/var/lib/warp-proxy/instances:ro
```

也可以挂到其他只读路径，再通过 `MICROWARP_DIR` 指定。必须同时保留可写的 `STATE_DIR` 用于保存导入账号和迁移记录。

### 调度

`LB_STRATEGY` 只处理没有被黏性接走的连接。`LB_STICKY_MODE=none` 时每条连接都走这里；其他黏性模式下，除 `ip-hash` 外，没有用户名的连接也走这里。

- `round`：在可接流量的账号之间轮流分配。`round-robin` 是同一个值。
- `random`：每次在可接流量的账号里随机选一个。
- `hash`：用客户端 IP 做稳定哈希，在当前可接流量的账号里选择。账号不可用时会在剩下的账号里重算。算法和 `ip-hash` 相同，但 `hash` 不覆盖已经按用户名黏住的连接。
- `rotate`：走这个策略的连接在一个时间窗里共用同一个账号。时间窗是 `LB_ROTATE_INTERVAL`，也就是 `--lb-rotate`，默认 `5m`。时间到了就按当前账号顺序换到下一个。这个账号不能接流量时，临时使用下一个可用账号，时间窗的指针不往前拨；它恢复后，仍回到这个窗口原来的账号。设为 `0` 时不再按时间换，退回 `round`。

`LB_ROTATE_INTERVAL` 只决定新连接进入哪个现有账号，不重连隧道，也不重新注册。保身份重连由下面三个独立阈值触发。面板里的「换出口」和 `/api/interval?seconds=300` 是另一项独立功能：到点重新注册账号以更换出口 IP。这项启动时关闭，`0` 表示关闭，其他值至少按 60 秒计。`/api/rotate?slot=1` 会立刻重新注册指定账号；`slot=0` 重新注册编号最小的实例。重新注册得到的新身份只在当前进程里生效，不会写回 `STATE_DIR`。

### 黏性

`LB_STICKY_MODE` 就是 `--sticky`。它决定一条连接第一次落到哪个账号，以及之后是否还走这个账号。映射只在进程内存里；重启进程、实例成功重连或保身份重启后，该实例的用户名映射会清空，新连接重新分配。

用户名从入口认证来。没有设置 `SOCKS_USER` / `SOCKS_PASS` 时，SOCKS5 用户名密码方法里的用户名，或 HTTP 代理 Basic 里的用户名，只用于黏性，密码不校验。设置了入口账号密码后，客户端必须使用这一组；这时所有连接都是同一个用户名，按用户名黏住就会进同一个账号。除 `ip-hash` 外，没有用户名的连接按 `LB_STRATEGY` 调度。

- `none`：不黏。每条连接都走 `LB_STRATEGY`。
- `username-round`：记住用户名第一次分到的账号。第一次在可接流量的账号里，选已经黏住的用户名最少的；数量相同就按顺序轮转。
- `username-least`：同样记住第一次的结果。第一次选的是当前活跃连接最少的账号，数量相同按顺序轮转。之后连接变少也不会改派。
- `username-hash`：用用户名做稳定哈希，只在当前可接流量的账号里选择。不保存映射。原来的账号停用、排空或离线后，下次会在剩下的账号里重算，出口可能变化。
- `ip-hash`：忽略用户名，用客户端 IP 做同样的哈希。匿名连接也按 IP 黏住。`client-ip-hash` 是同一个值。账号不可用时会在剩下的账号里重算。

`username-round` 和 `username-least` 记住的实例进入排空、停用或失联后，下次请求会立即在其他可用实例中重新选择并绑定；原实例恢复后不会自动迁回。所有实例都不可接入时才拒绝连接。面板实例页的「黏性用户数」只统计这两种模式的用户名映射，独立的本轮累计用户数和累计连接数列在「重启统计」中；重新连接成功后对应实例的两种统计都清零。

### 解析

`RESOLVE_PREFERENCE` 就是 `--resolve`，只影响隧道里的目标地址。别名可以用减号。`ipv4`、`v4` 等于 `ipv4_only`，`ipv6`、`v6` 等于 `ipv6_only`。

- `auto` 和 `ipv4_prefer`：同时查询 IPv4 和 IPv6。两者都有时用 IPv4，只有 IPv6 时用 IPv6。
- `ipv6_prefer`：两者都有时用 IPv6，没有 IPv6 时退回 IPv4。
- `ipv4_only`：只使用 IPv4。字面量 IPv6 会被拒绝。
- `ipv6_only`：只使用 IPv6。字面量 IPv4 会被拒绝。隧道没有 IPv6 地址时解析失败。

### 出口检查

隧道就绪后，每个账号按 `HEALTH_CHECK_INTERVAL` 同时做两次出口检查：IPv4 连 `104.16.124.96`，IPv6 连 `2606:4700::11`，TLS 仍使用 `www.cloudflare.com`。默认 `60s`。这两次请求会在 HTTP/2 上产生数据，避免上游或中间网络因为大约两分钟没有流量就把连接关掉。`0` 关闭。某一族失败只让面板那一列显示「未测到」，不拆隧道；两条都没确认 `warp=on` 或 `warp=plus` 时，初次连接和保身份重连才会重试。出口 IP 或 `warp` 状态变了才记日志。单次检查最长 `HEALTH_CHECK_TIMEOUT`，默认 `20s`。面板上的 IPv4 出口和 IPv6 出口是这两次探测的公网地址，接口地址只在提示里。

### 可组合的保身份重启

自动重启保留原有 WARP 账号身份，只重连隧道并重新验证 `warp=on` 或 `warp=plus`；失败后退避重试（1 秒起，最长 30 秒），成功前不接受新请求。

三种阈值**各自独立且可以同时开启**，任意达到就触发（OR 关系）：

| 配置项 | 含义 | 示例 |
| :--- | :--- | :--- |
| `RESTART_MAX_UPTIME` | 实例从最近一次成功连接起运行的时长；成功重连后重新计时 | `24h` |
| `RESTART_MAX_USERS` | 从上次成功连接起累计去重用户数，认证用户按用户名、匿名用户按客户端 IP 区分 | `1000` |
| `RESTART_MAX_CONNECTIONS` | 从上次成功连接起累计接入的连接次数，断开的连接也已经计数 | `10000` |

每个阈值 `0` 表示关闭；三个都为 `0` 表示完全关闭**自动**重启，不影响手动重连、换出口和故障恢复。阈值是按实例分别计算的，不是整个池的总计。入口若只有一组 `SOCKS_USER`，所有认证请求都计为一个用户；用户数不代表同时在线人数。为控制长期运行内存，单实例用户阈值上限为 `1000000`，超出时拒绝配置。

**排空和重启是两个队列，不存在排空超时：**

1. 任意阈值达到时，触发的那条连接先被接收，实例随后立即摘流，进入排空队列；此后新用户和老用户都不能再建立到该实例的连接。
2. 已建立的连接继续传输，不会因为自动重启而被强制中断。默认每 `10s`（`RESTART_DRAIN_CHECK_INTERVAL`）检查排空队列；实例活跃连接数归零后移到重启队列。某个长连接一直不结束，实例就一直排空等待。
3. 重启队列由 `RESTART_CONCURRENCY` 控制实际同时重连的实例数。重连并确认 WARP 正常后，该实例的运行时间、去重用户、累计连接和旧黏性映射重置，恢复接入。失败时实例保持不可接入，后台持续重试。排空检查不会每轮刷日志，也不会为每个排队实例开一个等待任务。
4. 老用户再次发起新请求时，只会选择其他可用实例。`username-round` 和 `username-least` 会在改派后保存新绑定，原实例恢复也不会自动迁回；`username-hash` 和 `ip-hash` 是无状态哈希，原实例恢复后按当前可用实例集合重新计算，可能回到原实例。若所有实例都不可用，入口拒绝新连接。

`RESTART_PROBE_TIMEOUT` 默认 `90s`，控制单次重连的出口验证时长；`RESTART_CONCURRENCY` 默认 `1`，只限制实际重连及重试并发，不限制排空队列长度。运行时降低阈值会立即检查已有统计并按需摘流。启用之前关闭的用户数阈值时，从启用时起重新统计去重身份。

运行中可以在管理面板同时修改三个阈值，或调用：

```sh
curl -H "X-Warp-Token: <token>" \
  "http://127.0.0.1:47100/api/restart-policy?max_uptime_seconds=86400&max_users=1000&max_connections=10000"
```

上述 API 任一参数都可省略（代表保留原值），为 `0` 则关闭对应条件。**三个阈值全部关闭时，尚在排空队列或待重启队列、未取得执行权的自动任务会取消，并在旧隧道仍可用时恢复接入。** 此时取消任务的实例会清零本轮统计并重新开始运行时间计时，避免以后重新开启阈值时立刻重复排空。已开始执行的自动重连及失败后的恢复重试继续完成；手动强制重启也不受影响。`/api/status` 返回当前三个阈值、排空队列 `drain_queue`、待重启队列 `restart_queue`、各实例本轮累计值和活跃连接数。

管理员仍可调用 `/api/restart?slot=1` **手动强制重连**：立即摘流并取得同一重启并发名额，不等待活跃连接归零，因此可能打断已有连接；`slot=0` 顺序处理所有实例。`/api/reconnect`、`/api/rotate` 和隧道故障恢复属于独立的直接重建路径，也不提供自动排空保证。

**旧配置迁移：**旧的 `ROTATE_RESTART_MODE`、`ROTATE_RESTART_THRESHOLD`、`ROTATE_RESTART_INTERVAL`、`ROTATE_RESTART_BATCH`、`ROTATE_RESTART_MISFIRE`、`ROTATE_RESTART_DEFER`、`ROTATE_RESTART_DRAIN_TIMEOUT`、`ROTATE_RESTART_FORCE_AFTER` 等环境变量已移除；发现遗留环境变量时程序会提示并忽略，不会再启用旧策略。旧的同名命令行参数会明确报错。`/api/select`（固定实例）已删除；旧的 `/api/restart-plan` 返回迁移提示。

## Docker

镜像在 GitHub Actions 里构建并推到 GHCR，同时包含 `linux/amd64` 和 `linux/arm64`。推送到 `main` 会打 `latest`，推送到 `dev` 会打 `dev`，发布 `v*` 标签或 Release 会打对应版本号。容器里不需要启动脚本，所有配置都是环境变量，名字和 MicroWARP 里能对应的保持一致。

```sh
docker compose up -d
docker logs warp-proxy
```

代理默认只发布在 `127.0.0.1:1080`，管理面板在 `127.0.0.1:47100`。管理密码用 `CONTROL_PASSWORD` 设置，未设置时是 `admin`。标准输出里的 `controlToken` 就是这个密码。账号保存在 `warp-proxy-state` 卷里。

长期运行时，`docker-compose.yml` 为容器标准输出和错误日志启用了轮转：单文件上限 10 MiB，最多保留 3 个文件，防止 Docker 日志无限占用磁盘。进程内的面板日志不写文件；如果直接运行二进制并将输出重定向到文件，请自行配置 logrotate 或由 systemd/journald 限制磁盘用量。

| 变量 | 默认 | 作用 |
| :--- | :--- | :--- |
| `INSTANCE_COUNT` | 容器 `1`，本机二进制 `2` | 启动及运行时自动恢复实例的数量上限；手动添加可超出 |
| `BIND_ADDR` / `BIND_PORT` | 容器 `0.0.0.0:1080` | 代理监听地址。可以只写主机，端口用 `BIND_PORT` |
| `CONTROL_ADDR` / `CONTROL_PORT` | 容器 `0.0.0.0:47100` | 管理面板和控制接口 |
| `STATE_DIR` | 容器 `/var/lib/warp-proxy` | 账号身份目录 |
| `MICROWARP_DIR` | `STATE_DIR/instances` | MicroWARP 的 `instances` 或其上一级目录，启动和运行时自动迁移 |
| `MICROWARP_SCAN_INTERVAL` | `60s` | 运行时检测新增配置的间隔，`0` 关闭运行时扫描（启动扫描仍执行） |
| `PROXY_MODE` | `socks5` | `mixed` 或 `http` 时同一端口同时接受 HTTP 代理 |
| `MASQUE_HTTP2` | `0` | `1` 改用 HTTP/2。配置了上游时会自动打开 |
| `UPSTREAM_SOCKS5` | 空 | 上游 SOCKS5，多个用逗号分隔 |
| `UPSTREAM_PROBE_TIMEOUT` | `8s` | 启动前探测上游的时间 |
| `HEALTH_CHECK_INTERVAL` | `60s` | 经隧道检查出口的间隔，`0` 关闭。见「出口检查」 |
| `HEALTH_CHECK_TIMEOUT` | `20s` | 单次出口检查的最长时间 |
| `SOCKS_USER` / `SOCKS_PASS` | 空 | 入口认证。两个要一起设置 |
| `CONTROL_PASSWORD` | `admin` | 管理面板和控制接口密码。请求头仍然是 `X-Warp-Token` |
| `RESOLVE_PREFERENCE` | `auto` | 隧道内目标地址的地址族，见「解析」 |
| `LB_STRATEGY` | `round` | 没有被黏性接走的连接如何选账号，见「调度」 |
| `LB_STICKY_MODE` | `username-round` | 见上方「黏性」。`client-ip-hash` 与 `ip-hash` 相同 |
| `LB_ROTATE_INTERVAL` | `5m` | 仅 `LB_STRATEGY=rotate` 时的换账号时间窗，见「调度」 |
| `LB_ACCESS_LOG` | `0` | `1` 把连接记到标准错误，不记录密码 |
| `RESTART_MAX_UPTIME` | `0` | 实例运行时长阈值，`24h` 等；`0` 关闭 |
| `RESTART_MAX_USERS` | `0` | 每轮累计去重用户上限，最大 `1000000`，`0` 关闭 |
| `RESTART_MAX_CONNECTIONS` | `0` | 每轮累计接入连接数上限，`0` 关闭 |
| `RESTART_DRAIN_CHECK_INTERVAL` | `10s` | 排空队列检测间隔，必须大于 `0`；无排空超时 |
| `RESTART_PROBE_TIMEOUT` | `90s` | 重连后确认 `warp=on` 或 `warp=plus` 的时间 |
| `RESTART_CONCURRENCY` | `1` | 实际重连和后台重试的并发上限 |

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
