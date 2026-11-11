# syntax=docker/dockerfile:1
# 多平台镜像：在构建机器上交叉编译 warp-proxy，运行层只保留一个静态链接以外的 glibc 二进制。
# 支持 linux/amd64 与 linux/arm64。配置全部来自环境变量，不需要启动脚本。

FROM --platform=$BUILDPLATFORM rust:1-bookworm AS builder
ARG BUILDPLATFORM
ARG TARGETARCH
WORKDIR /src

RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        ca-certificates \
        gcc-aarch64-linux-gnu \
        libc6-dev-arm64-cross \
        gcc-x86-64-linux-gnu \
        libc6-dev-amd64-cross \
    && rm -rf /var/lib/apt/lists/*

COPY . .

RUN set -eu; \
    build_arch="${BUILDPLATFORM#*/}"; \
    if [ "${TARGETARCH}" = "${build_arch}" ]; then \
        cargo build --locked --release -p warp-proxy; \
        cp target/release/warp-proxy /warp-proxy; \
    else \
        case "${TARGETARCH}" in \
            arm64) target=aarch64-unknown-linux-gnu; gcc=aarch64-linux-gnu-gcc ;; \
            amd64) target=x86_64-unknown-linux-gnu; gcc=x86_64-linux-gnu-gcc ;; \
            *) echo "unsupported TARGETARCH=${TARGETARCH}" >&2; exit 1 ;; \
        esac; \
        rustup target add "${target}"; \
        linker_env="CARGO_TARGET_$(printf '%s' "${target}" | tr 'abcdefghijklmnopqrstuvwxyz-' 'ABCDEFGHIJKLMNOPQRSTUVWXYZ_')_LINKER"; \
        cc_env="CC_$(printf '%s' "${target}" | tr '-' '_')"; \
        export "${linker_env}=${gcc}"; \
        export "${cc_env}=${gcc}"; \
        cargo build --locked --release --target "${target}" -p warp-proxy; \
        cp "target/${target}/release/warp-proxy" /warp-proxy; \
    fi

FROM debian:bookworm-slim

RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates wget \
    && rm -rf /var/lib/apt/lists/* \
    && useradd --system --create-home --home-dir /var/lib/warp-proxy --shell /usr/sbin/nologin warp

COPY --from=builder /warp-proxy /usr/local/bin/warp-proxy

# 容器里默认监听所有网卡。本机直接运行二进制时仍是 127.0.0.1。
ENV BIND_ADDR=0.0.0.0 \
    BIND_PORT=1080 \
    CONTROL_ADDR=0.0.0.0 \
    CONTROL_PORT=47100 \
    CONTROL_PASSWORD=admin \
    STATE_DIR=/var/lib/warp-proxy \
    INSTANCE_COUNT=1 \
    PROXY_MODE=socks5 \
    MASQUE_HTTP2=0 \
    RESOLVE_PREFERENCE=auto \
    LB_STRATEGY=round \
    LB_STICKY_MODE=username-round \
    LB_ROTATE_INTERVAL=5m \
    LB_ACCESS_LOG=0 \
    RESTART_MAX_UPTIME=0 \
    RESTART_MAX_USERS=0 \
    RESTART_MAX_CONNECTIONS=0 \
    RESTART_DRAIN_CHECK_INTERVAL=10s \
    RESTART_DRAIN_TIMEOUT=300s \
    RESTART_PROBE_TIMEOUT=90s \
    RESTART_CONCURRENCY=1 \
    UPSTREAM_PROBE_TIMEOUT=8s \
    HEALTH_CHECK_INTERVAL=60s \
    HEALTH_CHECK_TIMEOUT=20s

VOLUME ["/var/lib/warp-proxy"]
EXPOSE 1080/tcp 47100/tcp
USER warp

HEALTHCHECK --interval=30s --timeout=5s --start-period=120s --retries=3 \
    CMD wget -q -O /dev/null "http://127.0.0.1:${CONTROL_PORT}/" || exit 1

ENTRYPOINT ["warp-proxy"]
