# syntax=docker/dockerfile:1
#
# siphon-rtp engine — fully static musl image (the zero-C decision is what keeps this clean: the
# runtime is just the binary + the embedded BPF object, so it lands on distroless/scratch).
# cargo-chef layer-caches dependencies, mirroring siphon-sip's Dockerfile.
#
#   docker build -t siphon-rtp .                      # UDP-backend image (any kernel)
#   docker build --build-arg CARGO_FEATURES=xdp .     # once the eBPF crate lands
#
# See docker-compose.yml for the dev (veth + SKB XDP) and prod (host-net + native XDP) profiles.

# ── Chef base: Rust + musl toolchain + cargo-chef ────────────────────────────────────────
FROM debian:trixie-slim AS chef
RUN apt-get update && apt-get install -y --no-install-recommends \
        ca-certificates curl build-essential pkg-config musl-tools clang \
    && rm -rf /var/lib/apt/lists/*
RUN curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y --default-toolchain stable
ENV PATH="/root/.cargo/bin:${PATH}"
RUN rustup target add x86_64-unknown-linux-musl && cargo install cargo-chef --locked
# jemalloc (the one accepted -sys dep) is compiled by musl-gcc for the static target.
ENV CC_x86_64_unknown_linux_musl=musl-gcc
WORKDIR /build

# ── Planner: capture the dependency recipe ───────────────────────────────────────────────
FROM chef AS planner
COPY . .
RUN cargo chef prepare --recipe-path recipe.json

# ── Builder: cook deps (cached until Cargo.lock changes), then build the engine ──────────
FROM chef AS builder
# Opt-in XDP datapath (aya XDP program via its own pinned-nightly toolchain). Empty by default so
# the image builds anywhere without nightly — the binary then runs the UDP-loopback backend.
ARG CARGO_FEATURES=""
COPY --from=planner /build/recipe.json recipe.json
RUN cargo chef cook --release --target x86_64-unknown-linux-musl \
        --recipe-path recipe.json -p siphon-rtp-engine ${CARGO_FEATURES:+--features "$CARGO_FEATURES"}
COPY . .
RUN cargo build --release --target x86_64-unknown-linux-musl \
        -p siphon-rtp-engine ${CARGO_FEATURES:+--features "$CARGO_FEATURES"} \
 && cp target/x86_64-unknown-linux-musl/release/siphon-rtp-engine /siphon-rtp-engine

# ── Runtime (prod): distroless static, just the binary ───────────────────────────────────
FROM gcr.io/distroless/static-debian12 AS runtime
COPY --from=builder /siphon-rtp-engine /usr/local/bin/siphon-rtp-engine
EXPOSE 8080
ENTRYPOINT ["/usr/local/bin/siphon-rtp-engine"]
CMD ["--control", "0.0.0.0:8080"]

# ── Runtime (dev): shell + iproute2 to set up a veth pair for SKB-mode XDP testing ───────
FROM debian:trixie-slim AS runtime-dev
RUN apt-get update && apt-get install -y --no-install-recommends iproute2 \
    && rm -rf /var/lib/apt/lists/*
COPY --from=builder /siphon-rtp-engine /usr/local/bin/siphon-rtp-engine
COPY deploy/dev-entrypoint.sh /usr/local/bin/dev-entrypoint.sh
RUN chmod +x /usr/local/bin/dev-entrypoint.sh
EXPOSE 8080
ENTRYPOINT ["/usr/local/bin/dev-entrypoint.sh"]
CMD ["--control", "0.0.0.0:8080"]
