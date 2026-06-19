# ndn-rtc-signaling-relay — HTTP rendezvous server for ndn-face-webrtc.
#
# Build (from repo root):
#   docker build -f crates/ndn-rtc-signaling-relay/Dockerfile \
#     -t ndn-rtc-signaling-relay .
#
# Run with default bind (0.0.0.0:8888):
#   docker run --rm -p 8888:8888 ndn-rtc-signaling-relay
#
# Or bind to a different address:
#   docker run --rm -p 9000:9000 ndn-rtc-signaling-relay --bind 0.0.0.0:9000
#
# Same multi-stage cargo-chef pattern as binaries/ndn-fwd/Dockerfile so
# external deps cache cleanly across source-only changes.

# ── Stage 1: chef base ────────────────────────────────────────────────────────
FROM rust:slim AS chef

RUN cargo install cargo-chef --locked

RUN apt-get update && apt-get install -y --no-install-recommends \
    pkg-config \
    libdbus-1-dev \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /build

# ── Stage 2: planner ──────────────────────────────────────────────────────────
FROM chef AS planner
COPY . .
RUN cargo chef prepare --recipe-path recipe.json

# ── Stage 3: cacher ───────────────────────────────────────────────────────────
FROM chef AS cacher
COPY --from=planner /build/recipe.json recipe.json
RUN cargo chef cook --release --bin ndn-rtc-signaling-relay --recipe-path recipe.json

# ── Stage 4: builder ──────────────────────────────────────────────────────────
FROM chef AS builder
COPY . .
COPY --from=cacher /build/target target
RUN cargo build --release --bin ndn-rtc-signaling-relay

# ── Stage 5: runtime image ────────────────────────────────────────────────────
FROM debian:trixie-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

COPY --from=builder /build/target/release/ndn-rtc-signaling-relay \
    /usr/local/bin/ndn-rtc-signaling-relay

EXPOSE 8888/tcp

ENTRYPOINT ["ndn-rtc-signaling-relay"]
CMD ["--bind=0.0.0.0:8888"]
