# ── Connector-OSS Server ─────────────────────────────────────────
# Multi-stage build → scratch final image (~8MB, 0 CVEs)
#
# Build:
#   docker build -t connector-oss .
#
# Run:
#   docker run -p 8080:8080 -e DEEPSEEK_API_KEY=sk-... connector-oss
#
# With persistence:
#   docker run -p 8080:8080 \
#     -e DEEPSEEK_API_KEY=sk-... \
#     -e CONNECTOR_ENGINE_STORAGE=sqlite:/data/connector.db \
#     -e CONNECTOR_CELL_ID=cell_us_east_1 \
#     -v connector-data:/data \
#     connector-oss
#
# With custom YAML config:
#   docker run -p 8080:8080 \
#     -v ./my-config.yaml:/config/connector.yaml \
#     -e CONNECTOR_CONFIG=/config/connector.yaml \
#     connector-oss

# ── Stage 1: Build ───────────────────────────────────────────────
FROM rust:1.82-alpine AS builder

RUN apk add --no-cache musl-dev openssl-dev openssl-libs-static pkgconfig

WORKDIR /build
COPY . .

RUN cargo build --release --target x86_64-unknown-linux-musl \
    -p connector-server \
    --manifest-path connector/Cargo.toml

# ── Stage 2: Scratch (0 CVEs, ~8MB) ─────────────────────────────
FROM scratch

COPY --from=builder /build/connector/target/x86_64-unknown-linux-musl/release/connector-server /connector-server

# Default environment
ENV CONNECTOR_ADDR=0.0.0.0:8080
ENV CONNECTOR_ENGINE_STORAGE=memory
ENV RUST_LOG=info

EXPOSE 8080

HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
    CMD ["/connector-server", "--health-check"]

ENTRYPOINT ["/connector-server"]
