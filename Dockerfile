# ── Stage 1: Build ────────────────────────────────────────────────
FROM rust:1.75-alpine AS builder

RUN apk add --no-cache musl-dev openssl-dev openssl-libs-static

WORKDIR /build
COPY . .

RUN cargo build --release --target x86_64-unknown-linux-musl \
    -p connector-server \
    --manifest-path connector/Cargo.toml

# ── Stage 2: Scratch (0 CVEs, ~5MB) ──────────────────────────────
FROM scratch

COPY --from=builder /build/connector/target/x86_64-unknown-linux-musl/release/connector-server /connector-server

EXPOSE 8080

ENTRYPOINT ["/connector-server"]
