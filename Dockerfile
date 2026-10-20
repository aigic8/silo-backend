# Multi-stage build with a non-root runtime user.
#
# The `rust:1-slim-bookworm` builder and `debian:bookworm-slim` runtime share
# glibc, so the binary built in stage one runs unchanged in stage two. sqlx is
# configured with rustls, so the runtime image does not need OpenSSL.

FROM rust:1-slim-bookworm AS builder
WORKDIR /app

COPY Cargo.toml Cargo.lock ./
COPY src ./src
COPY migrations ./migrations

RUN cargo build --release --locked

FROM debian:bookworm-slim
RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates curl \
    && rm -rf /var/lib/apt/lists/* \
    && useradd --create-home --uid 10001 appuser

COPY --from=builder /app/target/release/silo-backend /usr/local/bin/silo-backend
COPY --from=builder /app/migrations /app/migrations

WORKDIR /app
USER appuser
EXPOSE 3000

CMD ["/usr/local/bin/silo-backend"]
