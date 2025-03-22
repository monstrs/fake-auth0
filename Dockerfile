FROM rust:bookworm AS builder

WORKDIR /workspace

COPY . .

RUN --mount=type=cache,target=/usr/local/cargo/registry cargo build --release

FROM debian:bookworm-slim

WORKDIR /workspace

COPY --from=builder /workspace/target/release/fake-auth0 /workspace/fake-auth0
COPY --from=builder /workspace/self_signed_certs /workspace/self_signed_certs
RUN chmod +x /workspace/fake-auth0

EXPOSE 3000

CMD "./fake-auth0"