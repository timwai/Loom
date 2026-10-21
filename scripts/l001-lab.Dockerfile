FROM golang:1.23-bookworm@sha256:167053a2bb901972bf2c1611f8f52c44d5fe7e762e5cab213708d82c421614db AS go
FROM rust:1.90.0-slim-bookworm@sha256:64232e656c058f4468e8d024e990acff04f0fd5a5c0a88a574dc37773d7325c9
RUN apt-get update -qq && apt-get install -y --no-install-recommends \
    make cmake python3 nodejs default-jdk-headless kotlin iproute2 ca-certificates \
    && rm -rf /var/lib/apt/lists/*
COPY --from=go /usr/local/go /usr/local/go
WORKDIR /workspace
ENV CARGO_TARGET_DIR=/build
ENV PATH=/usr/local/go/bin:${PATH}
