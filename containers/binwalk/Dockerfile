# syntax=docker/dockerfile:1
FROM docker.io/library/rust:1.85-slim-bookworm AS builder

RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    pkg-config \
    libfontconfig1-dev \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# Pin exact Binwalk v3 release (3.1.0)
RUN cargo install --locked binwalk --version 3.1.0 --root /usr/local

FROM docker.io/library/debian:bookworm-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
    libfontconfig1 \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/* \
    && groupadd -g 10001 firmlens \
    && useradd -u 10001 -g 10001 -M -s /usr/sbin/nologin firmlens

COPY --from=builder /usr/local/bin/binwalk /usr/local/bin/binwalk

USER 10001:10001
WORKDIR /input
ENTRYPOINT ["/usr/local/bin/binwalk"]
CMD ["--help"]
