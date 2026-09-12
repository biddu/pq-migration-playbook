# Post-Quantum Migration: An Engineer's Playbook -- companion image.
#
# Everything the labs in labs/ch01 .. labs/ch12 need, pinned to the versions the book's numbers
# were measured with (Appendix D). Build once, then run any lab or test suite inside it:
#
#   docker build -t pqm-labs .
#   docker run --rm -it -v "$PWD":/work pqm-labs bash
#   PQ_LAB_IMPL=solution pytest labs/ch05/tests
#
# The image compiles OpenSSL 3.5, OpenSSH 10 and liboqs from source because no long-term
# distribution shipped all three at the versions needed when this book was written. A build
# takes 10 to 20 minutes on a laptop. Versions are arguments so that you can move them.

FROM debian:bookworm-slim AS build

ARG OPENSSL_VERSION=3.5.4
ARG OPENSSH_VERSION=10.1p1
ARG LIBOQS_VERSION=0.16.0
ARG GO_VERSION=1.24.7

ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update && apt-get install -y --no-install-recommends \
      build-essential ca-certificates curl cmake ninja-build git perl zlib1g-dev libpam0g-dev \
      autoconf automake pkg-config python3 python3-dev python3-pip python3-venv \
    && rm -rf /var/lib/apt/lists/*

# ---- OpenSSL 3.5 (ML-KEM, ML-DSA, SLH-DSA in the default provider; hybrid TLS groups) ----
WORKDIR /src
RUN curl -fsSLO https://github.com/openssl/openssl/releases/download/openssl-${OPENSSL_VERSION}/openssl-${OPENSSL_VERSION}.tar.gz \
 && tar xzf openssl-${OPENSSL_VERSION}.tar.gz \
 && cd openssl-${OPENSSL_VERSION} \
 && ./Configure --prefix=/opt/openssl35 --openssldir=/opt/openssl35/ssl shared \
 && make -j"$(nproc)" >/dev/null && make install_sw install_ssldirs >/dev/null

# ---- OpenSSH 10 built against OpenSSL 3.5 (mlkem768x25519-sha256 default; WarnWeakCrypto) ----
RUN curl -fsSLO https://cdn.openbsd.org/pub/OpenBSD/OpenSSH/portable/openssh-${OPENSSH_VERSION}.tar.gz \
 && tar xzf openssh-${OPENSSH_VERSION}.tar.gz \
 && cd openssh-${OPENSSH_VERSION} \
 && ./configure --prefix=/opt/openssh10 --with-ssl-dir=/opt/openssl35 \
      --with-ldflags="-Wl,-rpath,/opt/openssl35/lib64" --sysconfdir=/opt/openssh10/etc \
 && make -j"$(nproc)" >/dev/null && make install-nokeys >/dev/null

# ---- liboqs (SLH-DSA, Falcon, HQC for Lab 2.1; research grade, not for production) ----
RUN git clone --depth 1 --branch ${LIBOQS_VERSION} https://github.com/open-quantum-safe/liboqs.git \
 && cmake -S liboqs -B liboqs/build -GNinja -DBUILD_SHARED_LIBS=ON -DOQS_BUILD_ONLY_LIB=ON \
      -DCMAKE_INSTALL_PREFIX=/opt/liboqs \
 && ninja -C liboqs/build >/dev/null && ninja -C liboqs/build install >/dev/null

# ---- Go (Lab 12.1 harness; Pebble for Lab 7.3) ----
RUN curl -fsSL https://go.dev/dl/go${GO_VERSION}.linux-amd64.tar.gz | tar -C /usr/local -xz

# =====================================================================================
FROM debian:bookworm-slim

ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update && apt-get install -y --no-install-recommends \
      ca-certificates python3 python3-pip python3-venv git softhsm2 opensc libpam0g procps \
      build-essential python3-dev \
    && rm -rf /var/lib/apt/lists/*

COPY --from=build /opt/openssl35 /opt/openssl35
COPY --from=build /opt/openssh10 /opt/openssh10
COPY --from=build /opt/liboqs    /opt/liboqs
COPY --from=build /usr/local/go  /usr/local/go

# The labs read these. LD_LIBRARY_PATH is what makes Python's ssl module (Lab 12.1) load 3.5.
ENV OPENSSL_BIN=/opt/openssl35/bin/openssl \
    OPENSSH_PREFIX=/opt/openssh10 \
    LD_LIBRARY_PATH=/opt/openssl35/lib64:/opt/liboqs/lib \
    OQS_INSTALL_PATH=/opt/liboqs \
    PATH=/opt/openssl35/bin:/opt/openssh10/bin:/usr/local/go/bin:/root/go/bin:$PATH \
    PIP_BREAK_SYSTEM_PACKAGES=1 \
    PYTHONDONTWRITEBYTECODE=1

COPY requirements.txt /tmp/requirements.txt
RUN pip install --no-cache-dir -r /tmp/requirements.txt

# Pebble (Let's Encrypt's test CA) for Lab 7.3. Built with the Go above; a Pebble built with
# Go 1.27+ can also issue ML-DSA certificates (Chapter 7).
RUN go install github.com/letsencrypt/pebble/v2/cmd/pebble@latest

# An unprivileged user for sshd in Lab 6.1 (sshd refuses to run without one).
RUN useradd -m -s /bin/bash lab && mkdir -p /opt/openssh10/var/empty

WORKDIR /work
CMD ["bash"]
