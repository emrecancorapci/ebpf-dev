# syntax=docker/dockerfile:1
FROM debian:trixie

RUN rm -f /etc/apt/apt.conf.d/docker-clean

RUN --mount=type=cache,target=/var/cache/apt,sharing=locked \
    --mount=type=cache,target=/var/lib/apt,sharing=locked \
    apt-get update && apt-get install -y --no-install-recommends \
    clang \
    llvm \
    libbpf-dev \
    bpftool \
    build-essential \
    libelf-dev \
    pkg-config \
    git \
    make \
    gcc \
    ca-certificates \
    openssh-server \
    sudo \
    wget \
    xdp-tools \
    just \
    bpfcc-tools \
    libbpfcc-dev \
    curl \
    libstdc++6 \
    tcpdump \
    iproute2 \
    linux-headers-arm64

RUN useradd -m -s /bin/bash appuser \
    && mkdir -p /var/run/sshd /home/appuser/.ssh \
    && chmod 700 /home/appuser/.ssh \
    && echo "appuser ALL=(ALL) NOPASSWD:ALL" >> /etc/sudoers

COPY --chown=appuser:appuser id_ed25519.pub /home/appuser/.ssh/authorized_keys
RUN chmod 600 /home/appuser/.ssh/authorized_keys \
    && chown -R appuser:appuser /home/appuser/.ssh \
    && chmod 700 /home/appuser/.ssh

RUN printf "PasswordAuthentication no\nPermitRootLogin no\n" >> /etc/ssh/sshd_config

WORKDIR /workspace
RUN chown appuser:appuser /workspace

EXPOSE 22

CMD ["/usr/sbin/sshd", "-D"]