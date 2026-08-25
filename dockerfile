# syntax=docker/dockerfile:1
FROM debian:trixie

RUN rm -f /etc/apt/apt.conf.d/docker-clean

## Installing the packages
RUN --mount=type=cache,target=/var/cache/apt,sharing=locked \
    --mount=type=cache,target=/var/lib/apt,sharing=locked \
    apt-get update && apt-get install -y --no-install-recommends \
    linux-headers-arm64 \
    sudo \
    git \
    make \
    gcc \
    clang \
    build-essential \
    llvm \
    libstdc++6 \
    libbpf-dev \
    libelf-dev \
    libbpfcc-dev \
    bpftool \
    bpfcc-tools \
    xdp-tools \
    pkg-config \
    ca-certificates \
    openssh-server \
    wget \
    curl \
    tcpdump \
    iproute2 \

## SSH Connection
RUN useradd -m -s /bin/bash appuser \
    && mkdir -p /var/run/sshd /home/appuser/.ssh \
    && chmod 700 /home/appuser/.ssh \
    && echo "appuser ALL=(ALL) NOPASSWD:ALL" >> /etc/sudoers

COPY --chown=appuser:appuser id_ed25519.pub /home/appuser/.ssh/authorized_keys

## SSH File Permissions
RUN chmod 600 /home/appuser/.ssh/authorized_keys \
    && chown -R appuser:appuser /home/appuser/.ssh \
    && chmod 700 /home/appuser/.ssh

RUN printf "PasswordAuthentication no\nPermitRootLogin no\n" >> /etc/ssh/sshd_config

WORKDIR /workspace
RUN chown appuser:appuser /workspace

EXPOSE 22

CMD ["/usr/sbin/sshd", "-D"]