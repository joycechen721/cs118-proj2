FROM ubuntu:22.04
ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && \
    apt-get install --yes --no-install-recommends \
    autoconf \
    build-essential \
    sudo \
    wget \
    curl \
    git-all \
    iproute2 \
    iputils-ping \
    net-tools \
    dnsutils \
    netcat \
    tcpdump \
    iptables \
    pkg-config \
    python3 \
    python3-pip \
    libssl-dev \
    g++ \
    make && \
    rm -rf /var/lib/apt/lists/*
