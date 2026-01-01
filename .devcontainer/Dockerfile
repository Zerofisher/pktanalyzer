FROM debian:bookworm

# Install base dependencies
RUN apt-get update && apt-get install -y \
    git \
    curl \
    wget \
    build-essential \
    libpcap-dev \
    tcpdump \
    iproute2 \
    iputils-ping \
    net-tools \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# Install Go 1.24 (latest stable, compatible with go 1.25.0 directive)
ARG GO_VERSION=1.24.4
RUN curl -fsSL "https://go.dev/dl/go${GO_VERSION}.linux-$(dpkg --print-architecture).tar.gz" | tar -C /usr/local -xzf -
ENV PATH="/usr/local/go/bin:/root/go/bin:${PATH}"
ENV GOPATH="/root/go"

# Verify Go installation
RUN go version

# Set working directory
WORKDIR /workspace

# Default command
CMD ["bash"]
