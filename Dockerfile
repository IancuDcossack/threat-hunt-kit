# threat-hunt-kit/Dockerfile
FROM ubuntu:22.04

# Install all tools and dependencies in one layer
RUN apt-get update && \
    DEBIAN_FRONTEND=noninteractive apt-get install -y \
    tcpdump \
    wireshark-common \ # Provides tshark (CLI version of Wireshark)
    curl \
    git \
    vim \
    jq \
    python3 \
    python3-pip \
    software-properties-common && \
    # Install Zeek
    curl -fsSL https://download.opensuse.org/repositories/security:zeek/Debian_12/Release.key | gpg --dearmor | tee /etc/apt/trusted.gpg.d/security_zeek.gpg > /dev/null && \
    echo 'deb http://download.opensuse.org/repositories/security:/zeek/Debian_12/ /' | tee /etc/apt/sources.list.d/security:zeek.list && \
    apt-get update && apt-get install -y zeek && \
    # Install Suricata
    add-apt-repository -y ppa:oisf/suricata-stable && \
    apt-get update && apt-get install -y suricata && \
    # Clean up
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

# Create directories and copy default configs
RUN mkdir -p /opt/pcaps /var/log/nsm
COPY configs/ /etc/nsm-configs/

# Entrypoint script that can handle different commands
COPY scripts/entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

ENTRYPOINT ["/entrypoint.sh"]
USER nobody
USER nobody