FROM kalilinux/kali-rolling:latest

ENV DEBIAN_FRONTEND=noninteractive
# Pin Sliver so builds are reproducible (assets: sliver-server_linux-amd64 / sliver-client_linux-amd64)
ARG SLIVER_VERSION=v1.7.7

# Some networks get 403 from http.kali.org (Cloudflare); use a stable mirror.
# Harmless when the default repo works — apt just re-reads sources.
RUN (grep -q 'ftp.halifax' /etc/apt/sources.list 2>/dev/null || \
    echo 'deb http://ftp.halifax.rwth-aachen.de/kali kali-rolling main contrib non-free non-free-firmware' > /etc/apt/sources.list) && \
    rm -f /etc/apt/sources.list.d/*.sources /etc/apt/sources.list.d/*.list 2>/dev/null; true

# System + attack toolset. Everything the Action Center needs lives HERE,
# so red-team actions and terminal sessions run inside this image.
RUN apt-get update && apt-get install -y --no-install-recommends \
    python3-pip python3-venv python3-dnspython python3-requests python3-yaml \
    nmap metasploit-framework git curl ca-certificates \
    hydra sqlmap wpscan nikto testssl.sh tmux wordlists docker.io \
    && (apt-get install -y --no-install-recommends crackmapexec || true) \
    && rm -rf /var/lib/apt/lists/*

# rockyou ships gzipped; decompress so hydra paths just work
RUN gunzip -kf /usr/share/wordlists/rockyou.txt.gz || true

# Sliver C2 (pinned; server + client) — installed at BUILD time, not runtime
RUN curl -fsSL -o /usr/local/bin/sliver-server \
        "https://github.com/BishopFox/sliver/releases/download/${SLIVER_VERSION}/sliver-server_linux-amd64" && \
    curl -fsSL -o /usr/local/bin/sliver-client \
        "https://github.com/BishopFox/sliver/releases/download/${SLIVER_VERSION}/sliver-client_linux-amd64" && \
    chmod +x /usr/local/bin/sliver-server /usr/local/bin/sliver-client

# Python extras used by the red-team clients (msgpack for msfrpcd; bloodhound-python)
RUN pip3 install --no-cache-dir --break-system-packages msgpack bloodhound 2>/dev/null || \
    pip3 install --no-cache-dir msgpack bloodhound

# Non-root user (same uid as host for file permissions)
ARG USER_ID=1000
ARG GROUP_ID=1000
RUN groupadd -g ${GROUP_ID} attack && \
    useradd -m -u ${USER_ID} -g ${GROUP_ID} -s /bin/bash attack

USER attack
WORKDIR /home/attack/attack-surface

ENV PIP_BREAK_SYSTEM_PACKAGES=1
COPY --chown=attack:attack . /home/attack/attack-surface
RUN pip3 install --no-cache-dir --upgrade pip && \
    pip3 install --no-cache-dir -r requirements.txt

# 8443: dashboard · 55553: msfrpcd (SSL) · 50051: sliver gRPC
EXPOSE 8443/tcp 55553/tcp 50051/tcp

COPY --chown=attack:attack entrypoint.sh /home/attack/entrypoint.sh
RUN chmod +x /home/attack/entrypoint.sh
ENTRYPOINT ["/home/attack/entrypoint.sh"]
