# Attack Surface Scanner - official image
FROM python:3.11-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
        nmap openssl ca-certificates \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /opt/attack-surface
COPY requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt

COPY core/ core/
COPY modules/ modules/
COPY wordlists/ wordlists/
COPY attack_surface.py scanner.py ./

RUN useradd -m scanner && chown -R scanner:scanner /opt/attack-surface
USER scanner

VOLUME ["/opt/attack-surface/reports"]

ENTRYPOINT ["python3", "attack_surface.py"]
CMD ["--help"]
