FROM ubuntu:24.04

# Corporate TLS interception (Zscaler etc.) breaks HTTPS inside containers.
# corp-ca.crt is exported from the host keychain; see README step 1.
RUN apt-get update && apt-get install -y --no-install-recommends \
      python3 python3-pip python3-venv jq ca-certificates curl \
    && rm -rf /var/lib/apt/lists/*

# corp-ca.crt must exist. If you are not behind a TLS-inspecting proxy, an empty
# file is fine:  touch corp-ca.crt
COPY corp-ca.crt /usr/local/share/ca-certificates/corp-ca.crt
RUN if [ -s /usr/local/share/ca-certificates/corp-ca.crt ]; then \
      cat /usr/local/share/ca-certificates/corp-ca.crt >> /etc/ssl/certs/ca-certificates.crt; \
      echo "corporate CA added"; \
    else echo "no corporate CA supplied; using defaults"; fi

# Point every TLS client (pip, requests, python, az) at the augmented bundle
ENV SSL_CERT_FILE=/etc/ssl/certs/ca-certificates.crt \
    REQUESTS_CA_BUNDLE=/etc/ssl/certs/ca-certificates.crt \
    PIP_CERT=/etc/ssl/certs/ca-certificates.crt \
    CURL_CA_BUNDLE=/etc/ssl/certs/ca-certificates.crt

# The azure-cli .deb repo is amd64-only, so it fails on Apple Silicon. pip works on both.
RUN python3 -m venv /opt/az \
    && /opt/az/bin/pip install --no-cache-dir --upgrade pip \
    && /opt/az/bin/pip install --no-cache-dir azure-cli
ENV PATH="/opt/az/bin:${PATH}"

# az CLI ships its own certifi bundle; make it trust the corp CA too
RUN if [ -s /usr/local/share/ca-certificates/corp-ca.crt ]; then \
      cat /usr/local/share/ca-certificates/corp-ca.crt >> "$(/opt/az/bin/python -c 'import certifi; print(certifi.where())')"; fi

# Fail loudly at build time if az is missing
RUN az version

RUN az config set extension.use_dynamic_install=yes_without_prompt \
    && az extension add -n resource-graph \
    && (az extension add -n log-analytics --allow-preview true || echo "log-analytics ext unavailable; flow logs disabled")

WORKDIR /app
COPY azure-net-map.html generate-netmap.sh entrypoint.sh /app/
RUN chmod +x /app/generate-netmap.sh /app/entrypoint.sh && mkdir -p /app/maps

EXPOSE 8080
ENTRYPOINT ["/app/entrypoint.sh"]
