# GovShield scanner worker — bundles the open-source engines the platform runs.
FROM python:3.12-slim

ENV DEBIAN_FRONTEND=noninteractive \
    TRIVY_VERSION=0.58.1 \
    GITLEAKS_VERSION=8.22.1 \
    SYFT_VERSION=1.19.0 \
    NUCLEI_VERSION=3.3.8

RUN apt-get update && apt-get install -y --no-install-recommends \
      git curl ca-certificates gnupg unzip tar \
    && curl -fsSL https://deb.nodesource.com/setup_22.x | bash - \
    && apt-get install -y --no-install-recommends nodejs \
    && rm -rf /var/lib/apt/lists/*

# Semgrep + Checkov (Python toolchain)
RUN pip install --no-cache-dir semgrep==1.101.0 checkov==3.2.360

# Trivy (SCA, container, IaC)
RUN curl -fsSL "https://github.com/aquasecurity/trivy/releases/download/v${TRIVY_VERSION}/trivy_${TRIVY_VERSION}_Linux-64bit.tar.gz" \
      | tar -xz -C /usr/local/bin trivy

# Gitleaks (secret detection)
RUN curl -fsSL "https://github.com/gitleaks/gitleaks/releases/download/v${GITLEAKS_VERSION}/gitleaks_${GITLEAKS_VERSION}_linux_x64.tar.gz" \
      | tar -xz -C /usr/local/bin gitleaks

# Syft (SBOM generation)
RUN curl -fsSL "https://github.com/anchore/syft/releases/download/v${SYFT_VERSION}/syft_${SYFT_VERSION}_linux_amd64.tar.gz" \
      | tar -xz -C /usr/local/bin syft

# Nuclei (active web testing)
RUN curl -fsSL -o /tmp/nuclei.zip "https://github.com/projectdiscovery/nuclei/releases/download/v${NUCLEI_VERSION}/nuclei_${NUCLEI_VERSION}_linux_amd64.zip" \
    && unzip -j /tmp/nuclei.zip nuclei -d /usr/local/bin \
    && rm /tmp/nuclei.zip

# Warm the caches so the first assessment is not penalised.
RUN trivy image --download-db-only --quiet || true \
    && nuclei -update-templates -silent || true

RUN useradd -m -u 10001 scanner
WORKDIR /opt/govshield
COPY agent.mjs normalize.mjs ./
RUN chown -R scanner:scanner /opt/govshield
USER scanner

ENV GOVSHIELD_POLL_MS=5000
CMD ["node", "agent.mjs"]
