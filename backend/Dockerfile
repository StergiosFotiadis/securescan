FROM python:3.11-slim

WORKDIR /app

# ── System packages ────────────────────────────────────────────────────────────
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        git curl wget ca-certificates gnupg unzip \
        # C compiler — required by cargo to link Rust crates
        build-essential \
        # Java (Maven uses the JDK)
        default-jdk-headless maven \
        # PHP
        php-cli php-zip php-curl php-json \
        # Ruby
        ruby-full \
    && rm -rf /var/lib/apt/lists/*

# ── Node.js 20 ─────────────────────────────────────────────────────────────────
RUN curl -fsSL https://deb.nodesource.com/setup_20.x | bash - && \
    apt-get install -y nodejs && \
    rm -rf /var/lib/apt/lists/*

# ── Composer & local-php-security-checker (PHP) ────────────────────────────────
RUN curl -sS https://getcomposer.org/installer \
    | php -- --install-dir=/usr/local/bin --filename=composer && \
    curl -sSLo /usr/local/bin/local-php-security-checker https://github.com/fabpot/local-php-security-checker/releases/latest/download/local-php-security-checker-linux-amd64 && \
    chmod +x /usr/local/bin/local-php-security-checker

# ── bundler-audit (Ruby) ───────────────────────────────────────────────────────
RUN gem install bundler bundler-audit --no-document

# ── Go 1.22 + govulncheck ──────────────────────────────────────────────────────
ENV GOPATH=/root/go
ENV PATH="${PATH}:/usr/local/go/bin:/root/go/bin"

RUN curl -fsSL https://go.dev/dl/go1.22.3.linux-amd64.tar.gz -o /tmp/go.tar.gz && \
    tar -C /usr/local -xzf /tmp/go.tar.gz && \
    rm /tmp/go.tar.gz && \
    go install golang.org/x/vuln/cmd/govulncheck@latest

# ── Rust (minimal toolchain) + cargo-audit ─────────────────────────────────────
ENV PATH="${PATH}:/root/.cargo/bin"

RUN curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs \
    | sh -s -- -y --no-modify-path --profile minimal && \
    cargo install cargo-audit --locked

# ── Trivy (Java / Maven / Gradle vulnerability scanning) ──────────────────────
RUN curl -sfL https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/install.sh \
    | sh -s -- -b /usr/local/bin && \
    # Pre-warm the vulnerability database so the first scan is fast
    trivy image --download-db-only --no-progress || true

# ── Python application ─────────────────────────────────────────────────────────
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

EXPOSE 8000

CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]
