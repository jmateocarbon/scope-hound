
# ScopeHound v0.2.0
# Lightweight, single-container attack surface scanner.
# No exposed ports or external services required.

# --------------------------------------------------
# Stage 1: Build Subfinder
# --------------------------------------------------
FROM golang:1.27.3-bookworm AS subfinder-builder

ENV CGO_ENABLED=0 \
    GOTOOLCHAIN=local \
    GOSUMDB=sum.golang.org

RUN go install -v \
    github.com/projectdiscovery/subfinder/v2/cmd/subfinder@v2.17.0

# --------------------------------------------------
# Stage 2: Python runtime
# --------------------------------------------------
FROM python:3.11-slim-bookworm

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PLAYWRIGHT_BROWSERS_PATH=/opt/playwright

WORKDIR /app

# Install Python dependencies and Chromium.
COPY requirements.txt ./

RUN python -m pip install -r requirements.txt \
    && python -m playwright install --with-deps chromium

# Copy Subfinder binary.
COPY --from=subfinder-builder \
    /go/bin/subfinder /usr/local/bin/subfinder

# Copy ScopeHound components.
COPY asm.py takeover.py ./
COPY domains.txt subdomains.txt dangerous_paths.txt ./

# Create reports directory.
RUN mkdir -p /app/reports \
    && chmod 755 /app/reports

# Verify installation.
RUN python -m compileall -q asm.py takeover.py \
    && subfinder -version

# ScopeHound runs as a CLI.
ENTRYPOINT ["python", "asm.py"]
