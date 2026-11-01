# ScopeHound 0.2.0: single-container scanner; never expose a listener.
FROM golang:1.25 AS subfinder-builder
RUN CGO_ENABLED=0 go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest

FROM python:3.11-slim
ENV PYTHONUNBUFFERED=1 PYTHONDONTWRITEBYTECODE=1
WORKDIR /app
COPY requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt \
    && python -m playwright install --with-deps chromium
COPY --from=subfinder-builder /go/bin/subfinder /usr/local/bin/subfinder
COPY asm.py takeover.py domains.txt subdomains.txt dangerous_paths.txt ./
RUN mkdir -p /app/reports
ENTRYPOINT ["python", "asm.py"]
