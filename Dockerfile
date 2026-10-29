# Build the official Subfinder executable separately from the Python runtime.
FROM golang:1.25 AS subfinder-builder
RUN CGO_ENABLED=0 go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest

FROM python:3.11-slim
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt && playwright install --with-deps chromium
COPY --from=subfinder-builder /go/bin/subfinder /usr/local/bin/subfinder
COPY asm.py takeover.py domains.txt subdomains.txt ./
RUN mkdir -p /app/reports
ENTRYPOINT ["python", "asm.py"]
