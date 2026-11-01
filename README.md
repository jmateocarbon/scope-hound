# ScopeHound

**Lightweight, open-source attack surface discovery and DNS takeover triage.**

ScopeHound inventories internet-facing assets using Subfinder, DNS resolution, Shodan InternetDB, Wappalyzer, and Playwright screenshots. Review findings in a searchable, self-contained HTML report. Run it locally or in Docker—no hosted service or database required.

## Contents

- [Features](#features)
- [Screenshots](#screenshots)
- [Quick start](#quick-start)
- [Docker](#docker)
- [CLI options](#cli-options)
- [Reports](#reports)
- [Security and limitations](#security-and-limitations)
- [Contributing and license](#contributing-and-license)

## Features

- Subdomain discovery with **Subfinder**, or scan your own list of subdomains
- DNS resolution, grouping, and **subdomain takeover triage**
- **Shodan InternetDB** IP/port enrichment and **Wappalyzer** technology detection
- **Playwright** screenshots and a searchable HTML dashboard
- Parallel domain discovery with bounded concurrency
- Optional status-only checks for potentially exposed paths
- Optional compact JSON export and scheduled scans
- Docker support for **Linux AMD64 and ARM64 (including Apple Silicon Macs)**

## Screenshots

### Dashboard
![ScopeHound dashboard](docs/images/dashboard-overview.png)

### HTTP status filters
![HTTP status filters](docs/images/status-filters.png)

### Asset details
![Asset details](docs/images/asset-details.png)

### DNS takeover triage
![DNS takeover triage](docs/images/dns-triage.png)

## Quick start

**Requirements:** Python 3.10+, Subfinder in your `PATH` (for enumeration), and Playwright Chromium for screenshots.

```bash
pip install -r requirements.txt
python -m playwright install chromium
```

Add domains you are authorized to assess to `domains.txt` (one parent domain per line):

```text
example.com
example.org
```

Run a scan:

```bash
python asm.py -f domains.txt
```

Already have a list of exact hostnames? Skip enumeration:

```bash
python asm.py -f domains.txt --input-subdomains subdomains.txt
```

The report is saved in `reports/`.

## Docker

Pull the published image (supports **Linux AMD64 and ARM64**, including Apple Silicon):

```bash
docker pull ghcr.io/jmateocarbon/scope-hound:main
```

Run on Linux or macOS:

```bash
mkdir -p reports
docker run --rm \
  -v "$PWD/domains.txt:/app/domains.txt:ro" \
  -v "$PWD/reports:/app/reports" \
  ghcr.io/jmateocarbon/scope-hound:main
```

On Windows PowerShell:

```powershell
New-Item -ItemType Directory -Force reports | Out-Null
docker run --rm `
  -v "${PWD}/domains.txt:/app/domains.txt:ro" `
  -v "${PWD}/reports:/app/reports" `
  ghcr.io/jmateocarbon/scope-hound:main
```

No exposed ports are needed. To see available flags, run:

```bash
docker run --rm ghcr.io/jmateocarbon/scope-hound:main --help
```

## CLI options

| Option | Description |
| --- | --- |
| `-f domains.txt` | Parent domains to assess |
| `--input-subdomains subdomains.txt` | Scan exact hostnames without enumeration |
| `--discovery wordlist -s subdomains.txt` | Use prefix-based wordlist discovery instead of Subfinder |
| `--parallel-domains auto` | Bounded automatic domain concurrency (default); or set `1`–`16` |
| `--extra-web-ports 8080,8443` | Include supported alternate web ports when reported by InternetDB |
| `--check-exposures` | Enable optional status-only checks using `dangerous_paths.txt` |
| `--paths my_paths.txt` | Custom paths file for `--check-exposures` |
| `--json` | Generate an additional compact JSON report |
| `--interval-hours 24` | Repeat scans sequentially every 24 hours |

By default, web fingerprinting checks ports **80/443** and visits only `/`. Supported optional extra ports are `81`, `8000`, `8080`, and `8443`. Alternate ports are selected only when reported by InternetDB.

For all options:

```bash
python asm.py --help
```

## Reports

Results are written to `reports/`:

| Output | Description |
| --- | --- |
| `scan_report_*.html` | Searchable asset inventory, screenshots, and DNS takeover triage |
| `scopehound_ai_*.json` | Optional compact JSON export (`--json`), without screenshots |
| `exposure_checks_*.json` | Optional status-only sensitive-path checks (`--check-exposures`) |
| `domain_failures_*.json` | Details about failed domain tasks, when applicable |

For optional exposure checks, a `200` HTTP response means **needs review**, not confirmed exposure. ScopeHound does not store the response bodies or follow redirects for these checks.

## Security and limitations

ScopeHound is a **read-only discovery and triage tool**, not an exploitation framework. DNS takeover indicators are not proof of exploitability, and InternetDB port data does not guarantee a port is currently reachable. Scan **only assets you own or have explicit permission to assess**. Keep generated reports private.

To report vulnerabilities in ScopeHound itself, see [SECURITY.md](SECURITY.md).

## Contributing and license

Contributions and feedback are welcome. ScopeHound is maintained by **Mateo Carbon** and released under the [MIT License](LICENSE).
