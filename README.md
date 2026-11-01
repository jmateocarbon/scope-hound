# ScopeHound

Lightweight Python-based attack surface discovery, technology fingerprinting, and DNS takeover triage.

ScopeHound is an open-source Python scanner for building an inventory of internet-facing assets. Provide a list of parent domains for enumeration, or skip enumeration and scan a developer-supplied list of subdomains. The tool enriches findings with Shodan InternetDB, Wappalyzer, Playwright screenshots, and DNS takeover indicators, then produces an HTML report for local review.

## Project Philosophy

ScopeHound is designed to be **easy to install, easy to run, and easy to understand**. It stays lightweight, open-source, CLI-first, and local-first, with straightforward commands and self-contained HTML reports. Development prioritizes **accessibility, accuracy, stability, security, and compatibility** over unnecessary features or infrastructure dependencies.

ScopeHound does not include user accounts, built-in authentication, or a hosted management service. You can run it locally, in Docker, or within your own automation and infrastructure.

## Features

- Subdomain discovery with **Subfinder**
- Support for **developer-supplied subdomain lists**
- DNS resolution and grouping by parent domain
- Focused web inventory: **HTTP 80 / HTTPS 443 by default**, optional alternate ports
- **Shodan InternetDB** enrichment for IP and port intelligence
- **Wappalyzer** technology fingerprinting
- **Playwright** screenshots for reachable web assets
- **DNS / subdomain takeover triage** with provider fingerprints
- Searchable HTML report with filtering, pagination, and dedicated asset details
- Optional **Docker** support for local or unattended runs
- Optional compact **AI-ready JSON** export (manual upload or bring-your-own agent)
- Optional separate **sensitive-path status checks**

## Screenshots

### Dashboard overview
![ScopeHound dashboard overview](docs/images/dashboard-overview.png)

### HTTP status filters
![ScopeHound status filters](docs/images/status-filters.png)

### Asset details
![ScopeHound asset details](docs/images/asset-details.png)

### DNS takeover triage
![ScopeHound DNS takeover triage](docs/images/dns-triage.png)

## Requirements

- Python 3.10+
- Google Chrome / Chromium (for Playwright screenshots)
- Go-installed **Subfinder** in `PATH` if you want automatic enumeration

Install Python dependencies:

```bash
pip install -r requirements.txt
```

Install Playwright browser support:

```bash
python -m playwright install chromium
```

## Quick start (Python)

### 1. Create `domains.txt`

```text
example.com
```

### 2. Run ScopeHound with Subfinder

```bash
python asm.py -f domains.txt
```

### 3. Or skip enumeration and use your own subdomains

```bash
python asm.py -f domains.txt --input-subdomains subdomains.txt
```

### 4. Legacy wordlist discovery mode

```bash
python asm.py -f domains.txt --discovery wordlist -s subdomains.txt
```

### Web port selection (v0.2.0)

ScopeHound uses **80 and 443 by default** for browser-based fingerprinting and screenshots. InternetDB may report other ports, but they are **not automatically browsed**. InternetDB port intelligence is still included in each asset's details when available; a reported port does not necessarily mean it is reachable now.

To opt into common alternate HTTP(S) ports on hosts you are authorized to scan:

```bash
python asm.py -f domains.txt --extra-web-ports 8080,8443
```

Supported extra ports are `81`, `8000`, `8080` (HTTP), and `8443` (HTTPS). Specify them as a comma-separated list; other values are rejected. Opting in does not force a probe of an alternate port absent from the Shodan InternetDB candidate list. When InternetDB offers no usable port data, fallback candidates remain **80 and 443 only**. These are candidate endpoints, **not verified open ports**.

This reduces unnecessary browser navigation on alternate ports while keeping those checks available when needed. A target may run its website *only* on an alternate port, so enable the corresponding option when the assessment requires it.

### Optional sensitive-path checks

By default, ScopeHound visits **only `/`** for web fingerprinting and screenshots. This avoids running the browser and Wappalyzer against sensitive-path candidates.

To run separate status-only HTTP checks using `dangerous_paths.txt`:

```bash
python asm.py -f domains.txt --check-exposures
```

To use another root-relative path file (one path per line):

```bash
python asm.py -f domains.txt --check-exposures --paths my_paths.txt
```

This module does **not** run screenshots or Wappalyzer on these paths, follow HTTP redirects, or store response bodies. It writes results to `reports/exposure_checks_<timestamp>.json`, separate from the HTML dashboard. A `200` response means **needs review**, not confirmed sensitive-data exposure; catch-all application routing can return `200` for nonexistent paths. Keep path lists small and only scan authorized assets.

## Parallel domain scanning and runtime (v0.2.0)

ScopeHound accepts **one parent domain per line** in `domains.txt`. All valid input domains are queued, regardless of how many lines the file contains. The number of *active domain workers* is bounded; it is **not** a limit on how many domains ScopeHound can scan.

```text
# domains.txt
example.com
example.org
example.net
```

### Automatic and manual concurrency

By default, `--parallel-domains auto` selects a conservative worker count from the host CPU count: **2–8 workers**, capped by the number of input domains. For example, a file containing three domains uses at most three workers, while a file containing 1,000 domains processes them in a queue rather than launching 1,000 simultaneous scans.

```bash
# Recommended: automatically select a bounded worker count
python asm.py -f domains.txt --parallel-domains auto --json

# More conservative: process one parent domain at a time
python asm.py -f domains.txt --parallel-domains 1 --json

# Explicitly allow up to four parent domains in parallel
python asm.py -f domains.txt --parallel-domains 4 --json
```

Manual values from **1 to 16** are supported. A higher value does not guarantee a faster scan: DNS resolvers, InternetDB, CPU/memory, remote services, and browser capacity can become bottlenecks. Start with `auto`, and increase concurrency cautiously only for authorized targets.

### What actually runs in parallel?

ScopeHound uses **one scan job and one combined report**, with separate internal phases:

| Phase | Runtime behavior | Why it may take time |
| --- | --- | --- |
| Parent-domain discovery | Up to `--parallel-domains` domains concurrently | Subfinder discovery and upstream response times; an individual Subfinder invocation has its own timeout |
| DNS resolution | Up to **32 DNS lookups** concurrently across domain workers | Many discovered hosts, slow DNS responses, and unresolved hostnames |
| Shodan InternetDB enrichment | Up to **8 requests** concurrently, one lookup per unique IP within the scan | Rate limiting, request latency, and number of unique IPs |
| DNS takeover triage | One triage phase over the discovered hosts | DNS lookups and optional provider fingerprint requests |
| Web fingerprinting + screenshots | One shared Wappalyzer pass and Playwright browser, with up to **5 screenshot tabs** concurrently | Page-loading timeouts, JavaScript-heavy websites, and total web origins |
| Optional dangerous-path checks | Separate HTTP-only checks when `--check-exposures` is enabled | Number of origins × paths, network latency, and timeouts; no browser screenshots |
| Report output | Merge results into **one HTML report**, plus optional JSON | Report size grows with asset count and embedded screenshots |

**Important:** `--parallel-domains` accelerates the **discovery and DNS stage**; it does not create a separate browser for each domain or make every processing phase fully parallel. Browser capture, DNS takeover triage, and optional exposure checks still contribute to the total run time. The scanner waits for the current phase to complete before proceeding to its next stage.

### How long will a scan take?

There is **no fixed runtime per domain**. One parent domain can produce hundreds of subdomains, while another may produce only a few. The important workload measures are:

- **Parent domains:** lines in `domains.txt` (the work queue).
- **Discovered hostnames:** total subdomains found or explicitly supplied (DNS workload).
- **Unique IP addresses:** InternetDB lookup workload, with shared-IP deduplication.
- **Web origins:** unique selected `scheme://host:port/` targets (fingerprinting and screenshot workload).
- **Optional path checks:** roughly `web origins × paths in dangerous_paths.txt` HTTP requests when enabled.

As an **illustration of scheduling only**, 1,000 domains with four workers means up to four parent-domain discovery/DNS tasks active at once, not four domains total and not a promise of 250 equal-duration batches. Workers take the next queued domain as slots become available. Total runtime also includes shared enrichment, DNS triage, browser capture, optional exposure checks, and report generation.

Do not interpret the configured concurrency as a guaranteed 4× or 8× speedup. Results depend on the number of discovered hosts per domain, remote timeouts, network throughput, and host resources. **No 1,000-domain benchmark is included with v0.2.0.**

### Tips for large domain lists

1. First run the default `--parallel-domains auto` with the standard **80/443** web-port selection. Extra ports (`--extra-web-ports`) add browser targets only when reported by InternetDB.
2. Keep `--check-exposures` disabled unless you need the optional path checks; custom lists add HTTP requests to every selected origin.
3. If you already have an authorized inventory of exact hosts, use `--input-subdomains subdomains.txt` to skip Subfinder enumeration. This still performs resolution, enrichment, fingerprinting, and reporting.
4. Compare real end-to-end runs on the **same authorized scope** before increasing workers. On Linux/macOS, you can measure elapsed time with `time python asm.py -f domains.txt --parallel-domains auto --json` (or use your shell's timing command on Windows).
5. Allow enough CPU, memory, and disk for a large HTML report. Screenshots are embedded in HTML; JSON output intentionally omits those images.

### Partial failures and reporting

All successful domain results are merged and deduplicated into **one HTML report** and, with `--json`, **one AI-ready JSON report**. When a parent-domain discovery/DNS task fails, ScopeHound continues with other domains and writes a separate `reports/domain_failures_*.json` summary. Review that file before interpreting the combined report as complete. A failed web endpoint is not necessarily a failed parent-domain scan.

### Scheduled runs

```bash
# Start a new scan cycle no more frequently than once per hour
python asm.py -f domains.txt --parallel-domains auto --json --interval-hours 1
```

`--interval-hours` measures the interval between **scan starts**. Scheduled scans do **not overlap within this process**. If a scan takes 20 minutes with a one-hour interval, the process waits approximately 40 minutes before starting again. If it takes 75 minutes, the next scan can start immediately after the current scan finishes; it does **not** launch a second simultaneous scan. This behavior does not prevent overlap with separately launched ScopeHound processes or containers; schedule only one runner per scope/output destination.

## Complete CLI reference (v0.2.0)

Run `python asm.py --help` locally or `docker run --rm scopehound:0.2.0 --help` inside Docker to inspect the arguments supported by your installed version.

| Option | Default | Purpose |
| --- | --- | --- |
| `-f FILE`, `--domains FILE` | `domains.txt` | Text file containing authorized parent domains, one per line. |
| `--input-subdomains FILE` | Disabled | Scan exact supplied hostnames; skips automatic enumeration. Hosts must belong to a listed parent domain. |
| `--discovery subfinder\|wordlist` | `subfinder` | Select automatic discovery engine when an exact host list is not supplied. |
| `-s FILE`, `--subdomains FILE` | `subdomains.txt` | Prefix list used by `--discovery wordlist`; not an exact-host list in that mode. |
| `--extra-web-ports PORTS` | None | Add selected alternate web ports (allowed: `81,8000,8080,8443`) to default 80/443. |
| `--parallel-domains auto\|N` | `auto` | Concurrent parent-domain workers; `N` is 1–16, capped by domain count. |
| `--json` | Off | Export compact AI-ready JSON without screenshots. |
| `--check-exposures` | Off | Run separate status-only checks for potential sensitive paths. |
| `--paths FILE` | `dangerous_paths.txt` | Root-relative paths file for `--check-exposures`; using a custom list requires that flag. |
| `--interval-hours HOURS` | `0` | Repeat scans at this start-to-start interval; `0` runs once. |
| `-h`, `--help` | — | Show CLI help and exit. |

**Port behavior:** 80 and 443 are eligible by default but are not necessarily reachable. Alternate ports are selected only if present in usable Shodan InternetDB port data. No usable InternetDB data means fallback *candidates* of 80/443, not verified open ports. `--extra-web-ports` does not perform a full port scan.

**Common commands:**

```bash
# One-off run: all parent domains, conservative auto concurrency
python asm.py -f domains.txt

# Structured JSON for optional AI ingestion
python asm.py -f domains.txt --json

# Explicit worker count (processes all domains, up to 4 at a time)
python asm.py -f domains.txt --parallel-domains 4 --json

# Add alternate web ports (only when in the port candidate list)
python asm.py -f domains.txt --extra-web-ports 8080,8443 --json

# Skip enumeration with exact scoped hostnames
python asm.py -f domains.txt --input-subdomains subdomains.txt --json

# Legacy prefix-based discovery
python asm.py -f domains.txt --discovery wordlist -s subdomains.txt

# Opt-in sensitive-path checks, separate output from HTML
python asm.py -f domains.txt --check-exposures

# Custom path file (one root-relative path per line)
python asm.py -f domains.txt --check-exposures --paths dangerous_paths.txt --json

# Run sequential scan cycles every 6 hours
python asm.py -f domains.txt --json --interval-hours 6
```

### Input files: do not confuse hostnames and path lists

`domains.txt` contains **parent domains** (one per line):

```text
example.com
example.org
example.net
```

`subdomains.txt` has **two uses**, depending on the CLI option. With `--input-subdomains`, it must contain *full scoped hostnames* (for example `api.example.com`). With `--discovery wordlist -s`, it must contain *prefixes* (for example `api`, `staging`). Prepare the file for the mode you intend to use.

`dangerous_paths.txt` contains **root-relative URL paths** such as `/.git/HEAD` or `/config.json`, one per line; it is read only when `--check-exposures` is active. ScopeHound performs status-only checks and does not save response bodies. A 200 response requires verification, not an automatic vulnerability claim.

### Output files and scan completion

| File | When generated | Contents |
| --- | --- | --- |
| `reports/scan_report_*.html` | Each completed scan | Combined web inventory, embedded screenshots (when available), and DNS takeover triage. |
| `reports/scopehound_ai_*.json` | With `--json` | Compact combined assets and triage findings for optional manual or custom-agent ingestion; no Base64 screenshots. |
| `reports/exposure_checks_*.json` | With `--check-exposures` | Separate status-only path-check results. |
| `reports/domain_failures_*.json` | If parent-domain tasks fail | Failed-domain information, to avoid mistaking partial scan success for complete coverage. |

One domain failing does not stop other domain tasks. Review errors and the failure summary before treating the reports as complete. Scan time is driven by discovered hostnames, unique IPs, reachable web origins, DNS/network delays and screenshot timeouts—not merely the number of lines in `domains.txt`.

## Docker: complete usage guide

ScopeHound is a **CLI container**, not a hosted web UI. Docker starts the single `asm.py` entrypoint, which coordinates discovery, DNS triage, optional exposure checks and reporting. No port publication (`-p`) or database is required. There is **no published official registry image assumed** in the commands below; build from your local checkout unless a project maintainer has released a verified image.

### 1. Build and verify locally

Run from the repository directory containing `Dockerfile` and `requirements.txt`:

```bash
docker build --progress=plain -t scopehound:0.2.0 .
docker run --rm --entrypoint subfinder scopehound:0.2.0 -version
docker run --rm scopehound:0.2.0 --help
```

Docker's build stage needs a **Go version compatible with the pinned Subfinder release**. Avoid `go install ...@latest`; use a tested, explicitly pinned Subfinder version and a compatible Go builder. If a Go installation step fails, inspect the first relevant `go:` error in `docker build --progress=plain` output. Base-image digests and dependency locks should be reviewed separately before claiming a fully reproducible build.

### 2. One-time scan — Linux/macOS Bash

```bash
mkdir -p reports

docker run --rm \
  -v "$PWD/domains.txt:/app/domains.txt:ro" \
  -v "$PWD/reports:/app/reports" \
  scopehound:0.2.0 --json --parallel-domains auto
```

### 3. One-time scan — Windows PowerShell

```powershell
New-Item -ItemType Directory -Force reports | Out-Null

docker run --rm `
  -v "${PWD}/domains.txt:/app/domains.txt:ro" `
  -v "${PWD}/reports:/app/reports" `
  scopehound:0.2.0 --json --parallel-domains auto
```

Both commands generate one combined HTML report and one optional compact JSON report in your **host's** `reports/` directory. The bind mount preserves reports when the container exits.

### 4. Run with additional options

The command arguments go **after the image name**, just as with `python asm.py`:

```bash
# Enable path exposure checks using the default list baked into the image
docker run --rm \
  -v "$PWD/domains.txt:/app/domains.txt:ro" \
  -v "$PWD/reports:/app/reports" \
  scopehound:0.2.0 --json --check-exposures --parallel-domains 4

# Use an externally maintained path list; mount the file before referencing it
docker run --rm \
  -v "$PWD/domains.txt:/app/domains.txt:ro" \
  -v "$PWD/my_paths.txt:/app/my_paths.txt:ro" \
  -v "$PWD/reports:/app/reports" \
  scopehound:0.2.0 --check-exposures --paths my_paths.txt --json

# Scan an exact list of scoped subdomains, skipping Subfinder
docker run --rm \
  -v "$PWD/domains.txt:/app/domains.txt:ro" \
  -v "$PWD/subdomains.txt:/app/subdomains.txt:ro" \
  -v "$PWD/reports:/app/reports" \
  scopehound:0.2.0 --input-subdomains subdomains.txt --json

# Enable 8080/8443 where these ports are present in port intelligence
docker run --rm \
  -v "$PWD/domains.txt:/app/domains.txt:ro" \
  -v "$PWD/reports:/app/reports" \
  scopehound:0.2.0 --extra-web-ports 8080,8443 --json
```

For **Windows PowerShell**, use the volume-mount style shown in step 3, and replace Bash's line-continuation `\` with a PowerShell backtick (`` ` ``). If a source file has a different name, mount it to a matching path in `/app/` and provide that filename in the CLI option.

### 5. Scheduled Docker scanning

After verifying a one-off scan, launch a single long-running container:

```bash
mkdir -p reports

docker run -d \
  --name scopehound \
  --restart unless-stopped \
  -v "$PWD/domains.txt:/app/domains.txt:ro" \
  -v "$PWD/reports:/app/reports" \
  scopehound:0.2.0 --json --parallel-domains auto --interval-hours 24
```

```bash
# Inspect and stop the scheduled container
docker logs -f scopehound
docker stop scopehound
docker rm scopehound
```

`--interval-hours 24` means a scan starts no more frequently than every 24 hours **within that one process**. If the scan takes longer than the interval, the next starts after it finishes; ScopeHound does not overlap scan cycles inside the same container. However, separately launched containers can overlap and write to the same reports directory, so avoid duplicate runners. Scan reports are not automatically pruned; monitor storage and implement your own retention policy if scheduling regularly.

### 6. Docker troubleshooting

| Symptom | What to check |
| --- | --- |
| `go install ... subfinder@latest` fails during build | Replace floating `@latest` with a tested Subfinder version and compatible Go builder; use `--progress=plain` to see the underlying error. |
| `domains.txt` missing / path not found | Run from the correct directory; check the host path and the read-only bind mount. |
| `subdomains.txt` or custom paths file not found | Mount the file into `/app/` and pass its container filename. |
| No reports visible on the host | Check the `/app/reports` bind mount and host-folder write permissions. |
| Browser launch or screenshot failures | Confirm Playwright Chromium installed successfully in the image and inspect `docker logs`/terminal output. |
| Scan is slower than expected | Compare discovered host counts and unique origins; default to ports 80/443, leave optional paths off unless required, and tune `--parallel-domains` conservatively. |
| A few targets failed | Review the terminal and `domain_failures_*.json` if produced; isolated web endpoint failures do not necessarily mean the entire scan failed. |

**Security:** Run only against domains you own or have explicit permission to assess. Keep report directories private because asset inventories and sensitive-path status results may reveal internal infrastructure.

## Reports

HTML reports include browser-based web inventory and DNS takeover triage. Path-check JSON is saved separately, and **the compact AI JSON export is opt-in**. Reports may describe sensitive infrastructure and should be secured accordingly.


ScopeHound automatically creates `reports/` and saves standalone HTML there. The optional exposure checker writes a separate status-only JSON. With `--json`, ScopeHound also writes a compact, screenshot-free `scopehound_ai_*.json` containing asset inventory, DNS takeover triage, and optional exposure check outcomes. JSON output is not a claim that vulnerabilities are confirmed.

### Optional AI-ready JSON (v0.2.0)

```bash
python asm.py -f domains.txt --json
python asm.py -f domains.txt --json --check-exposures
```

**Manual ingestion:** Upload the `scopehound_ai_*.json` report to an approved AI assistant and ask it to prioritize observed evidence, state uncertainty, and propose verification/remediation steps.

**Bring your own agent:** Feed the JSON file into your own LLM API or agent workflow. ScopeHound does not call AI APIs, require API keys, send notifications, or map asset owners. Treat both JSON content and external responses as untrusted data; do not upload sensitive reports to unapproved services.

The JSON schema is versioned (`schema_version: 1.0`). Screenshots and their Base64 data are intentionally excluded to reduce size and token cost.

## Tests and release verification

```bash
python -m unittest discover -s tests -v
python -m compileall -q asm.py takeover.py tests
```

Before tagging `v0.2.0`, build and smoke-test the Docker image against a domain you control. Validate output files, browser screenshots, alternate port behavior, and Docker volume permissions. The unit suite uses mocks and does not establish that Docker or live scanning works in every environment.

## Deployment and Access Control

ScopeHound does not provide built-in authentication or hosted services. **Users are responsible for securing their own deployments**, including authentication, access controls, network exposure, and generated scan reports. Avoid publishing reports containing sensitive asset information to publicly accessible locations.

## Notes and limitations

- ScopeHound is a **local, read-only inventory and triage tool**. It is not an exploit framework.
- DNS takeover findings are **indicators** only. They are not proof that a service can be claimed.
- Port information comes from **Shodan InternetDB** when available. Fallback web targets are probe candidates, not confirmed open ports.
- Screenshots are captured only for web targets that can be reached by Playwright.
- Use ScopeHound only on domains and assets you own or are explicitly authorized to assess.

## Security

If you believe you have found a vulnerability in ScopeHound itself, please use GitHub private vulnerability reporting or follow the guidance in `SECURITY.md`.

## Maintainer

- **Mateo Carbon** — johnmatthew.carbon@gmail.com

## License

Released under the **MIT License**. See `LICENSE` for details.
