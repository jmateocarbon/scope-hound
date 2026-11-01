# ScopeHound 0.2.0 — Release Candidate

## Added
- `--json` exports compact, provider-neutral, screenshot-free JSON under `reports/scopehound_ai_*.json`.
- JSON carries observed asset URLs/IPs/ports/statuses/technologies, DNS takeover triage, and optional status-only path results.
- Two documented consumption modes: manual AI upload or bring-your-own agent/API (no embedded AI provider).
- Docker image includes `dangerous_paths.txt`; supports optional exposure checks and scheduled runs.
- New JSON export, scope, and port-selection regression tests.
- Browser scans now default to only 80/443; `--extra-web-ports 8080,8443` opts in to reported alternate web ports.

## Fixed
- Repaired malformed `requirements.txt` line from the uploaded archive.
- Atomic report writes, timestamped report names, CSP hash for HTML inline script, scope guard for optional exposure target origins.
- Added service-worker blocking in browser screenshot context.

## Release validation
- Python unit tests passed (24 tests); syntax compilation passed.
- Docker build, live scanning, and dependency vulnerability audit have **not** been performed in this environment. Do not tag until those checks pass.

## Usage
`python asm.py -f domains.txt --json --check-exposures`

`docker build -t scopehound:0.2.0 .`

`docker run --rm -v "$PWD/domains.txt:/app/domains.txt:ro" -v "$PWD/reports:/app/reports" scopehound:0.2.0 --json --check-exposures`
