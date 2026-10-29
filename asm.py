import os
import sys
import asyncio
import base64
import json
import socket
import argparse
import time
import shutil
import re
import requests
from playwright.async_api import async_playwright
from wappalyzer import Wappalyzer
from datetime import datetime
from pathlib import Path
from urllib.parse import urlsplit
from takeover import scan_takeovers

# --- CONFIGURATION ---
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
DEFAULT_TARGET_FILE = "domains.txt"
DEFAULT_SUBDOMAINS_FILE = "subdomains.txt"
MAX_CONCURRENT_TABS = 5

PATHS_TO_CHECK = ["/", "/.git", "/config.json"]
WEB_PORTS = [80, 81, 443, 8000, 8080, 8443]

FALLBACK_SUBDOMAINS = [
    "www", "api", "dev", "staging", "test", "admin", 
    "portal", "vpn", "secure", "app", "shop", "store", 
    "qa", "static", "assets", "ftp", "dashboard", "login", 
    "auth", "sso", "git", "ci"
]


# --- FILE LOADERS ---
def load_targets(target_input: str) -> list[str]:
    """Reads target domains from a file or string and normalizes them to base apex domains."""
    raw_targets = []
    
    target_path = target_input
    if not os.path.isabs(target_path):
        alt_path = os.path.join(SCRIPT_DIR, target_input)
        if os.path.isfile(alt_path):
            target_path = alt_path

    if os.path.isfile(target_path):
        with open(target_path, "r", encoding="utf-8") as f:
            for line in f:
                if line.strip():
                    raw_targets.append(line.strip())
    else:
        raw_targets.append(target_input)

    cleaned_domains = []
    for entry in raw_targets:
        cleaned = entry.strip().replace("https://", "").replace("http://", "").split("/")[0].strip()
        if cleaned.startswith("www."):
            cleaned = cleaned[4:]
        if cleaned and not cleaned.startswith("#"):
            cleaned_domains.append(cleaned)
            
    return list(dict.fromkeys(cleaned_domains))


def load_subdomains(subdomain_input: str = DEFAULT_SUBDOMAINS_FILE) -> list[str]:
    """Reads subdomain prefix wordlist from a text file with SCRIPT_DIR fallback."""
    subdomain_path = subdomain_input
    if not os.path.isabs(subdomain_path):
        alt_path = os.path.join(SCRIPT_DIR, subdomain_input)
        if os.path.isfile(alt_path):
            subdomain_path = alt_path

    if os.path.isfile(subdomain_path):
        subdomains = []
        with open(subdomain_path, "r", encoding="utf-8") as f:
            for line in f:
                cleaned = line.strip()
                if cleaned and not cleaned.startswith("#"):
                    subdomains.append(cleaned)
        print(f"[*] Loaded {len(subdomains)} subdomain prefixes from {os.path.basename(subdomain_path)}")
        return list(dict.fromkeys(subdomains))

    print(f"[!] Warning: Subdomain file '{subdomain_input}' not found. Using internal fallback list.")
    return FALLBACK_SUBDOMAINS


def load_supplied_hosts(filename: str, domains: list[str]) -> dict[str, list[str]]:
    """Read exact hostnames, never arbitrary URLs or out-of-scope domains."""
    path = Path(filename)
    if not path.is_file():
        raise ValueError(f"Subdomain input file not found: {filename}")
    hosts = {d: [] for d in domains}
    for number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
        host = line.strip().lower().rstrip('.')
        if not host or host.startswith('#'):
            continue
        if not re.fullmatch(r"(?=.{1,253}$)[a-z0-9-]+(?:\.[a-z0-9-]+)+", host) or any(
            not label or label.startswith('-') or label.endswith('-') or len(label) > 63
            for label in host.split('.')
        ):
            raise ValueError(f"Invalid hostname on line {number}: {host}")
        matches = [d for d in domains if host == d or host.endswith('.' + d)]
        if not matches:
            raise ValueError(f"Out-of-scope hostname on line {number}: {host}")
        parent = max(matches, key=len)
        hosts[parent].append(host)
    return {d: list(dict.fromkeys(items)) for d, items in hosts.items()}


async def discover_subfinder(domain: str) -> list[str]:
    """Passive enumeration using the official Subfinder CLI."""
    if not shutil.which('subfinder'):
        raise RuntimeError('Subfinder not found in PATH. Install it or use --input-subdomains.')
    process = await asyncio.create_subprocess_exec(
        'subfinder', '-d', domain, '-silent',
        stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE,
    )
    try:
        stdout, stderr = await asyncio.wait_for(process.communicate(), timeout=180)
    except asyncio.TimeoutError:
        process.kill()
        await process.communicate()
        raise RuntimeError(f'Subfinder timed out for {domain}')
    if process.returncode:
        raise RuntimeError(f'Subfinder failed for {domain}: {stderr.decode(errors="replace")[:300]}')
    discovered = set()
    for line in stdout.decode(errors='replace').splitlines():
        hostname = line.strip().lower().rstrip('.')
        if hostname == domain or hostname.endswith('.' + domain):
            discovered.add(hostname)
    discovered.add(domain)
    return sorted(discovered)


async def resolve_hosts(hosts: list[str]) -> dict[str, set[str]]:
    """Resolve exactly the provided/discovered hosts, without wordlist guesses."""
    results = await asyncio.gather(*(resolve_subdomain(h) for h in hosts))
    ip_to_hosts = {}
    for host, ips in results:
        for ip in ips:
            ip_to_hosts.setdefault(ip, set()).add(host)
    return ip_to_hosts


# --- 1. RECON & DISCOVERY ---
async def resolve_subdomain(subdomain):
    loop = asyncio.get_running_loop()
    try:
        _, _, ips = await loop.run_in_executor(None, socket.gethostbyname_ex, subdomain)
        return subdomain, ips
    except socket.gaierror:
        return subdomain, []

async def brute_force_subdomains(domain, subdomains_wordlist):
    print(f"[*] Reconnaissance of subdomains for {domain}...")
    subdomains_to_test = set(subdomains_wordlist + ["www"])
    
    tasks = [resolve_subdomain(f"{sub}.{domain}") for sub in subdomains_to_test]
    tasks.append(resolve_subdomain(domain))  # Apex root domain
    
    results = await asyncio.gather(*tasks)
    ip_to_hosts = {}
    for sub, ips in results:
        if ips:
            print(f"  [+] Discovered: {sub} -> {ips}")
            for ip in ips:
                ip_to_hosts.setdefault(ip, set()).add(sub)
                
    print(f"[*] Resolved {len(ip_to_hosts)} unique IP addresses for {domain}.")
    return ip_to_hosts

def fetch_shodan_internetdb(ip):
    print(f"[*] Querying Shodan InternetDB for {ip}...")
    try:
        response = requests.get(f"https://internetdb.shodan.io/{ip}", timeout=10)
        if response.status_code == 200:
            return response.json()
    except requests.exceptions.RequestException:
        pass
    return {}


def get_port_candidates(internetdb_data):
    """Return (ports to probe, evidence source), never implying an open-port scan.

    Only a valid InternetDB `ports` list counts as reported intelligence.
    When InternetDB has no usable port data, 80/443 are *probe candidates*.
    """
    raw_ports = internetdb_data.get('ports') if isinstance(internetdb_data, dict) else None
    if isinstance(raw_ports, list):
        ports = sorted({port for port in raw_ports if type(port) is int and 1 <= port <= 65535})
        return ports, 'Shodan InternetDB'
    return [80, 443], 'Fallback candidates (unverified)'


# --- 2. FINGERPRINTING & SCREENSHOTS ---
def run_wappalyzer_scan(urls):
    if not urls:
        return {}
    try:
        with Wappalyzer(workers=3, timeout=15) as scanner:
            return scanner.analyze_many(urls)
    except Exception as e:
        print(f"[-] Wappalyzer scan error: {e}")
        return {}

def is_allowed_browser_url(url: str, expected_host: str) -> bool:
    """Restrict browser network traffic to the exact scanned hostname."""
    try:
        parsed = urlsplit(url)
        # data and blob resources may be generated locally by the scanned page.
        if parsed.scheme in ("data", "blob", "about"):
            return True
        return (parsed.scheme in ("http", "https")
                and parsed.hostname is not None
                and parsed.hostname.lower().rstrip(".") == expected_host.lower().rstrip("."))
    except (ValueError, AttributeError):
        return False


async def process_target_screenshot(context, target, semaphore):
    async with semaphore:
        page = None
        expected_host = urlsplit(target['url']).hostname
        blocked_redirect = False
        try:
            if not expected_host:
                raise ValueError("Target URL has no hostname")
            page = await context.new_page()

            async def guard_request(route):
                nonlocal blocked_redirect
                url = route.request.url
                if is_allowed_browser_url(url, expected_host):
                    await route.continue_()
                else:
                    if route.request.is_navigation_request() and route.request.frame == page.main_frame:
                        blocked_redirect = True
                        print(f"[!] Blocked out-of-scope navigation: {target['url']} -> {url}")
                    await route.abort()

            await page.route("**/*", guard_request)
            response = await page.goto(target['url'], timeout=20000, wait_until="domcontentloaded")
            await page.wait_for_timeout(2000)
            if blocked_redirect or not is_allowed_browser_url(page.url, expected_host):
                target['status'] = "Blocked redirect"
                target['b64_img'] = None
                return

            if response:
                target['status'] = response.status
                headers = response.headers
                if 'server' in headers:
                    target['software'].append(f"Server: {headers['server']}")
                if 'x-powered-by' in headers:
                    target['software'].append(f"Powered-By: {headers['x-powered-by']}")

            img_bytes = await page.screenshot(type='jpeg', quality=60, full_page=True)
            target['b64_img'] = base64.b64encode(img_bytes).decode('utf-8')
        except Exception as e:
            print(f"[-] Playwright error for {target['url']}: {str(e).splitlines()[0]}")
            target['b64_img'] = None
            target['status'] = "Blocked redirect" if blocked_redirect else "Failed"
        finally:
            if page:
                await page.close()

async def capture_screenshots(targets):
    if not targets:
        return targets

    urls = [t['url'] for t in targets]
    
    print("[*] Running Wappalyzer technology fingerprinting...")
    loop = asyncio.get_running_loop()
    wappalyzer_results = await loop.run_in_executor(None, run_wappalyzer_scan, urls)

    for target in targets:
        url = target['url']
        tech_data = wappalyzer_results.get(url, {})
        if isinstance(tech_data, dict):
            for tech_name, data in tech_data.items():
                version = data.get('version', '') if isinstance(data, dict) else ''
                tech_str = f"{tech_name} {version}".strip()
                if tech_str not in target['software']:
                    target['software'].append(tech_str)

    print("[*] Capturing page screenshots across all targets...")
    semaphore = asyncio.Semaphore(MAX_CONCURRENT_TABS)
    async with async_playwright() as p:
        browser = await p.chromium.launch(
            headless=True,
            args=["--no-sandbox", "--disable-dev-shm-usage"]
        )
        context = await browser.new_context(
            viewport={'width': 1920, 'height': 1080},
            ignore_https_errors=True,
            user_agent="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
        )
        
        tasks = [process_target_screenshot(context, target, semaphore) for target in targets]
        await asyncio.gather(*tasks)
        await browser.close()
        
    return targets


# --- 3. HTML REPORT GENERATION ---
def generate_html(targets, takeover_findings=None):
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    reports_dir = os.path.join(SCRIPT_DIR, "reports")
    os.makedirs(reports_dir, exist_ok=True)
    filename = os.path.join("reports", f"scan_report_{timestamp}.html")
    output_file = os.path.join(SCRIPT_DIR, filename)
    
    html_template = """<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Attack Surface & Integrity Dashboard</title>
    <style>
        :root { --bg-primary:#f6f5f1; --bg-card:#fff; --bg-card-hover:#fcfbf8; --border-color:#deded7; --text-main:#202a27; --text-muted:#59655e; --accent-red:#a83f3c; --accent-red-bg:#fff0ee; --accent-green:#176f53; --accent-green-bg:#eaf6ef; --accent-blue:#205e56; --accent-blue-bg:#eaf3f0; --accent-amber:#8b5d13; --accent-amber-bg:#fcf4e4; --accent-purple:#5a6657; --accent-purple-bg:#f0f2ed; }
        * { box-sizing:border-box; }
        body { font-family:Inter, ui-sans-serif, system-ui, -apple-system, Segoe UI, sans-serif; background:var(--bg-primary); color:var(--text-main); margin:0; padding:30px clamp(16px,3vw,48px); line-height:1.5; }
        .masthead { max-width:1400px; margin:0 auto 28px; border-bottom:1px solid var(--border-color); padding:9px 0 25px; display:flex; align-items:flex-end; justify-content:space-between; gap:20px; }
        .eyebrow { font-size:11px; letter-spacing:.17em; text-transform:uppercase; font-weight:800; color:var(--accent-green); }
        h1 { margin:5px 0 0; font-size:clamp(26px,3vw,41px); line-height:1.1; letter-spacing:-.045em; font-weight:760; }
        h1 span { color:var(--accent-green); }
        .subtitle { color:var(--text-muted); font-size:13px; max-width:320px; text-align:right; }
        h2 {font-size:22px; letter-spacing:-.025em; margin-bottom:4px;}
        .filter-container, .status-summary, .toolbar, .grid, .pager { max-width:1400px; margin-left:auto; margin-right:auto; }
        .filter-container { display:flex; justify-content:flex-end; align-items:center; gap:10px; margin-bottom:14px; }
        .filter-label { font-size:12px; color:var(--text-muted); font-weight:700; }
        .filter-select, .toolbar input, .toolbar select { font:inherit; background:#fff; color:var(--text-main); border:1px solid var(--border-color); border-radius:7px; padding:10px 12px; outline:none; }
        .filter-select:focus, .toolbar input:focus, .toolbar select:focus { border-color:var(--accent-green); box-shadow:0 0 0 3px #176f5318; }
        .status-summary { display:flex; gap:8px; flex-wrap:wrap; margin-bottom:16px; }
        .status-button { background:#fff; color:var(--text-muted); border:1px solid var(--border-color); border-radius:7px; cursor:pointer; padding:9px 12px; font-size:12px; font-weight:700; }
        .status-button.active { background:var(--text-main); color:#fff; border-color:var(--text-main); }
        .toolbar { display:flex; align-items:center; flex-wrap:wrap; gap:10px; margin-bottom:18px; font-size:12px; color:var(--text-muted); }
        .toolbar input { flex:1; min-width:200px; }
        .pager {display:flex; justify-content:center; align-items:center; gap:14px; margin-top:20px; margin-bottom:18px; font-size:12px; color:var(--text-muted);}
        .pager button {border:1px solid var(--border-color); padding:9px 14px; border-radius:7px; background:#fff; color:var(--text-main); cursor:pointer; font-weight:650;}
        .pager button:disabled {opacity:.4;cursor:default;}
        .grid { display:grid; grid-template-columns:repeat(auto-fill,minmax(300px,1fr)); gap:14px; }
        .card { background:var(--bg-card); border:1px solid var(--border-color); border-radius:11px; overflow:hidden; cursor:pointer; transition:border-color .15s,box-shadow .15s; box-shadow:0 2px 9px #202a2708; }
        .card:hover {border-color:#9ca9a0;box-shadow:0 6px 16px #202a2713;}
        .card img {width:100%;height:165px;object-fit:cover;object-position:top;display:block;}
        .screenshot-frame {height:165px;display:flex;align-items:center;justify-content:center;background:#f1f2ef;border-bottom:1px solid var(--border-color);overflow:hidden;}
        .no-screenshot {font-size:12px;font-weight:600;color:var(--text-muted);text-align:center;padding:14px;}
        .modal-screenshot-frame {min-height:200px;display:flex;align-items:center;justify-content:center;background:#f1f2ef;border-radius:7px;margin-bottom:20px;overflow:hidden;}
        .modal-screenshot-frame:has(img:not([hidden])) {min-height:0;}
        .modal-screenshot-frame .modal-img {width:100%;height:auto;display:block;margin:0;}
        [hidden] {display:none !important;}
        .asset-view {max-width:1400px;margin:0 auto 28px;}
        .asset-back {font:inherit;background:transparent;border:0;padding:6px 0;color:var(--accent-green);font-weight:750;cursor:pointer;margin-bottom:14px;}
        .asset-head {display:flex;align-items:center;justify-content:space-between;gap:16px;flex-wrap:wrap;margin-bottom:24px;}
        .asset-head h2 {margin:0;font-size:clamp(22px,3vw,33px);overflow-wrap:anywhere;}
        .asset-subtitle {color:var(--text-muted);font-size:13px;margin:6px 0 0;}
        .asset-open {color:var(--accent-green);text-decoration:none;font-weight:750;border:1px solid var(--border-color);background:#fff;border-radius:8px;padding:11px 15px;}
        .asset-tabs {display:flex;gap:8px;flex-wrap:wrap;margin:0 0 20px;}
        .asset-tab {font:inherit;font-size:13px;cursor:pointer;border:1px solid var(--border-color);background:#fff;color:var(--text-muted);border-radius:8px;padding:10px 16px;font-weight:700;}
        .asset-tab.active {background:var(--text-main);color:#fff;border-color:var(--text-main);}
        .asset-columns {display:grid;grid-template-columns:minmax(0,1.1fr) minmax(0,1fr);gap:20px;align-items:start;}
        .asset-panel {background:#fff;border:1px solid var(--border-color);border-radius:14px;padding:20px;min-width:0;box-shadow:0 2px 9px #202a2708;}
        .asset-panel h3 {font-size:17px;margin:0 0 14px;}
        .asset-screenshot-frame {min-height:310px;background:#eff1ee;border:1px solid var(--border-color);border-radius:10px;overflow:hidden;display:flex;align-items:center;justify-content:center;}
        .asset-screenshot-frame img {display:block;width:100%;height:auto;max-height:620px;object-fit:contain;object-position:top;}
        .asset-shot-caption {font-size:12px;color:var(--text-muted);margin-top:12px;}
        .asset-row {display:grid;grid-template-columns:145px minmax(0,1fr);gap:14px;border-bottom:1px solid #e9ece8;padding:12px 0;font-size:13px;}
        .asset-row:last-child {border-bottom:0;}
        .asset-row-label {font-weight:700;color:var(--text-muted);}
        .asset-row-value {min-width:0;overflow-wrap:anywhere;}
        .asset-row-value a {color:var(--accent-green);}
        .asset-tech-list {display:flex;flex-wrap:wrap;gap:7px;}
        .asset-tech-list .tech-pill {margin:0;padding:7px 10px;}
        .asset-empty {color:var(--text-muted);padding:26px 12px;text-align:center;}
        .card:focus-visible,.asset-back:focus-visible,.asset-tab:focus-visible {outline:3px solid var(--accent-green);outline-offset:3px;}
        @media(max-width:850px){.asset-columns{grid-template-columns:1fr}.asset-screenshot-frame{min-height:190px}}
        @media(max-width:520px){.asset-row{grid-template-columns:1fr;gap:3px}.asset-panel{padding:15px}}
        .card-info {padding:15px;}
        .card-info h3 {margin:0 0 12px;font-size:13px;font-weight:720;word-break:break-all;}
        .badge { display:inline-flex;align-items:center;padding:4px 8px;border-radius:5px;font-size:10px;font-weight:700;margin:0 5px 7px 0;letter-spacing:.01em; }
        .domain-badge {background:var(--accent-purple-bg);color:var(--accent-purple);}
        .ip-badge {background:#f4f5f3;color:#53605b;border:1px solid #ebeeea;}
        .tech-pill {display:inline-block;padding:4px 7px;border-radius:5px;font-size:11px;background:#f6f7f4;color:#56635a;margin:2px;}
        .takeover-section {max-width:1400px;margin:50px auto 20px;border-top:1px solid var(--border-color);padding-top:25px;}
        details.takeover-entry {background:#fff;padding:14px 18px;margin:7px 0;border:1px solid var(--border-color);border-radius:8px;overflow-wrap:anywhere;}
        details.takeover-entry summary {cursor:pointer;font-weight:720;font-size:13px;}
        details.takeover-entry .detail {margin-top:12px;font-size:12px;color:var(--text-muted);line-height:1.8;}
        details.takeover-entry code {display:block;white-space:pre-wrap;margin-top:8px;background:#f4f5f2;padding:8px;border-radius:5px;color:var(--accent-green);}
        .modal-overlay {position:fixed;inset:0;background:#18221cbf;display:none;justify-content:center;align-items:center;z-index:50;padding:20px;backdrop-filter:blur(3px);}
        .modal {background:#fff;padding:30px;border-radius:12px;max-width:800px;width:100%;max-height:90vh;overflow-y:auto;position:relative;box-shadow:0 25px 65px #1117;}
        .close-btn {position:absolute;right:15px;top:10px;background:none;border:0;font-size:28px;cursor:pointer;color:var(--text-muted);}
        .modal-img {width:100%;border-radius:7px;background:#eaece8;}
        .detail-row {margin-bottom:12px;border-bottom:1px solid #ebece8;padding-bottom:12px;display:flex;align-items:flex-start;}
        .detail-label {font-size:11px;color:var(--text-muted);font-weight:750;min-width:140px;text-transform:uppercase;letter-spacing:.045em;}
        .detail-value {word-break:break-word;flex:1;font-size:13px;}
        .detail-value a {color:var(--accent-green);}
        @media(max-width:650px){.masthead{display:block}.subtitle{text-align:left;margin-top:12px}.filter-container{justify-content:flex-start}.modal{padding:20px}.detail-row{display:block}.detail-label{display:block;margin-bottom:4px}}

        /* Fix v6: shared theme tokens and accessible dark appearance. */
        :root { color-scheme:light; --surface:#ffffff; --surface-alt:#f1f2ef; --surface-soft:#f4f5f3; --divider:#e9ece8; --hover-outline:#9ca9a0; --shadow:#202a2708; --shadow-hover:#202a2713; --button-active:#202a27; --button-active-text:#ffffff; --chip-text:#53605b; }
        html[data-theme="dark"] { color-scheme:dark; --bg-primary:#121a19; --bg-card:#1d2927; --bg-card-hover:#23332f; --border-color:#394c46; --text-main:#e8efea; --text-muted:#adbbb3; --accent-red:#ffa39d; --accent-red-bg:#4d2929; --accent-green:#7bd4a5; --accent-green-bg:#1e4236; --accent-blue:#8ecbc9; --accent-blue-bg:#223f42; --accent-amber:#e9bb79; --accent-amber-bg:#493924; --accent-purple:#bccdb6; --accent-purple-bg:#303e36; --surface:#1d2927; --surface-alt:#25332f; --surface-soft:#293833; --divider:#3b4c45; --hover-outline:#7bd4a5; --shadow:#00000020; --shadow-hover:#00000040; --button-active:#70c49a; --button-active-text:#10221a; --chip-text:#c0d3c7; }
        html[data-theme="dark"] .filter-select, html[data-theme="dark"] .toolbar input, html[data-theme="dark"] .toolbar select, html[data-theme="dark"] .status-button, html[data-theme="dark"] .pager button, html[data-theme="dark"] .asset-tab, html[data-theme="dark"] .asset-open, html[data-theme="dark"] .asset-panel, html[data-theme="dark"] details.takeover-entry {background:var(--surface);color:var(--text-main);}
        html[data-theme="dark"] .status-button.active, html[data-theme="dark"] .asset-tab.active {background:var(--button-active);color:var(--button-active-text);border-color:var(--button-active);}
        html[data-theme="dark"] .card, html[data-theme="dark"] .modal {background:var(--bg-card);color:var(--text-main);box-shadow:0 2px 9px var(--shadow);}
        html[data-theme="dark"] .card:hover {background:var(--bg-card-hover);border-color:var(--hover-outline);box-shadow:0 6px 16px var(--shadow-hover);}
        html[data-theme="dark"] .screenshot-frame, html[data-theme="dark"] .modal-screenshot-frame, html[data-theme="dark"] .asset-screenshot-frame, html[data-theme="dark"] .modal-img {background:var(--surface-alt);}
        html[data-theme="dark"] .asset-row, html[data-theme="dark"] .detail-row {border-bottom-color:var(--divider);}
        html[data-theme="dark"] .ip-badge, html[data-theme="dark"] .tech-pill, html[data-theme="dark"] details.takeover-entry code {background:var(--surface-soft);border-color:var(--border-color);color:var(--chip-text);}
        .theme-switch {font:inherit;display:inline-flex;align-items:center;justify-content:center;gap:8px;min-width:130px;padding:9px 13px;border:1px solid var(--border-color);border-radius:9px;background:var(--surface);color:var(--text-main);font-size:12px;font-weight:750;cursor:pointer;white-space:nowrap;}
        .theme-switch:hover {border-color:var(--accent-green);}
        .theme-switch:focus-visible {outline:3px solid var(--accent-green);outline-offset:3px;}
        .masthead-actions {display:flex;align-items:center;justify-content:flex-end;gap:18px;}
        @media(max-width:650px){.masthead-actions{justify-content:space-between;margin-top:12px;flex-wrap:wrap}.subtitle{text-align:left;}}
    </style>
</head>
<body>
    <header class="masthead">
      <div><div class="eyebrow">ScopeHound</div><h1>Attack surface <span>inventory.</span></h1></div>
      <div class="masthead-actions"><div class="subtitle">A lightweight, local-first view of discovered assets, technologies and DNS takeover indicators.</div><button id="themeToggle" class="theme-switch" type="button" aria-label="Switch to dark mode" aria-pressed="false"><span id="themeIcon" aria-hidden="true">☾</span><span id="themeLabel">Dark mode</span></button></div>
    </header>
    
    <div id="inventoryView">
    <div class="filter-container">
        <label for="domainFilter" class="filter-label">Filter Target Domain:</label>
        <select id="domainFilter" class="filter-select" onchange="filterDomains()">
            <option value="ALL">All Domains</option>
        </select>
    </div>

    <div class="status-summary" id="statusSummary" aria-label="Filter by HTTP status"></div>
    <div class="toolbar">
        <input id="searchInput" type="search" placeholder="Search hostname, URL, technology or IP..." aria-label="Search assets">
        <label for="pageSize">Per page:</label>
        <select id="pageSize"><option>25</option><option selected>50</option><option>100</option></select>
        <span id="assetCount" aria-live="polite"></span>
    </div>
    <div class="grid" id="grid"></div>
    <div class="pager"><button id="prevPage">Previous</button><span id="pageIndicator"></span><button id="nextPage">Next</button></div>
    <section class="takeover-section">
      <h2>DNS / Subdomain Takeover Triage</h2>
      <p style="color:var(--text-muted)">Read-only indicators, not proof that a domain can be claimed. Checks include discovered hosts without web endpoints.</p>
      <div class="status-summary" id="takeoverSummary"></div>
      <div class="toolbar"><input id="takeoverSearch" type="search" placeholder="Search DNS findings..."><select id="takeoverPageSize"><option>25</option><option selected>50</option><option>100</option></select><span id="takeoverCount"></span></div>
      <div id="takeoverResults"></div>
      <div class="pager"><button id="takeoverPrev">Previous</button><span id="takeoverPages"></span><button id="takeoverNext">Next</button></div>
    </section>
    </div>

    <section class="asset-view" id="assetView" hidden aria-label="Selected asset details">
      <button type="button" class="asset-back" id="assetBack">← Back to assets</button>
      <div class="asset-head">
        <div><div class="eyebrow">Asset investigation</div><h2 id="assetTitle"></h2>
          <p class="asset-subtitle" id="assetSubtitle"></p></div>
        <a id="assetOpen" class="asset-open" target="_blank" rel="noopener noreferrer">↗ Open in browser</a>
      </div>
      <div class="asset-tabs" role="tablist" aria-label="Asset details sections">
        <button class="asset-tab active" id="tabOverview" type="button" role="tab" aria-selected="true">Overview</button>
        <button class="asset-tab" id="tabTechnology" type="button" role="tab" aria-selected="false">Technology</button>
        <button class="asset-tab" id="tabDNS" type="button" role="tab" aria-selected="false">DNS findings</button>
      </div>
      <div id="assetOverview" role="tabpanel">
        <div class="asset-columns">
          <div class="asset-panel">
            <h3>Screenshot preview</h3>
            <div class="asset-screenshot-frame" id="assetScreenshotFrame">
              <img id="assetImg" alt="Captured website screenshot" hidden>
              <div id="assetNoScreenshot" class="no-screenshot">No screenshot available</div>
            </div>
            <div class="asset-shot-caption">Screenshot captured during this scan, when available.</div>
          </div>
          <div class="asset-panel"><h3>Asset details</h3><div id="assetRows"></div></div>
        </div>
      </div>
      <div id="assetTechnology" class="asset-panel" role="tabpanel" hidden>
        <h3>Detected technology</h3>
        <p class="asset-subtitle">Observed through technology fingerprinting and available response headers.</p>
        <div class="asset-tech-list" id="assetTechList" style="margin-top:20px"></div>
      </div>
      <div id="assetDNS" class="asset-panel" role="tabpanel" hidden>
        <h3>DNS / subdomain takeover triage</h3>
        <p class="asset-subtitle">Read-only indicators, not proof that a hostname can be claimed.</p>
        <div id="assetDnsFindings"></div>
      </div>
    </section>
    <script>
        // Persistent report-only preference; works offline and tolerates file:// storage restrictions.
        const THEME_KEY = 'scopehound-report-theme';
        function setTheme(theme, save) {
            const dark = theme === 'dark';
            document.documentElement.dataset.theme = dark ? 'dark' : 'light';
            document.getElementById('themeIcon').textContent = dark ? '☀' : '☾';
            document.getElementById('themeLabel').textContent = dark ? 'Light mode' : 'Dark mode';
            const toggle = document.getElementById('themeToggle');
            toggle.setAttribute('aria-label', dark ? 'Switch to light mode' : 'Switch to dark mode');
            toggle.setAttribute('aria-pressed', String(dark));
            if (save) { try { localStorage.setItem(THEME_KEY, dark ? 'dark' : 'light'); } catch (_) {} }
        }
        let initialTheme = 'light';
        try { initialTheme = localStorage.getItem(THEME_KEY) || 'light'; } catch (_) {}
        if (initialTheme !== 'dark' && initialTheme !== 'light') initialTheme = 'light';
        setTheme(initialTheme, false);
        document.getElementById('themeToggle').addEventListener('click', () => {
            setTheme(document.documentElement.dataset.theme === 'dark' ? 'light' : 'dark', true);
        });
        const targetsData = /* JSON_INJECTED_HERE */;
        const takeoverData = /* TAKEOVER_JSON */;
        const domainFilter = document.getElementById('domainFilter');
        const grid = document.getElementById('grid');
        const takeoverSummary = document.getElementById('takeoverSummary');
        const takeoverResults = document.getElementById('takeoverResults');
        let selectedStatus = 'ALL', takeoverStatus = 'ALL';
        let assetPage = 0, takeoverPage = 0;
        const uniqueDomains = [...new Set([...targetsData, ...takeoverData].map(t => t.parent_domain))].sort();
        uniqueDomains.forEach(domain => {
            const option = document.createElement('option');
            option.value = domain; option.textContent = domain;
            domainFilter.appendChild(option);
        });
        function statusGroup(status) {
            if (typeof status !== 'number') return 'Failed / Unknown';
            if (status >= 200 && status < 300) return '2xx Success';
            if (status >= 300 && status < 400) return '3xx Redirect';
            if (status >= 400 && status < 500) return '4xx Client Error';
            if (status >= 500 && status < 600) return '5xx Server Error';
            return 'Failed / Unknown';
        }
        const summary = document.getElementById('statusSummary');
        const statusGroups = ['ALL', '2xx Success', '3xx Redirect', '4xx Client Error', '5xx Server Error', 'Failed / Unknown'];
        function makeFilterButtons(container, groups, countFn, update) {
            groups.forEach(group => {
                const button = document.createElement('button');
                button.className = 'status-button' + (group === 'ALL' ? ' active' : '');
                button.textContent = `${group === 'ALL' ? 'All' : group} (${countFn(group)})`;
                button.addEventListener('click', () => {
                    container.querySelectorAll('button').forEach(b => b.classList.remove('active'));
                    button.classList.add('active'); update(group);
                });
                container.appendChild(button);
            });
        }
        makeFilterButtons(summary, statusGroups,
            group => group === 'ALL' ? targetsData.length : targetsData.filter(t => statusGroup(t.status) === group).length,
            group => { selectedStatus = group; assetPage = 0; renderAssets(); });
        const takeoverGroups = ['ALL', 'Potential takeover', 'Needs review', 'No indicator'];
        makeFilterButtons(takeoverSummary, takeoverGroups,
            group => group === 'ALL' ? takeoverData.length : takeoverData.filter(t => t.status === group).length,
            group => { takeoverStatus = group; takeoverPage = 0; renderTakeovers(); });
        function makeText(tag, value, className) {
            const node = document.createElement(tag);
            node.textContent = value == null ? '' : String(value);
            if (className) node.className = className;
            return node;
        }
        function renderAssetCard(target, index) {
            const card = document.createElement('div');
            card.className = 'card';
            card.addEventListener('click', () => openAsset(index));
            card.tabIndex = 0; card.setAttribute('role', 'button');
            card.setAttribute('aria-label', 'View details for ' + target.url);
            card.addEventListener('keydown', e => { if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); openAsset(index); } });
            const screenshotFrame = makeText('div', '', 'screenshot-frame');
            const fallback = () => screenshotFrame.replaceChildren(makeText('div', 'No screenshot available', 'no-screenshot'));
            if (target.b64_img) {
                const img = document.createElement('img');
                img.alt = 'Captured screenshot';
                img.loading = 'lazy';
                img.onerror = fallback;
                screenshotFrame.appendChild(img);
                img.src = 'data:image/jpeg;base64,' + target.b64_img;
            } else {
                fallback();
            }
            card.appendChild(screenshotFrame);
            const info = makeText('div', '', 'card-info');
            info.appendChild(makeText('h3', target.url));
            const badges = makeText('div', '');
            badges.appendChild(makeText('span', target.parent_domain, 'badge domain-badge'));
            const httpBadge = makeText('span', 'HTTP ' + (target.status ?? 'N/A'), 'badge');
            const status = statusGroup(target.status);
            httpBadge.style.background = status.startsWith('2xx') ? 'var(--accent-green-bg)' :
                status.startsWith('3xx') ? 'var(--accent-blue-bg)' : 'var(--accent-red-bg)';
            badges.appendChild(httpBadge);
            badges.appendChild(makeText('span', target.ip, 'badge ip-badge'));
            badges.appendChild(makeText('span', 'Port ' + target.port + (target.port_source === 'Shodan InternetDB' ? ' · InternetDB' : ' · probe candidate'), 'badge ip-badge'));
            info.appendChild(badges);
            const tech = makeText('div', '');
            const technology = [...new Set(target.software || [])];
            technology.slice(0, 3).forEach(t => tech.appendChild(makeText('span', t, 'tech-pill')));
            if (technology.length > 3) tech.appendChild(makeText('span', '+' + (technology.length - 3) + ' more', 'tech-pill'));
            info.appendChild(tech);
            card.appendChild(info);
            return card;
        }
        function renderAssets() {
            const selected = domainFilter.value;
            const query = document.getElementById('searchInput').value.trim().toLowerCase();
            const matches = targetsData.map((t, index) => ({t, index})).filter(({t}) =>
                (selected === 'ALL' || t.parent_domain === selected) &&
                (selectedStatus === 'ALL' || statusGroup(t.status) === selectedStatus) &&
                (!query || [t.url, t.ip, t.parent_domain, ...(t.software || [])].join(' ').toLowerCase().includes(query)));
            const perPage = Number(document.getElementById('pageSize').value);
            const pages = Math.max(1, Math.ceil(matches.length / perPage));
            assetPage = Math.min(assetPage, pages - 1);
            grid.replaceChildren();
            const fragment = document.createDocumentFragment();
            matches.slice(assetPage * perPage, (assetPage + 1) * perPage).forEach(({t, index}) => fragment.appendChild(renderAssetCard(t, index)));
            grid.appendChild(fragment);
            document.getElementById('assetCount').textContent = matches.length + ' matching assets';
            document.getElementById('pageIndicator').textContent = `Page ${assetPage + 1} of ${pages}`;
            document.getElementById('prevPage').disabled = assetPage === 0;
            document.getElementById('nextPage').disabled = assetPage >= pages - 1;
        }
        function renderTakeovers() {
            const selected = domainFilter.value;
            const query = document.getElementById('takeoverSearch').value.trim().toLowerCase();
            const entries = takeoverData.filter(t =>
                (selected === 'ALL' || t.parent_domain === selected) &&
                (takeoverStatus === 'ALL' || t.status === takeoverStatus) &&
                (!query || [t.hostname, t.provider, ...(t.cname_chain || []), ...(t.evidence || [])].join(' ').toLowerCase().includes(query)));
            const perPage = Number(document.getElementById('takeoverPageSize').value);
            const pages = Math.max(1, Math.ceil(entries.length / perPage));
            takeoverPage = Math.min(takeoverPage, pages - 1);
            const fragment = document.createDocumentFragment();
            entries.slice(takeoverPage * perPage, (takeoverPage + 1) * perPage).forEach(t => {
                const item = document.createElement('details');
                item.className = 'takeover-entry';
                item.appendChild(makeText('summary', t.hostname + ' — ' + t.status));
                const details = makeText('div', '', 'detail');
                details.appendChild(makeText('div', 'Provider: ' + t.provider));
                details.appendChild(makeText('div', 'CNAME: ' + ((t.cname_chain || []).join(' → ') || 'none')));
                details.appendChild(makeText('div', 'NS: ' + ((t.ns || []).join(', ') || 'none')));
                details.appendChild(makeText('div', 'HTTP: ' + (t.http_status ?? 'not tested')));
                details.appendChild(makeText('div', (t.evidence || []).join('; ') || 'No detected takeover indicators'));
                details.appendChild(makeText('code', t.dig_command || ''));
                item.appendChild(details);
                fragment.appendChild(item);
            });
            takeoverResults.replaceChildren(fragment);
            document.getElementById('takeoverCount').textContent = entries.length + ' matching hosts';
            document.getElementById('takeoverPages').textContent = `Page ${takeoverPage + 1} of ${pages}`;
            document.getElementById('takeoverPrev').disabled = takeoverPage === 0;
            document.getElementById('takeoverNext').disabled = takeoverPage >= pages - 1;
        }
        function filterDomains() { assetPage = 0; takeoverPage = 0; renderAssets(); renderTakeovers(); }
        document.getElementById('searchInput').addEventListener('input', () => { assetPage = 0; renderAssets(); });
        document.getElementById('takeoverSearch').addEventListener('input', () => { takeoverPage = 0; renderTakeovers(); });
        document.getElementById('pageSize').addEventListener('change', () => { assetPage = 0; renderAssets(); });
        document.getElementById('takeoverPageSize').addEventListener('change', () => { takeoverPage = 0; renderTakeovers(); });
        document.getElementById('prevPage').onclick = () => { assetPage--; renderAssets(); };
        document.getElementById('nextPage').onclick = () => { assetPage++; renderAssets(); };
        document.getElementById('takeoverPrev').onclick = () => { takeoverPage--; renderTakeovers(); };
        document.getElementById('takeoverNext').onclick = () => { takeoverPage++; renderTakeovers(); };
        renderAssets(); renderTakeovers();

         let activeAssetIndex = null;
         const assetPanels = {overview:'assetOverview', technology:'assetTechnology', dns:'assetDNS'};
         const assetTabIds = {overview:'tabOverview', technology:'tabTechnology', dns:'tabDNS'};
         function chooseAssetTab(name) {
             Object.keys(assetPanels).forEach(key => {
                 document.getElementById(assetPanels[key]).hidden = key !== name;
                 const button = document.getElementById(assetTabIds[key]);
                 button.classList.toggle('active', key === name);
                 button.setAttribute('aria-selected', key === name ? 'true' : 'false');
             });
         }
         function addAssetRow(label, value, kind) {
             const row = makeText('div', '', 'asset-row');
             row.appendChild(makeText('div', label, 'asset-row-label'));
             const v = makeText('div', '', 'asset-row-value');
             if (kind === 'url') {
                 const link = makeText('a', value);
                 link.href = value; link.target = '_blank'; link.rel = 'noopener noreferrer';
                 v.appendChild(link);
             } else if (kind === 'tech') {
                 const list = makeText('div', '', 'asset-tech-list');
                 if (value.length) value.forEach(t => list.appendChild(makeText('span', t, 'tech-pill')));
                 else list.appendChild(makeText('span', 'Not detected'));
                 v.appendChild(list);
             } else v.textContent = String(value);
             row.appendChild(v);
             document.getElementById('assetRows').appendChild(row);
         }
         function hostnameFor(url) {
             try { return new URL(url).hostname.toLowerCase().replace(/\\.$/, ''); }
             catch { return ''; }
         }
         function openAsset(index) {
             const t = targetsData[index];
             if (!t) return;
             activeAssetIndex = index;
             document.getElementById('inventoryView').hidden = true;
             document.getElementById('assetView').hidden = false;
             const hostname = hostnameFor(t.url);
             document.getElementById('assetTitle').textContent = hostname || t.url;
             document.getElementById('assetSubtitle').textContent = 'Web endpoint  •  ' + t.url;
             const open = document.getElementById('assetOpen');
             open.href = t.url;
             document.getElementById('assetRows').replaceChildren();
             addAssetRow('Parent domain', t.parent_domain || 'Unknown');
             addAssetRow('Target URL', t.url, 'url');
             addAssetRow('HTTP status', t.status == null ? 'Unknown / not captured' : String(t.status));
             addAssetRow('Resolved IP', t.ip || 'Unknown');
             const reported = t.port_source === 'Shodan InternetDB';
             const allPorts = reported && Array.isArray(t.all_ports) && t.all_ports.length
                 ? t.all_ports.join(', ') + ' (Shodan InternetDB, not live-verified)'
                 : (reported ? 'No ports reported by InternetDB' : 'No verified port intelligence; 80/443 are probe candidates');
             addAssetRow('Port intelligence', allPorts);
             addAssetRow('Endpoint port', String(t.port ?? 'Unknown') + (reported ? ' (InternetDB reported)' : ' (probe candidate)'));
             addAssetRow('HTTPS scheme', t.is_https ? 'Yes (HTTPS target)' : 'No (HTTP target)');
             const tech = [...new Set(t.software || [])];
             addAssetRow('Technology', tech, 'tech');
             const techRoot = document.getElementById('assetTechList');
             techRoot.replaceChildren();
             if (tech.length) tech.forEach(x => techRoot.appendChild(makeText('span', x, 'tech-pill')));
             else techRoot.appendChild(makeText('div', 'No identifiable technology detected.', 'asset-empty'));
             const img = document.getElementById('assetImg');
             const missing = document.getElementById('assetNoScreenshot');
             img.onload = null; img.onerror = null; img.hidden = true;
             missing.hidden = false; img.removeAttribute('src');
             if (t.b64_img) {
                 img.onload = () => { if (activeAssetIndex === index) { img.hidden = false; missing.hidden = true; } };
                 img.onerror = () => { img.hidden = true; missing.hidden = false; };
                 img.src = 'data:image/jpeg;base64,' + t.b64_img;
             }
             const dnsRoot = document.getElementById('assetDnsFindings');
             dnsRoot.replaceChildren();
             const findings = takeoverData.filter(f => (f.hostname || '').toLowerCase().replace(/\\.$/, '') === hostname);
             if (!findings.length) dnsRoot.appendChild(makeText('p', 'No DNS triage result recorded for this hostname.', 'asset-empty'));
             findings.forEach(f => {
                 const box = makeText('div', '', '');
                 addDnsLine(box, 'Hostname', f.hostname || hostname);
                 addDnsLine(box, 'Triage result', f.status || 'Unknown');
                 addDnsLine(box, 'Provider', f.provider || 'Unknown');
                 addDnsLine(box, 'CNAME chain', (f.cname_chain || []).join(' → ') || 'None recorded');
                 addDnsLine(box, 'Name servers', (f.ns || []).join(', ') || 'None recorded');
                 addDnsLine(box, 'Evidence', (f.evidence || []).join('; ') || 'No indicators recorded');
                 if (f.dig_command) addDnsLine(box, 'Suggested DNS check', f.dig_command);
                 dnsRoot.appendChild(box);
             });
             chooseAssetTab('overview');
             window.scrollTo(0, 0);
         }
         function addDnsLine(container, label, value) {
             const row = makeText('div', '', 'asset-row');
             row.appendChild(makeText('div', label, 'asset-row-label'));
             row.appendChild(makeText('div', value, 'asset-row-value'));
             container.appendChild(row);
         }
         function closeAsset() {
             activeAssetIndex = null;
             document.getElementById('assetView').hidden = true;
             document.getElementById('inventoryView').hidden = false;
             window.scrollTo(0, 0);
         }
         document.getElementById('assetBack').addEventListener('click', closeAsset);
         document.getElementById('tabOverview').addEventListener('click', () => chooseAssetTab('overview'));
         document.getElementById('tabTechnology').addEventListener('click', () => chooseAssetTab('technology'));
         document.getElementById('tabDNS').addEventListener('click', () => chooseAssetTab('dns'));
         document.addEventListener('keydown', e => {
             if (e.key === 'Escape' && !document.getElementById('assetView').hidden) closeAsset();
         });
    </script>
</body>
</html>"""

    json_data = json.dumps(targets).replace("<", "\\u003c")
    takeover_json = json.dumps(takeover_findings or []).replace("<", "\\u003c")
    html_content = html_template.replace('/* TAKEOVER_JSON */', takeover_json)
    html_content = html_content.replace('/* JSON_INJECTED_HERE */', json_data)

    os.makedirs(SCRIPT_DIR, exist_ok=True)
    
    with open(output_file, 'w', encoding='utf-8') as f:
        f.write(html_content)
        
    print(f"\n[+] [ASM Module] Success! Report saved to: {filename}")


# --- MAIN EXECUTION ---
async def main():
    parser = argparse.ArgumentParser(description="ScopeHound — attack-surface scanner")
    parser.add_argument('-f', '--domains', default=DEFAULT_TARGET_FILE,
                        help='Parent domain file (default: domains.txt).')
    parser.add_argument('--input-subdomains', metavar='FILE',
                        help='Skip enumeration and scan exact subdomains from this file.')
    parser.add_argument('--discovery', choices=['subfinder', 'wordlist'], default='subfinder',
                        help='Discovery engine when no custom input is supplied (default: subfinder).')
    parser.add_argument('-s', '--subdomains', default=DEFAULT_SUBDOMAINS_FILE,
                        help='Prefix wordlist for --discovery wordlist (legacy option).')
    parser.add_argument('--interval-hours', type=float, default=0, metavar='HOURS',
                        help='Run scans repeatedly every HOURS (for unattended Docker deployments).')
    args = parser.parse_args()
    if args.interval_hours < 0:
        parser.error('--interval-hours must be nonnegative')
    if not os.path.isfile(args.domains):
        parser.error(f'Domain scope file not found: {args.domains}')
    domains = load_targets(args.domains)
    try:
        supplied_hosts = load_supplied_hosts(args.input_subdomains, domains) if args.input_subdomains else None
    except ValueError as exc:
        parser.error(str(exc))
    subdomains_wordlist = load_subdomains(args.subdomains) if args.discovery == 'wordlist' and supplied_hosts is None else []

    if not domains:
        print("[-] Error: No valid targets found to scan.")
        return

    if not args.interval_hours:
        await run_scan(domains, supplied_hosts, subdomains_wordlist, args)
    else:
        print(f"[*] Scheduled mode: scanning every {args.interval_hours:g} hour(s). Stop with Ctrl+C.", flush=True)
        while True:
            started = time.monotonic()
            try:
                await run_scan(domains, supplied_hosts, subdomains_wordlist, args)
            except Exception as exc:
                print(f"[-] Scan failed: {exc}", file=sys.stderr, flush=True)
            delay = max(0, args.interval_hours * 3600 - (time.monotonic() - started))
            await asyncio.sleep(delay)

async def run_scan(domains, supplied_hosts, subdomains_wordlist, args):
    print(f"[*] Starting scan for {len(domains)} domain(s): {', '.join(domains)}")

    all_web_targets = []
    all_hosts_by_parent = {}
    seen_urls = set()

    for domain in domains:
        if supplied_hosts is not None:
            hosts = supplied_hosts[domain]
            print(f"[*] Using {len(hosts)} provided hosts for {domain}")
            ip_to_hosts = await resolve_hosts(hosts)
            all_hosts_by_parent[domain] = hosts
        elif args.discovery == 'wordlist':
            ip_to_hosts = await brute_force_subdomains(domain, subdomains_wordlist)
            all_hosts_by_parent[domain] = sorted({h for group in ip_to_hosts.values() for h in group})
        else:
            try:
                hosts = await discover_subfinder(domain)
            except RuntimeError as exc:
                print(f"[-] {exc}", file=sys.stderr)
                return
            print(f"[*] Subfinder discovered {len(hosts)} hosts for {domain}")
            ip_to_hosts = await resolve_hosts(hosts)
            all_hosts_by_parent[domain] = hosts
        if not ip_to_hosts:
            print(f"[-] No host IP addresses discovered for {domain}.")
            continue

        for ip, hosts_set in ip_to_hosts.items():
            db_data = fetch_shodan_internetdb(ip)
            candidate_ports, port_source = get_port_candidates(db_data)
            
            hosts_to_scan = list(hosts_set) if hosts_set else [ip]

            for port in candidate_ports:
                if port in WEB_PORTS:
                    is_https = port in [443, 8443]
                    protocol = "https" if is_https else "http"
                    
                    for target_host in hosts_to_scan:
                        for path in PATHS_TO_CHECK:
                            formatted_path = path if path.startswith('/') else f"/{path}"
                            
                            if (protocol == "https" and port == 443) or (protocol == "http" and port == 80):
                                host_port_str = target_host
                            else:
                                host_port_str = f"{target_host}:{port}"
                            
                            full_url = f"{protocol}://{host_port_str}{formatted_path}"
                            
                            if full_url not in seen_urls:
                                seen_urls.add(full_url)
                                all_web_targets.append({
                                    "parent_domain": domain,
                                    "ip": ip,
                                    "url": full_url,
                                    "port": port,
                                    "is_https": is_https,
                                    "software": [],
                                    "all_ports": [str(p) for p in candidate_ports] if port_source == 'Shodan InternetDB' else [],
                                    "port_source": port_source,
                                    "b64_img": None,
                                    "status": None
                                })

    print('[*] Checking DNS takeover indicators for discovered hosts...')
    findings = await asyncio.to_thread(scan_takeovers, all_hosts_by_parent)
    print(f'[*] Checked {len(findings)} host(s); potential: {sum(x["status"] == "Potential takeover" for x in findings)}, review: {sum(x["status"] == "Needs review" for x in findings)}')
    if all_web_targets:
        print(f"[*] Processing {len(all_web_targets)} unique target URLs across all domains...")
        results = await capture_screenshots(all_web_targets)
    else:
        print('[*] No active web targets. Generating DNS-only report.')
        results = []
    generate_html(results, findings)


if __name__ == "__main__":
    asyncio.run(main())