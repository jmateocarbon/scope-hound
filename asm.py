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

async def process_target_screenshot(context, target, semaphore):
    async with semaphore:
        page = None
        try:
            page = await context.new_page()
            response = await page.goto(target['url'], timeout=20000, wait_until="domcontentloaded")
            await page.wait_for_timeout(2000)
            
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
            target['status'] = "Failed"
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
    os.makedirs("reports", exist_ok=True)
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
        .card img {width:100%;height:165px;object-fit:cover;object-position:top;border-bottom:1px solid var(--border-color);background:#eaece8;}
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
        .modal-img {width:100%;border-radius:7px;margin-bottom:20px;background:#eaece8;}
        .detail-row {margin-bottom:12px;border-bottom:1px solid #ebece8;padding-bottom:12px;display:flex;align-items:flex-start;}
        .detail-label {font-size:11px;color:var(--text-muted);font-weight:750;min-width:140px;text-transform:uppercase;letter-spacing:.045em;}
        .detail-value {word-break:break-word;flex:1;font-size:13px;}
        .detail-value a {color:var(--accent-green);}
        @media(max-width:650px){.masthead{display:block}.subtitle{text-align:left;margin-top:12px}.filter-container{justify-content:flex-start}.modal{padding:20px}.detail-row{display:block}.detail-label{display:block;margin-bottom:4px}}

    </style>
</head>
<body>
    <header class="masthead">
      <div><div class="eyebrow">ScopeHound</div><h1>Attack surface <span>inventory.</span></h1></div>
      <div class="subtitle">A lightweight, local-first view of discovered assets, technologies and DNS takeover indicators.</div>
    </header>
    
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

    <div class="modal-overlay" id="modalOverlay" onclick="closeModal(event)">
        <div class="modal" onclick="event.stopPropagation()">
            <button class="close-btn" onclick="closeModal(event)">&times;</button>
            <img id="modalImg" class="modal-img" src="" alt="Full Screenshot">
            
            <div class="detail-row">
                <span class="detail-label">Target Domain:</span> 
                <span class="detail-value" id="modalParentDomain"></span>
            </div>
            <div class="detail-row">
                <span class="detail-label">Target URL:</span> 
                <span class="detail-value"><a id="modalUrl" href="" target="_blank"></a></span>
            </div>
            <div class="detail-row">
                <span class="detail-label">HTTP Status:</span> 
                <span class="detail-value" id="modalStatus"></span>
            </div>
            <div class="detail-row">
                <span class="detail-label">Resolved IP:</span> 
                <span class="detail-value" id="modalIp"></span>
            </div>
            <div class="detail-row">
                <span class="detail-label">Open Ports:</span> 
                <span class="detail-value" id="modalPorts"></span>
            </div>
            <div class="detail-row">
                <span class="detail-label">HTTPS Active:</span> 
                <span class="detail-value" id="modalHttps"></span>
            </div>
            <div class="detail-row">
                <span class="detail-label">Detected Tech:</span> 
                <div class="detail-value" id="modalSoftware"></div>
            </div>
        </div>
    </div>

    <script>
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
            card.addEventListener('click', () => openModal(index));
            const img = document.createElement('img');
            if (target.b64_img) img.src = 'data:image/jpeg;base64,' + target.b64_img;
            img.alt = 'Screenshot of ' + target.url;
            img.loading = 'lazy';
            card.appendChild(img);
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
            badges.appendChild(makeText('span', 'Port ' + target.port, 'badge ip-badge'));
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

        function openModal(index) {
            const target = targetsData[index];
            document.getElementById('modalImg').src = target.b64_img ? 'data:image/jpeg;base64,' + target.b64_img : '';
            document.getElementById('modalParentDomain').textContent = target.parent_domain;
            document.getElementById('modalUrl').href = target.url;
            document.getElementById('modalUrl').textContent = target.url;
            
            let statusStyle = 'background: var(--accent-amber-bg); color: var(--accent-amber); border: 1px solid rgba(245, 158, 11, 0.3);';
            if (target.status >= 200 && target.status < 300) statusStyle = 'background: var(--accent-green-bg); color: var(--accent-green); border: 1px solid rgba(16, 185, 129, 0.3);';
            else if (target.status >= 300 && target.status < 400) statusStyle = 'background: var(--accent-blue-bg); color: var(--accent-blue); border: 1px solid rgba(59, 130, 246, 0.3);';
            else if (target.status >= 500 || target.status === 'Failed') statusStyle = 'background: var(--accent-red-bg); color: var(--accent-red); border: 1px solid rgba(239, 68, 68, 0.3);';
            
            document.getElementById('modalStatus').innerHTML = `<span class="badge" style="${statusStyle}">HTTP ${target.status || 'N/A'}</span>`;
            document.getElementById('modalIp').textContent = target.ip;
            
            const portsStr = target.all_ports && target.all_ports.length ? target.all_ports.join(', ') : 'Unknown';
            document.getElementById('modalPorts').textContent = portsStr;
            document.getElementById('modalHttps').innerHTML = target.is_https ? '🔒 Yes' : '⚠️ No';
            
            const modalSoftwareContainer = document.getElementById('modalSoftware');
            modalSoftwareContainer.innerHTML = '';
            
            const techList = target.software ? [...new Set(target.software)] : [];
            if (techList.length > 0) {
                techList.forEach(t => {
                    const pill = document.createElement('span');
                    pill.className = 'tech-pill';
                    pill.textContent = t;
                    modalSoftwareContainer.appendChild(pill);
                });
            } else {
                modalSoftwareContainer.innerHTML = '<span style="color: var(--text-muted)">No identifiable technology stack detected</span>';
            }
            
            document.getElementById('modalOverlay').style.display = 'flex';
            document.body.style.overflow = 'hidden';
        }

        function closeModal(e) {
            document.getElementById('modalOverlay').style.display = 'none';
            document.body.style.overflow = 'auto';
        }
        
        document.addEventListener('keydown', (e) => {
            if(e.key === "Escape") closeModal();
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
            open_ports = db_data.get('ports', [80, 443])
            
            hosts_to_scan = list(hosts_set) if hosts_set else [ip]

            for port in open_ports:
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
                                    "all_ports": [str(p) for p in open_ports],
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