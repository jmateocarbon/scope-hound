"""Read-only, conservative subdomain takeover triage.

No resource claims, account creation, or exploit attempts. Fingerprints are
heuristics, never proof of claimability.
"""
from concurrent.futures import ThreadPoolExecutor, as_completed
import requests
import dns.resolver
import dns.exception

# Narrow, provider-specific fingerprints; generic 404s are intentionally excluded.
PROVIDERS = (
    ('GitHub Pages', ('github.io',), ('there isn\'t a github pages site here',)),
    ('Heroku', ('herokudns.com', 'herokuapp.com'), ('no such app', 'there is no app configured at that hostname')),
    ('Amazon S3 website', ('s3-website',), ('nosuchbucket', 'the specified bucket does not exist')),
    ('Azure App Service', ('azurewebsites.net',), ('404 web site not found',)),
    ('Fastly', ('fastly.net',), ('fastly error: unknown domain',)),
)


def query_records(host, record_type, resolver=None):
    r = resolver or dns.resolver.Resolver()
    r.timeout = 2
    r.lifetime = 4
    try:
        return [str(answer).rstrip('.').lower() for answer in r.resolve(host, record_type)]
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.resolver.NoNameservers,
            dns.exception.Timeout, dns.resolver.YXDOMAIN):
        return []


def inspect_host(host, parent, resolver=None, http_get=None):
    """Read-only DNS and optional HTTP checks for one scoped hostname."""
    if host != parent and not host.endswith('.' + parent):
        raise ValueError('Hostname outside parent-domain scope')
    cname = query_records(host, 'CNAME', resolver)
    ns = query_records(host, 'NS', resolver)
    chain = []
    seen = {host}
    current = host
    for _ in range(5):
        targets = cname if current == host else query_records(current, 'CNAME', resolver)
        if not targets:
            break
        current = targets[0]
        chain.append(current)
        if current in seen:
            break
        seen.add(current)
    target = chain[-1] if chain else None
    def matches(target_name, suffix):
        if suffix == 's3-website':
            return 's3-website' in target_name
        return target_name == suffix or target_name.endswith('.' + suffix)

    provider = next((name for name, suffixes, _ in PROVIDERS
                     if target and any(matches(target, suffix) for suffix in suffixes)), None)
    result = {'parent_domain': parent, 'hostname': host, 'cname_chain': chain,
              'ns': ns, 'provider': provider or 'Unknown', 'status': 'No indicator',
              'http_status': None, 'evidence': [], 'dig_command': f'dig {host} CNAME +short'}
    if target:
        addresses = query_records(target, 'A', resolver) + query_records(target, 'AAAA', resolver)
        if not addresses:
            result['status'] = 'Needs review'
            result['evidence'].append('CNAME target did not return A/AAAA records (not proof of takeover)')
    if ns and not target:
        result['evidence'].append('NS delegation present; requires separate manual review if orphaned')
    if provider:
        result['evidence'].append('CNAME matches known provider: ' + provider)
        getter = http_get or requests.get
        try:
            response = getter('https://' + host + '/', timeout=5, allow_redirects=False,
                              headers={'User-Agent': 'PoorMansASM/0.3'}, stream=True)
            try:
                result['http_status'] = response.status_code
                content = response.raw.read(65536, decode_content=True).decode('utf-8', errors='replace').lower() if hasattr(response, 'raw') else response.text[:65536].lower()
            finally:
                response.close()
            patterns = next(p for name, _, p in PROVIDERS if name == provider)
            if any(p in content for p in patterns):
                result['status'] = 'Potential takeover'
                result['evidence'].append('Provider-specific HTTP error fingerprint matched')
        except requests.RequestException as exc:
            result['evidence'].append('HTTP fingerprint unavailable: ' + type(exc).__name__)
    return result


def scan_takeovers(hosts_by_parent, workers=8, inspector=inspect_host):
    tasks = [(host, domain) for domain, hosts in hosts_by_parent.items() for host in sorted(set(hosts))]
    results = []
    with ThreadPoolExecutor(max_workers=workers) as pool:
        futures = {pool.submit(inspector, host, domain): (host, domain) for host, domain in tasks}
        for future in as_completed(futures):
            try:
                results.append(future.result())
            except Exception as exc:
                host, domain = futures[future]
                results.append({'hostname': host, 'parent_domain': domain, 'cname_chain': [], 'ns': [],
                                'provider': 'Unknown', 'status': 'Needs review', 'http_status': None,
                                'evidence': ['DNS check failed: ' + type(exc).__name__],
                                'dig_command': f'dig {host} CNAME +short'})
    return sorted(results, key=lambda r: (r['parent_domain'], r['hostname']))
