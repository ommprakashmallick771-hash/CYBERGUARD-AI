#!/usr/bin/env python3
"""CyberGuard AI server (pure Python standard library, no pip needed).
Runs in two modes from this one file:
  * LOCAL  (double-click run.bat): 127.0.0.1, port 8000-8010, opens the browser.
  * PUBLIC (Render / any host that sets PORT): 0.0.0.0:$PORT, no browser, SSRF-safe link scanning.
"""
import gzip, os, re, sys, json, math, ssl, socket, struct, zlib, base64, hashlib, ipaddress, subprocess, threading, webbrowser, unicodedata, mimetypes, io, time, signal, traceback, itertools, http.client
from datetime import datetime, timezone
from http.server import ThreadingHTTPServer, SimpleHTTPRequestHandler
from urllib.parse import urlparse, unquote, urljoin
from urllib.request import Request, build_opener, urlopen, HTTPRedirectHandler
from urllib.error import HTTPError

ROOT = os.path.dirname(os.path.abspath(__file__)); WEB = os.path.join(ROOT, 'web'); IS_WIN = os.name == 'nt'
for e, t in (('.webmanifest', 'application/manifest+json'), ('.css', 'text/css'), ('.js', 'application/javascript'), ('.svg', 'image/svg+xml'), ('.webp', 'image/webp')): mimetypes.add_type(t, e)
UA = 'Mozilla/5.0 (CyberGuardScanner)'

# ---------------------------------------------------------------- deployment mode + limits
def _detect_public():
    # CYBERGUARD_MODE=local|public forces a mode. Otherwise: Render (or any host) sets PORT -> public mode.
    m = os.environ.get('CYBERGUARD_MODE', '').strip().lower()
    if m in ('local', 'dev', 'development'): return False
    if m in ('public', 'production', 'prod', 'render'): return True
    return bool(os.environ.get('PORT') or os.environ.get('RENDER'))
PUBLIC = _detect_public()
def _mb(name, default):
    try: return int(float(os.environ.get(name, default)) * 1_000_000)
    except ValueError: return int(default * 1_000_000)
MAX_UPLOAD = _mb('MAX_UPLOAD_MB', 15 if PUBLIC else 30)          # image uploads (bytes); local mode keeps the original 30 MB
MAX_LINK_BODY = 8192                                              # JSON body of /api/link
MAX_TEXT_BODY = 1_000_000 if PUBLIC else MAX_UPLOAD               # JSON body of /api/emoji
MAX_TEXT_CHARS = 100_000 if PUBLIC else None                      # pasted characters (public mode only)
MAX_URL_CHARS = 2048
SCAN_SLOTS = threading.BoundedSemaphore(max(1, int(os.environ.get('MAX_CONCURRENT_SCANS', '4'))))
WEB_REAL = os.path.realpath(WEB); STARTED = time.time()
RATE_LIMIT = int(os.environ.get('RATE_LIMIT_PER_MIN', '40')) if PUBLIC else 0          # scans per IP per minute (0 = off)
_HITS, _HITS_LOCK = {}, threading.Lock()
def rate_ok(ip):
    if not RATE_LIMIT: return True
    now = time.time()
    with _HITS_LOCK:
        q = [t for t in _HITS.get(ip, ()) if now - t < 60]
        if len(q) >= RATE_LIMIT: _HITS[ip] = q; return False
        q.append(now); _HITS[ip] = q
        if len(_HITS) > 5000:
            for k in [k for k, v in _HITS.items() if not v or now - v[-1] > 60]: _HITS.pop(k, None)
    return True
_GZ = {}                                                                               # (path, mtime, size) -> gzipped bytes
class UserError(ValueError):
    """A deliberate, user-friendly error message (safe to show to visitors)."""
class Blocked(Exception):
    """An outbound connection that the public server refuses to make (SSRF protection)."""

# ---------------------------------------------------------------- helpers
def L(name, risk, details, status=None):
    risk = int(max(0, min(100, risk)))
    return {'name': name, 'risk': risk, 'status': status or ('bad' if risk >= 50 else 'warn' if risk >= 20 else 'ok'), 'details': details or ['No issues found in this layer.']}
def lay(layers, name, S): layers.append(L(name, sum(p for p, _ in S), [m for _, m in S]))
def entropy(s):
    return -sum((s.count(c) / len(s)) * math.log2(s.count(c) / len(s)) for c in set(s)) if s else 0.0
def lev(a, b):
    p = list(range(len(b) + 1))
    for i, x in enumerate(a, 1):
        c = [i]
        for j, y in enumerate(b, 1): c.append(min(p[j] + 1, c[j - 1] + 1, p[j - 1] + (x != y)))
        p = c
    return p[-1]
def sh(cmd, t=10):
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=t); return (r.stdout or '') + (r.stderr or '')
    except Exception: return ''
def pr(s): return sum(c.isprintable() or c in '\n\r\t' for c in s) / len(s) if s else 0
def make_report(r):
    b = '=' * 66
    o = [b, '  CYBERGUARD AI - SECURITY SCAN REPORT', b, 'Scan type  : ' + r['title'], 'Target     : ' + r['target'], 'Scanned at : ' + datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC'),
         'Verdict    : %s  (risk score %s/100)' % (r['verdict'], r['score']), '', 'SUMMARY', r['summary'], '']
    for i, l in enumerate(r['layers'], 1):
        o += ['[Layer %d] %s -> %s (risk %d/100)' % (i, l['name'], l['status'].upper(), l['risk'])] + ['    - ' + d for d in l['details']] + ['']
    for t in r.get('tables', []): o += [t['title'].upper(), ' | '.join(t['cols'])] + [' | '.join(str(c) for c in x) for x in t['rows']] + ['']
    for k in r.get('blocks', []): o += [k['title'].upper(), k['text'], '']
    o += [b, 'DISCLAIMER: CyberGuard is AI-powered and can make mistakes. Treat this report as guidance,', 'not proof. Created by Omm Prakash Mallick, SBD International School, Bhadrak.', b]
    return '\n'.join(o)
def finish(title, target, layers, score, verdict, level, summary, tables=None, blocks=None):
    r = {'title': title, 'target': target, 'layers': layers, 'score': int(score), 'verdict': verdict, 'level': level, 'summary': summary, 'tables': tables or [], 'blocks': blocks or []}
    r['report'] = make_report(r); return r

PAT = [('Script tag', r'<\s*script', 40), ('JavaScript URI', r'javascript\s*:', 40), ('Code execution call', r'\b(eval|exec|system|popen|Function)\s*\(', 30),
       ('PowerShell', r'powershell|invoke-expression|\biex\b|-enc(odedcommand)?\s', 45), ('Windows shell/LOLBin', r'cmd(\.exe)?\s*/c|wscript|cscript|mshta|regsvr32|certutil|bitsadmin', 45),
       ('Unix shell command', r'(curl|wget)[^\n]{0,80}\|\s*(ba)?sh|rm\s+-rf|chmod\s+\+x|/bin/(ba)?sh|nc\s+-e', 45), ('SQL injection', r"(\'|\")\s*or\s+1\s*=\s*1|union\s+select|drop\s+table|;\s*--", 35),
       ('HTML event handler', r'\bon(error|load|click|mouseover|focus)\s*=', 30), ('Data URI', r'data:[a-z/+\-]+;base64', 30), ('Template injection', r'\{\{[^}]{1,60}\}\}|\$\{[^}]{1,60}\}', 20),
       ('Path traversal', r'\.\./\.\./', 25), ('PHP code', r'<\?php|base64_decode\s*\(', 40), ('URL', r'https?://[^\s<>"\']{4,}', 6)]
SKIPURL = re.compile(r'ns\.adobe\.com|w3\.org|purl\.org|iptc\.org|xmlns|schemas\.|ns\.useplus|cipa\.jp|exif', re.I)
def pattern_hits(text):
    out = []
    for name, rx, risk in PAT:
        for m in list(re.finditer(rx, text, re.I))[:3]:
            if name == 'URL' and SKIPURL.search(m.group(0)): continue
            out.append((name, m.group(0)[:90].replace('\n', ' '), risk))
    return out
def b64_blobs(text):
    res = []
    for m in re.finditer(r'[A-Za-z0-9+/]{24,}={0,2}', text):
        s = m.group(0)
        try:
            t = base64.b64decode(s + '=' * (-len(s) % 4)).decode('utf-8')
            if len(t) >= 8 and pr(t) > 0.9: res.append((s[:36] + '...', t[:300]))
        except Exception: pass
    return res[:5]

# ---------------------------------------------------------------- LINK
BRANDS = {'instagram': ['instagram.com'], 'facebook': ['facebook.com', 'fb.com'], 'google': ['google.com', 'gmail.com', 'youtube.com'], 'paypal': ['paypal.com'], 'amazon': ['amazon.com', 'amazon.in', 'amazonaws.com'],
          'microsoft': ['microsoft.com', 'live.com', 'office.com', 'outlook.com'], 'apple': ['apple.com', 'icloud.com'], 'netflix': ['netflix.com'], 'whatsapp': ['whatsapp.com', 'whatsapp.net'],
          'sbi': ['onlinesbi.sbi', 'sbi.co.in'], 'hdfc': ['hdfcbank.com'], 'icici': ['icicibank.com'], 'paytm': ['paytm.com'], 'phonepe': ['phonepe.com'], 'twitter': ['twitter.com', 'x.com'],
          'linkedin': ['linkedin.com'], 'github': ['github.com'], 'dropbox': ['dropbox.com'], 'binance': ['binance.com'], 'flipkart': ['flipkart.com'], 'telegram': ['telegram.org', 't.me'], 'snapchat': ['snapchat.com'], 'spotify': ['spotify.com']}
TRUSTED = {d for v in BRANDS.values() for d in v} | {'wikipedia.org', 'openai.com', 'anthropic.com', 'claude.ai', 'python.org', 'mozilla.org', 'cdninstagram.com', 'fbcdn.net', 'stackoverflow.com', 'microsoftonline.com'}
SLD = {'co.uk', 'org.uk', 'ac.uk', 'gov.uk', 'com.au', 'co.in', 'gov.in', 'nic.in', 'ac.in', 'org.in', 'net.in', 'co.jp', 'com.br', 'co.za', 'com.cn'}
KW = ['login', 'signin', 'verify', 'secure', 'account', 'update', 'confirm', 'banking', 'password', 'wallet', 'free', 'gift', 'prize', 'claim', 'suspend', 'unlock', 'otp', 'kyc', 'billing', 'recover', 'alert']
BADTLD = {'tk', 'ml', 'ga', 'cf', 'gq', 'xyz', 'top', 'click', 'zip', 'mov', 'work', 'support', 'rest', 'icu', 'buzz', 'cyou', 'monster', 'sbs', 'cfd', 'loan'}
SHORT = {'bit.ly', 'tinyurl.com', 't.co', 'goo.gl', 'is.gd', 'cutt.ly', 'rb.gy', 'shorturl.at', 'ow.ly', 'tiny.cc', 'buff.ly', 'rebrand.ly'}
def regdom(h):
    p = h.split('.')
    if len(p) >= 3 and '.'.join(p[-2:]) in SLD: return '.'.join(p[-3:])
    return '.'.join(p[-2:]) if len(p) >= 2 else h
def is_trusted(rd): return rd in TRUSTED or rd.endswith(('.gov.in', '.nic.in', '.gov', '.edu', '.ac.in'))
class RH(HTTPRedirectHandler):
    def __init__(s): s.chain = []
    def redirect_request(s, req, fp, code, msg, hdrs, newurl):
        s.chain.append(newurl); return super().redirect_request(req, fp, code, msg, hdrs, newurl)
def sysdns(h):
    if not re.fullmatch(r'[a-z0-9.\-]+', h): return 'n/a', ''
    if IS_WIN:
        o = sh(['powershell', '-NoProfile', '-NonInteractive', '-Command', "Resolve-DnsName -Name '%s' -ErrorAction SilentlyContinue | Select-Object -First 6 Name,Type,IPAddress | Format-Table -HideTableHeaders | Out-String -Width 120" % h], 15)
        return 'PowerShell Resolve-DnsName', o.strip()
    for c in (['dig', '+short', h], ['host', h], ['nslookup', h]):
        o = sh(c)
        if o.strip(): return c[0] + ' (Linux shell)', o.strip()
    return 'no DNS tool available', ''

# ---- outbound safety (SSRF protection). In PUBLIC mode the server only talks to public internet addresses,
# ---- on ports 80/443, always connecting to the exact IP it validated (so DNS rebinding cannot swap it later),
# ---- and re-validating every redirect hop. In LOCAL mode the original unrestricted behaviour is kept.
_NONPUBLIC_NETS = [ipaddress.ip_network(n) for n in ('64:ff9b::/96', '64:ff9b:1::/48', '2002::/16', '2001::/32', '::/96', '100.64.0.0/10', '192.0.0.0/24', '198.18.0.0/15')]
def is_public_ip(ip):
    try: a = ipaddress.ip_address(str(ip).split('%')[0])
    except ValueError: return False
    if a.version == 6 and a.ipv4_mapped: a = a.ipv4_mapped
    if not a.is_global or a.is_multicast: return False
    return not any(n.version == a.version and a in n for n in _NONPUBLIC_NETS)
def resolve_ips(h, timeout=6):
    out = []
    def w():
        try: out.extend(sorted({a[4][0] for a in socket.getaddrinfo(h, None, proto=socket.IPPROTO_TCP)}))
        except Exception: pass
    t = threading.Thread(target=w, daemon=True); t.start(); t.join(timeout)
    return list(out)
def guard(ips, port):
    if not PUBLIC: return
    if port not in (80, 443): raise Blocked('live connections are limited to ports 80 and 443 on this public server')
    if not ips: raise OSError('host did not resolve')
    if any(not is_public_ip(i) for i in ips): raise Blocked('this address resolves to a private, loopback, link-local or otherwise non-public IP; the public server never connects to such addresses (SSRF protection)')
def dial(ips, port, timeout=5):
    last = None
    for ip in ips[:6]:
        try: return socket.create_connection((ip, port), timeout=timeout)
        except OSError as e: last = e
    raise last or OSError('no address to connect to')
def tls_connect(h, port, ips):
    ctx = ssl.create_default_context()
    if not PUBLIC: s0 = socket.create_connection((h, port), timeout=6)
    else: guard(ips, port); s0 = dial(ips, port, 5)
    try: return ctx.wrap_socket(s0, server_hostname=h)
    except Exception: s0.close(); raise
class _PinHTTP(http.client.HTTPConnection):
    def __init__(s, host, port, ips, timeout): super().__init__(host, port, timeout=timeout); s._ips = ips
    def connect(s): s.sock = dial(s._ips, s.port, s.timeout)
class _PinHTTPS(http.client.HTTPSConnection):
    def __init__(s, host, port, ips, timeout): super().__init__(host, port, timeout=timeout); s._ips = ips; s._ctx = ssl.create_default_context()
    def connect(s): s.sock = s._ctx.wrap_socket(dial(s._ips, s.port, s.timeout), server_hostname=s.host)
def fetch_safe(raw, h0, ips0, hops=5, budget=14):
    """Public-mode page fetch: validated IPs only, pinned connection, manual redirects re-validated at every hop."""
    chain = []; url = raw; end = time.time() + budget
    for hop in range(hops + 1):
        u = urlparse(url)
        if u.scheme not in ('http', 'https'): raise Blocked('a redirect pointed to a non-web address (%s://); not followed' % u.scheme)
        host = (u.hostname or '').lower().rstrip('.')
        try: host = host.encode('idna').decode()
        except Exception: pass
        if not re.fullmatch(r'[a-z0-9.\-]+|[0-9a-f:]+', host or '') or host.startswith('-'): raise Blocked('a redirect pointed to an invalid host name; not followed')
        port = u.port or (443 if u.scheme == 'https' else 80)
        ips = ips0 if (hop == 0 and host == h0) else resolve_ips(host)
        guard(ips, port)
        conn = (_PinHTTPS if u.scheme == 'https' else _PinHTTP)(host, port, ips, 6)
        try:
            conn.request('GET', (u.path or '/') + ('?' + u.query if u.query else ''), headers={'User-Agent': UA, 'Accept': 'text/html,*/*;q=0.5', 'Accept-Encoding': 'identity', 'Connection': 'close'})
            r = conn.getresponse(); loc = r.getheader('Location'); ct = r.getheader('Content-Type', '') or ''
            if r.status in (301, 302, 303, 307, 308) and loc:
                chain.append(urljoin(url, loc))
                if hop == hops: return url, 'redirect limit reached', '', '', chain
                url = chain[-1]; continue
            body = b''
            if 'text' in ct or 'html' in ct:
                while len(body) < 300000 and time.time() < end:
                    c = r.read(min(16384, 300000 - len(body)))
                    if not c: break
                    body += c
            return url, r.status, ct, body.decode('utf-8', 'ignore'), chain
        finally: conn.close()
    return url, 'redirect limit reached', '', '', chain
def fetch_live(raw, rh, h, ips):
    if PUBLIC: return fetch_safe(raw, h, ips)
    try: resp = build_opener(rh).open(Request(raw, headers={'User-Agent': UA}), timeout=8)
    except HTTPError as e: resp = e
    ct = resp.headers.get('Content-Type', '')
    body = resp.read(300000).decode('utf-8', 'ignore') if ('text' in ct or 'html' in ct) else ''
    return resp.geturl(), getattr(resp, 'status', getattr(resp, 'code', '?')), ct, body, rh.chain
def max_run(text): return max((sum(1 for _ in g) for _, g in itertools.groupby(text)), default=0)

def analyze_link(raw):
    raw = (raw or '').strip()
    if not raw: raise UserError('Please enter a link.')
    if len(raw) > MAX_URL_CHARS: raise UserError('This link is too long (maximum %d characters).' % MAX_URL_CHARS)
    if not re.match(r'^[a-z][a-z0-9+.\-]*://', raw, re.I): raw = 'https://' + raw
    u = urlparse(raw)
    if u.scheme not in ('http', 'https'): raise UserError('Only http:// and https:// links can be scanned.')
    h = (u.hostname or '').lower().rstrip('.')
    try: h = h.encode('idna').decode()
    except Exception: pass
    if not re.fullmatch(r'[a-z0-9.\-]+|[0-9a-f:]+', h or '') or h.startswith('-'): raise UserError('This is not a valid web address.')
    try: port = u.port
    except ValueError: raise UserError('Invalid port number in link.')
    try: ipaddress.ip_address(h); isip = True
    except ValueError: isip = False
    https = u.scheme == 'https'; rd = regdom(h); trusted = is_trusted(rd) and not isip; layers = []; notes = []
    # L1 structure
    S = [(0 if https else 20, 'Connection uses HTTPS.' if https else 'Link uses plain HTTP - traffic is not encrypted.')]
    sub = max(0, h.count('.') - rd.count('.'))
    if isip: S.append((40, 'Host is a raw IP address instead of a domain name.'))
    if '@' in u.netloc: S.append((35, "Link contains '@' - the real destination is hidden after it."))
    if len(raw) > 100: S.append((10, 'Very long URL (%d characters).' % len(raw)))
    if sub >= 3: S.append((20, '%d sub-domain levels - often used to fake a brand name.' % sub))
    if h.count('-') >= 3: S.append((10, 'Many hyphens in host name.'))
    if port not in (None, 80, 443): S.append((15, 'Unusual port %s.' % port))
    if 'xn--' in h: S.append((30, 'Punycode (xn--) domain - can hide look-alike foreign letters.'))
    if re.search(r'%[0-9a-f]{2}', raw, re.I): S.append((5, 'URL contains percent-encoded characters.'))
    lay(layers, 'URL structure', S)
    # L2 brand
    norm = h.replace('0', 'o').replace('1', 'l').replace('3', 'e').replace('5', 's').replace('rn', 'm').replace('vv', 'w'); S = []
    if trusted: S.append((0, '%s is a well-known official domain.' % rd))
    else:
        toks = set(re.split(r'[.\-]', norm)); label = rd.split('.')[0]
        for b, doms in BRANDS.items():
            if rd in doms: continue
            if b in toks or (len(b) >= 6 and b in norm):
                S.append((60, "Host contains brand '%s' but is not an official %s domain (%s) - classic impersonation." % (b, b, ', '.join(doms)))); break
            if len(label) >= 5 and label != b and lev(label, b) <= 2:
                S.append((65, "Domain '%s' is a look-alike of '%s' (typosquatting)." % (label, b))); break
        if not S: S.append((0, 'No brand impersonation detected. Domain is not on the trusted list (unknown, not necessarily bad).'))
    lay(layers, 'Brand impersonation & reputation', S)
    # L3 lexical
    txt = (h + u.path + u.query).lower(); kws = [k for k in KW if k in txt]; tld = h.rsplit('.', 1)[-1]; S = []
    if kws: S.append((min(30, 8 * len(kws)) if not trusted else 0, 'Phishing-style words: ' + ', '.join(kws)))
    if tld in BADTLD: S.append((25, "Top-level domain '.%s' is heavily abused by scammers." % tld))
    if rd in SHORT: S.append((30, 'URL shortener - the final destination is hidden.'))
    if re.search(r'(url|redirect|next|goto|link)=https?', raw, re.I): S.append((25, 'Open-redirect style parameter found in query.'))
    lay(layers, 'Lexical, TLD & shortener analysis', S or [(0, 'No suspicious words, TLDs or shorteners.')])
    # L4 DNS (system level)
    ips = resolve_ips(h)
    tool, out = sysdns(h); S = []
    if not ips: S.append((35, 'Domain did not resolve (dead/taken down, mistyped, or you are offline).'))
    else:
        S.append((0, 'Resolved to: ' + ', '.join(ips[:6])))
        if any(not is_public_ip(i) for i in ips): S.append((40, 'Resolves to a PRIVATE / non-public address - suspicious for a public site.'))
    S.append((0, 'System tool used: ' + tool)); S += [(0, '  ' + x.strip()) for x in out.splitlines()[:5] if x.strip()]
    lay(layers, 'DNS lookup (PowerShell / Linux shell)', S); cert = {}
    # L5 TLS
    S = []
    try:
        with tls_connect(h, port or 443, ips) as ss:
            cert = ss.getpeercert(); iss = dict(x[0] for x in cert.get('issuer', ())).get('organizationName', 'unknown')
            nb = ssl.cert_time_to_seconds(cert['notBefore']); age = (datetime.now(timezone.utc).timestamp() - nb) / 86400
            S.append((0, 'Valid certificate for this host, issued by %s, using %s.' % (iss, ss.version())))
            S.append((40 if age < 14 else 15 if age < 45 else 0, 'Certificate is %d days old.' % age))
    except Blocked as e: S.append((0, 'NOT PERFORMED on this public server: %s.' % e))
    except ssl.SSLCertVerificationError as e: S.append((70, 'Certificate FAILED verification: %s' % (e.verify_message or e)))
    except Exception as e: S.append((12 if https else 0, 'Could not complete a TLS handshake (%s).' % type(e).__name__))
    lay(layers, 'TLS / SSL certificate', S)
    # L6 live content
    S = []; chain = []; final = raw; title = ''; rh = RH()
    try:
        final, status, ct, body, chain = fetch_live(raw, rh, h, ips)
        S.append((0, 'Server answered (%s), content type: %s' % (status, ct or 'unknown')))
        frd = regdom((urlparse(final).hostname or '').lower())
        if frd != rd: S.append((25 if not is_trusted(frd) else 0, 'Redirects to a different domain: %s' % frd))
        if len(chain) > 3: S.append((15, '%d redirects in a row.' % len(chain)))
        if re.search(r'(exe|msi|apk|zip|scr|bat)', ct) or 'octet-stream' in ct: S.append((50, 'Link triggers a file download.'))
        mt = re.search(r'<title[^>]*>(.*?)</title>', body, re.I | re.S); title = mt.group(1).strip()[:100] if mt else ''
        if not trusted:
            pw = len(re.findall(r'type\s*=\s*["\']?password', body, re.I))
            if pw: S.append((30, 'Page has %d password field(s) - it asks for credentials.' % pw))
            for a in re.findall(r'<form[^>]*action\s*=\s*["\']([^"\']+)', body, re.I)[:5]:
                if a.startswith(('http', '//')) and regdom((urlparse(a if a.startswith('http') else 'https:' + a).hostname or '')) != rd: S.append((35, 'Form sends data to another site: ' + a[:80]))
            ob = sum(body.count(x) for x in ('eval(', 'atob(', 'unescape(', 'fromCharCode'))
            if ob >= 3: S.append((20, 'Obfuscated JavaScript markers found (%d).' % ob))
            if re.search(r'<iframe[^>]*(display\s*:\s*none|width\s*=\s*["\']?0)', body, re.I): S.append((25, 'Hidden iframe found.'))
            if re.search(r'http-equiv\s*=\s*["\']?refresh', body, re.I): S.append((10, 'Meta-refresh auto redirect.'))
            if re.search(r'contextmenu|oncontextmenu\s*=\s*["\']?return false', body, re.I): S.append((8, 'Right-click blocking script.'))
        if len(S) == 1: S.append((0, 'No malicious page behaviour found in the first 300 KB.'))
    except Blocked as e: S.append((0, 'NOT PERFORMED on this public server: %s.' % e))
    except Exception as e: S.append((8, 'Live page could not be fetched (%s) - content checks skipped.' % type(e).__name__))
    lay(layers, 'Live content & redirect analysis', S)
    # L7 domain age
    S = []
    if isip: S.append((0, 'IP address - no registration data.'))
    else:
        try:
            j = json.loads(urlopen(Request('https://rdap.org/domain/' + rd, headers={'User-Agent': UA}), timeout=8).read())
            ev = {e.get('eventAction'): e.get('eventDate') for e in j.get('events', [])}; dt = datetime.fromisoformat(ev['registration'].replace('Z', '+00:00'))
            if dt.tzinfo is None: dt = dt.replace(tzinfo=timezone.utc)
            days = (datetime.now(timezone.utc) - dt).days
            S.append((60 if days < 7 else 50 if days < 30 else 25 if days < 90 else 8 if days < 365 else 0, 'Domain registered %s (%d days ago).' % (dt.date(), days)))
        except Exception: S.append((0, 'Registration date not available (offline or registry has no public data).'))
    lay(layers, 'Domain age (RDAP registry)', S)
    # L8 ML
    digits = sum(c.isdigit() for c in h) / max(1, len(h)); ent = entropy(h)
    z = -4.0 + 0.018 * len(raw) + 0.35 * sub + 0.5 * h.count('-') + 3 * digits + 0.6 * max(0, ent - 3.3) + 0.7 * len(kws) + (0 if https else 1.2) + (2.5 if isip else 0) + (2 if '@' in u.netloc else 0) + (1 if tld in BADTLD else 0)
    p = 1 / (1 + math.exp(-z))
    lay(layers, 'Machine-learning risk model', [(int(p * 100), 'Logistic model probability of phishing: %.1f%%' % (p * 100)), (0, 'Features: length=%d, sub-domains=%d, hyphens=%d, digit ratio=%.2f, entropy=%.2f, keywords=%d' % (len(raw), sub, h.count('-'), digits, ent, len(kws)))])
    for l in layers:
        if any(d.startswith('NOT PERFORMED') for d in l['details']): l['status'] = 'warn'; notes.append(l['name'])
    rs = [l['risk'] for l in layers]; w = [1, 1.3, 1, .8, 1, 1.1, 1, 1]
    score = 0.4 * sum(a * b for a, b in zip(rs, w)) / sum(w) + 0.6 * max(rs)
    if trusted and layers[1]['risk'] < 50: score *= 0.12
    score = int(min(100, round(score))); level = 'safe' if score < 25 else 'warn' if score < 50 else 'bad'
    verdict = {'safe': 'Likely Safe', 'warn': 'Suspicious - be careful', 'bad': 'Phishing / Dangerous'}[level]
    top = [l['name'] for l in layers if l['risk'] >= 20]
    summary = '%s scored %d/100. %s' % (rd, score, ('Concerns found in: ' + '; '.join(top) + '.') if top else 'No major red flags were found in any of the 8 layers.') + ' Never enter passwords or OTPs unless you are sure of the address.'
    if notes: summary += ' IMPORTANT: these checks were NOT performed on this public server and are not part of the score: ' + '; '.join(notes) + '.'
    tab = [{'title': 'URL anatomy', 'cols': ['Part', 'Value'], 'rows': [['Scheme', u.scheme], ['Host', h], ['Registered domain', rd], ['Sub-domain levels', sub], ['Path', u.path or '/'], ['Query', u.query or '-'], ['Port', port or 'default']]}]
    blk = [{'title': 'Technical details', 'text': 'Resolved IPs : %s\nFinal URL    : %s\nRedirects    : %s\nPage title   : %s\nCertificate  : %s' % (', '.join(ips) or '-', final, ' -> '.join(chain) or 'none', title or '-', 'subject ' + str(dict(x[0] for x in cert.get('subject', ()))) if cert else 'n/a')}]
    return finish('Phishing Link Detection', raw, layers, score, verdict, level, summary, tab, blk)

# ---------------------------------------------------------------- EMOJI / TEXT
ZW = {0x200B, 0x200C, 0x2060, 0xFEFF, 0x180E}; BIDI = set(range(0x202A, 0x202F)) | set(range(0x2066, 0x206A)) | {0x200E, 0x200F, 0x061C}
def bits_text(bits):
    best = ''
    for sw in (0, 1):
        b = ''.join(str(int(x) ^ sw) for x in bits)
        t = bytes(int(b[i:i + 8], 2) for i in range(0, len(b) // 8 * 8, 8)).decode('utf-8', 'ignore')
        if len(t) >= 2 and pr(t) > 0.8 and len(t) > len(best): best = t
    return best
def isvs(k): return 0xFE00 <= k <= 0xFE0F or 0xE0100 <= k <= 0xE01EF
def analyze_text(text):
    if not text: raise UserError('Paste some emoji or text first.')
    cnt, first = {}, {}
    for i, c in enumerate(text):
        k = ord(c)
        if 32 <= k < 127 or c in '\n\r\t': continue
        cnt[k] = cnt.get(k, 0) + 1; first.setdefault(k, i)
    tagtxt = ''.join(chr(ord(c) - 0xE0000) for c in text if 0xE0020 <= ord(c) <= 0xE007E); legit = tagtxt in ('gbeng', 'gbsct', 'gbwls')
    zw = [c for c in text if ord(c) in (0x200B, 0x200C)]; zmsg = bits_text(['0' if ord(c) == 0x200B else '1' for c in zw]) if len(zw) >= 8 else ''
    vs = [ord(c) for c in text if isvs(ord(c))]; vb = bytes((k - 0xFE00) if k < 0xFE10 else (k - 0xE0100 + 16) for k in vs).decode('utf-8', 'ignore')
    vmsg = vb if len(vs) >= 6 and len(vb.strip()) >= 3 and pr(vb) > 0.7 else ''
    bidi = [c for c in text if ord(c) in BIDI]; ctrl = [c for c in text if unicodedata.category(c) in ('Cc', 'Co', 'Cn') and c not in '\n\r\t']
    run = mx = 0
    for c in text:
        run = run + 1 if unicodedata.category(c) in ('Mn', 'Me') else 0; mx = max(mx, run)
    vis = ''.join(c for c in text if unicodedata.category(c) not in ('Cf', 'Co', 'Cn') and not isvs(ord(c)) and (c in '\n\t\r' or unicodedata.category(c) != 'Cc'))
    secrets = [x for x in (tagtxt if not legit else '', zmsg, vmsg) if x]
    allt = vis + '\n' + '\n'.join(secrets); blobs = b64_blobs(allt); allt += '\n' + '\n'.join(d for _, d in blobs); hits = pattern_hits(allt); layers = []
    lay(layers, 'Zero-width steganography', [(55 if zmsg else 15 if len(zw) >= 8 else 0, ('%d invisible zero-width characters decode to hidden text: "%s"' % (len(zw), zmsg[:120])) if zmsg else ('%d zero-width characters found but no readable message.' % len(zw)) if zw else 'No zero-width characters.')])
    lay(layers, 'Unicode TAG characters (hidden ASCII)', [(0 if not tagtxt or legit else 65, 'No TAG characters.' if not tagtxt else 'TAG characters decode to: "%s"%s' % (tagtxt[:150], ' (normal flag emoji)' if legit else ' - invisible text smuggled inside the emoji (used for prompt injection / payload hiding).'))])
    lay(layers, 'Variation-selector smuggling', [(60 if vmsg else 10 if len(vs) >= 12 else 0, ('%d variation selectors decode to hidden data: "%s"' % (len(vs), vmsg[:150])) if vmsg else ('%d variation selectors (normal emoji styling).' % len(vs)) if vs else 'None found.')])
    lay(layers, 'Bidirectional (Trojan-Source) controls', [(35 if bidi else 0, ('%d direction-control characters can reorder text to disguise code or links.' % len(bidi)) if bidi else 'No direction-override characters.')])
    lay(layers, 'Control, private-use & unassigned code points', [(25 if ctrl else 0, ('%d control/private/unassigned code points: ' % len(ctrl) + ', '.join(sorted({'U+%04X' % ord(c) for c in ctrl})[:8])) if ctrl else 'None found.')])
    fl = []
    if mx >= 12: fl.append((40, 'Stacked combining marks (%d in a row) - "zalgo" text that can crash or freeze apps.' % mx))
    if len(text) > 20000: fl.append((15, 'Very large input (%d characters) - flood/DoS style.' % len(text)))
    if max_run(text) >= 2000: fl.append((20, 'One character repeated 2000+ times.'))
    lay(layers, 'Crash, zalgo & flood patterns', fl or [(0, 'No crash-style patterns (longest combining run: %d).' % mx)])
    hs = min(70, sum(r for _, _, r in hits if _ != 'URL') + (6 if any(n == 'URL' for n, _, _ in hits) else 0))
    lay(layers, 'Code & command patterns', [(hs, '%s: %s' % (n, s)) for n, s, _ in hits][:10] or [(0, 'No script, shell, SQL or injection patterns found.')][0:1])
    if not hits: layers[-1]['details'] = ['No script, shell, SQL or injection patterns found.']
    lay(layers, 'Encoded payloads (Base64)', [(20, 'Base64 decodes to: ' + d[:100]) for _, d in blobs] or [(0, 'No encoded payloads.')])
    score = min(100, sum(l['risk'] for l in layers)); level = 'safe' if score < 20 else 'warn' if score < 50 else 'bad'
    verdict = {'safe': 'Clean - nothing hidden found', 'warn': 'Suspicious content', 'bad': 'Dangerous - hidden payload detected'}[level]
    emo = sum(1 for c in text if ord(c) >= 0x1F000 or 0x2600 <= ord(c) < 0x2800)
    def note(k):
        c = chr(k); cat = unicodedata.category(c)
        if 0xE0020 <= k <= 0xE007E: return 'HIDDEN TAG char -> "%s"' % chr(k - 0xE0000)
        if k in (0x200B, 0x200C): return 'SUSPICIOUS zero-width (can carry binary data)'
        if k == 0x200D: return 'Zero-width joiner (normal in emoji sequences)'
        if k in (0xFE0F, 0xFE0E): return 'Variation selector (normal emoji style)'
        if isvs(k): return 'SUSPICIOUS variation selector (data carrier)'
        if k in BIDI: return 'SUSPICIOUS direction control'
        if k in ZW: return 'Invisible character'
        if cat in ('Cc', 'Co', 'Cn'): return 'SUSPICIOUS control/private/unassigned'
        if cat in ('Mn', 'Me'): return 'Combining mark'
        return 'Emoji / symbol' if (k >= 0x1F000 or 0x2600 <= k < 0x2800) else 'Visible character'
    rows = [[('U+%04X' % k), (chr(k) if unicodedata.category(chr(k))[0] not in 'CZM' else '(invisible)'), unicodedata.name(chr(k), '(unnamed)'), unicodedata.category(chr(k)), n, first[k], note(k)] for k, n in cnt.items()]
    rows.sort(key=lambda r: (0 if 'SUSPICIOUS' in r[6] or 'HIDDEN' in r[6] else 1, -r[4])); rows = rows[:150]
    blocks = []
    if secrets: blocks.append({'title': 'EXACT hidden secret text recovered', 'text': '\n'.join('%s: %s' % (m, s) for m, s in (('TAG characters', tagtxt if not legit else ''), ('Zero-width bits', zmsg), ('Variation selectors', vmsg)) if s)})
    if hits: blocks.append({'title': 'Code patterns found (exact text)', 'text': '\n'.join('[%s] %s' % (n, s) for n, s, _ in hits)})
    summary = 'Scanned %d characters (%d emoji/symbols, %d distinct special code points). %s' % (len(text), emo, len(cnt), ('Hidden text was recovered and is shown below.' if secrets else 'No hidden messages were decoded.'))
    return finish('Emoji & Text Hidden-Code Scan', '%d characters pasted' % len(text), layers, score, verdict, level, summary, [{'title': 'Character-by-character analysis (special characters)', 'cols': ['Code point', 'Glyph', 'Unicode name', 'Category', 'Count', 'First position', 'Meaning'], 'rows': rows}], blocks)

# ---------------------------------------------------------------- IMAGES
def sniff(d):
    if d[:8] == b'\x89PNG\r\n\x1a\n': return 'PNG'
    if d[:3] == b'\xff\xd8\xff': return 'JPEG'
    if d[:6] in (b'GIF87a', b'GIF89a'): return 'GIF'
    if d[:4] == b'RIFF' and d[8:12] == b'WEBP': return 'WEBP'
    if d[:2] == b'BM': return 'BMP'
    return None
def parse_png(d, m):
    p = 8
    while p + 12 <= len(d):
        n, t = struct.unpack('>I4s', d[p:p + 8]); t = t.decode('latin1')
        if p + 12 + n > len(d): m['trail'] = d[p:]; m['chunks'].append(t + '(truncated)'); return
        b = d[p + 8:p + 8 + n]; m['chunks'].append(t)
        if t == 'IHDR': m['w'], m['h'], m['bd'], m['ct'], _, _, m['il'] = struct.unpack('>IIBBBBB', b[:13])
        elif t == 'IDAT': m['idat'] += b
        elif t == 'tEXt': k, _, v = b.partition(b'\0'); m['texts'].append((k.decode('latin1'), v.decode('latin1')))
        elif t == 'zTXt':
            k, _, v = b.partition(b'\0')
            try: m['texts'].append((k.decode('latin1'), zlib.decompress(v[1:]).decode('utf-8', 'ignore')))
            except Exception: pass
        elif t == 'iTXt':
            k, _, r = b.partition(b'\0'); comp = r[0]; r = r[2:]; _, _, r = r.partition(b'\0'); _, _, r = r.partition(b'\0')
            try: m['texts'].append((k.decode('latin1'), (zlib.decompress(r) if comp else r).decode('utf-8', 'ignore')))
            except Exception: pass
        elif t == 'eXIf': m['exif'] = b
        p += 12 + n
        if t == 'IEND': m['trail'] = d[p:]; return
def parse_jpeg(d, m):
    p = 2
    while p + 4 <= len(d):
        if d[p] != 0xFF: p += 1; continue
        mk = d[p + 1]
        if mk == 0xFF: p += 1; continue
        if mk in (0xD8, 0x01) or 0xD0 <= mk <= 0xD7: p += 2; continue
        if mk == 0xD9: m['trail'] = d[p + 2:]; return
        n = struct.unpack('>H', d[p + 2:p + 4])[0]; b = d[p + 4:p + 2 + n]; m['segs'].append('FF%02X' % mk)
        if mk == 0xFE: m['texts'].append(('JPEG comment', b.decode('latin1')))
        elif mk == 0xE1:
            if b[:4] == b'Exif': m['exif'] = b
            elif b'xmpmeta' in b or b'xpacket' in b: m['texts'].append(('XMP', b.decode('utf-8', 'ignore')))
        elif mk in (0xC0, 0xC1, 0xC2): m['h'], m['w'] = struct.unpack('>HH', b[1:5])
        if mk == 0xDA: e = d.rfind(b'\xff\xd9'); m['trail'] = d[e + 2:] if e > 0 else b''; return
        p += 2 + n
def load(d):
    t = sniff(d); m = {'type': t, 'texts': [], 'trail': b'', 'exif': b'', 'chunks': [], 'idat': b'', 'w': 0, 'h': 0, 'segs': []}
    try:
        if t == 'PNG': parse_png(d, m)
        elif t == 'JPEG': parse_jpeg(d, m)
        elif t == 'GIF': m['w'], m['h'] = struct.unpack('<HH', d[6:10]); m['trail'] = b'' if d.endswith(b'\x3b') else d[d.rfind(b'\x00\x3b') + 2:] if b'\x00\x3b' in d else b''
        elif t == 'WEBP':
            sz = struct.unpack('<I', d[4:8])[0] + 8; m['trail'] = d[sz:] if sz < len(d) else b''
        elif t == 'BMP':
            sz = struct.unpack('<I', d[2:6])[0]; m['w'], m['h'] = struct.unpack('<ii', d[18:26]); m['h'] = abs(m['h']); m['trail'] = d[sz:] if 0 < sz < len(d) else b''
    except Exception as e: m['err'] = str(e)
    return m
def png_pixels(m):
    bpp = {0: 1, 2: 3, 6: 4}.get(m.get('ct'))
    if not bpp or m.get('bd') != 8 or m.get('il') or not m['idat']: return None
    w, h = m['w'], m['h']; st = w * bpp
    if w * h > 6_000_000: return None
    raw = zlib.decompress(m['idat'])
    if len(raw) < (st + 1) * h: return None
    out = bytearray(); prev = bytearray(st)
    for y in range(h):
        ft = raw[y * (st + 1)]; ln = bytearray(raw[y * (st + 1) + 1:(y + 1) * (st + 1)])
        if ft == 1:
            for i in range(bpp, st): ln[i] = (ln[i] + ln[i - bpp]) & 255
        elif ft == 2:
            for i in range(st): ln[i] = (ln[i] + prev[i]) & 255
        elif ft == 3:
            for i in range(st): ln[i] = (ln[i] + (((ln[i - bpp] if i >= bpp else 0) + prev[i]) >> 1)) & 255
        elif ft == 4:
            for i in range(st):
                a = ln[i - bpp] if i >= bpp else 0; b = prev[i]; c = prev[i - bpp] if i >= bpp else 0; pp = a + b - c
                pa, pb, pc = abs(pp - a), abs(pp - b), abs(pp - c); ln[i] = (ln[i] + (a if pa <= pb and pa <= pc else b if pb <= pc else c)) & 255
        out += ln; prev = ln
    return out, bpp, w
def pixels(d, m):
    try:
        from PIL import Image
        im = Image.open(io.BytesIO(d))
        if im.width * im.height <= 12_000_000: im = im.convert('RGB'); return bytearray(im.tobytes()), 3, im.width
    except Exception: pass
    try:
        if m['type'] == 'PNG': return png_pixels(m)
    except Exception: pass
    return None
def strings(d, n=16):
    return [s for s in (x.decode('ascii') for x in re.findall(rb'[\x20-\x7e]{%d,}' % n, d)) if sum(c.isalnum() or c == ' ' for c in s) / len(s) > 0.6]
SIGS = [(b'PK\x03\x04', 'ZIP / Office / JAR archive'), (b'MZ\x90\x00', 'Windows executable (PE)'), (b'\x7fELF', 'Linux executable (ELF)'), (b'%PDF-', 'PDF document'), (b'Rar!\x1a\x07', 'RAR archive'),
        (b'7z\xbc\xaf\x27\x1c', '7-Zip archive'), (b'#!/bin/', 'Shell script'), (b'<?php', 'PHP code'), (b'SQLite format 3', 'SQLite database'), (b'This program cannot be run in DOS mode', 'Windows executable text')]
STDPNG = {'IHDR', 'PLTE', 'IDAT', 'IEND', 'tRNS', 'gAMA', 'cHRM', 'sRGB', 'iCCP', 'sBIT', 'bKGD', 'hIST', 'pHYs', 'sPLT', 'tIME', 'tEXt', 'zTXt', 'iTXt', 'eXIf', 'acTL', 'fcTL', 'fdAT', 'cICP', 'caBX'}
EXT = {'png': 'PNG', 'jpg': 'JPEG', 'jpeg': 'JPEG', 'gif': 'GIF', 'webp': 'WEBP', 'bmp': 'BMP'}
def preview(b, n=300):
    return ''.join(chr(x) if 32 <= x < 127 else '.' for x in b[:n])
def table_facts(d, m, name):
    return {'title': 'File facts', 'cols': ['Property', 'Value'], 'rows': [['Name', name], ['Detected type', m['type'] or 'UNKNOWN'], ['Size', '%.1f KB' % (len(d) / 1024)], ['Dimensions', '%sx%s' % (m['w'], m['h']) if m['w'] else 'n/a'], ['SHA-256', hashlib.sha256(d).hexdigest()], ['Entropy (bits/byte)', '%.2f' % (entropy(d[:200000].decode('latin1')) if d else 0)]]}

def analyze_photo(d, name):
    m = load(d); t = m['type']; layers = []; hidden = []
    ext = name.rsplit('.', 1)[-1].lower() if '.' in name else ''; S = []
    if not t: S.append((45, 'Not a recognised image format - content may be a disguised file.'))
    else: S.append((0, 'Real format (from file signature): %s' % t))
    if ext in EXT and t and EXT[ext] != t: S.append((45, "File extension '.%s' does not match real content (%s) - extension spoofing." % (ext, t)))
    lay(layers, 'File identity & extension check', S)
    tr = m['trail']; S = []
    if len(tr) > 16:
        sig = [lab for s, lab in SIGS if s in tr]; hidden.append('Data appended after the image end (%d bytes): %s' % (len(tr), preview(tr, 400)))
        S.append((80 if sig else 50, '%d bytes hidden AFTER the end of the image%s.' % (len(tr), (' - contains ' + ', '.join(sig)) if sig else '')))
    else: S.append((0, 'No data appended after the image end.'))
    lay(layers, 'Structure & trailing-data analysis', S)
    S = []; mh = []
    for k, v in m['texts']:
        v = v.strip()
        if v: S.append((0, '%s: %s' % (k, v[:120].replace('\n', ' '))))
        mh += [(k,) + x for x in pattern_hits(v)]
    if m['exif']: S.append((0, 'EXIF block present (%d bytes). Readable text: %s' % (len(m['exif']), '; '.join(strings(m['exif'], 4)[:6]))))
    for k, n, s, r in mh: S.append((r, '%s contains %s: %s' % (k, n, s))); hidden.append('%s -> [%s] %s' % (k, n, s))
    lay(layers, 'Metadata text (EXIF / XMP / PNG text / comments)', S or [(0, 'No text metadata found.')])
    S = []
    for s, lab in SIGS:
        offs = []; p = d.find(s, 8)
        while p != -1 and len(offs) < 3: offs.append(p); p = d.find(s, p + 1)
        if offs: S.append((70, '%s signature at byte offset %s.' % (lab, ', '.join(map(str, offs)))))
    lay(layers, 'Embedded file signatures', S or [(0, 'No embedded executables, archives or scripts.')])
    strs = strings(d); blob = '\n'.join(strs); hits = [h for h in pattern_hits(blob)]
    hs = min(70, sum(r for n, _, r in hits if n != 'URL') + (6 if any(n == 'URL' for n, _, _ in hits) else 0))
    S = [(0, '[%s] %s' % (n, s)) for n, s, _ in hits[:10]]
    if hs: S[0] = (hs, S[0][1])
    lay(layers, 'Script & command patterns in file data', S or [(0, 'No code patterns in readable data.')])
    for n, s, _ in hits:
        if n != 'URL': hidden.append('[%s] %s' % (n, s))
    bl = b64_blobs(blob + '\n' + '\n'.join(v for _, v in m['texts']))
    lay(layers, 'Encoded payloads (Base64)', [(25, 'Base64 decodes to: ' + x[:100]) for _, x in bl] or [(0, 'No encoded payloads.')])
    for s, x in bl: hidden.append('Base64 %s -> %s' % (s, x))
    S = []
    if t in ('PNG', 'BMP', 'GIF', 'WEBP') or (t == 'JPEG' and False):
        px = pixels(d, m)
        if px:
            buf = px[0]; n = min(len(buf), 240000) // 8
            bs = bytes(sum((buf[i * 8 + j] & 1) << (7 - j) for j in range(8)) for i in range(n))
            if len(bs) >= 64 and pr(bs[:200].decode('latin1')) > 0.9 and sum(32 <= x < 127 for x in bs[:200]) > 170:
                msg = re.split(r'[^\x20-\x7e\n\r\t]{3,}', bs.decode('latin1'))[0]; S.append((75, 'LSB steganography: pixel low bits spell readable text: "%s"' % msg[:200])); hidden.append('LSB hidden message: ' + msg[:500])
            else: S.append((0, 'Pixel least-significant bits look random (no hidden LSB text).'))
        else: S.append((0, 'Pixel-level LSB check not available for this file (very large/unsupported).'))
    else: S.append((0, 'LSB check applies to lossless images; lossy JPEG needs specialised tools.'))
    lay(layers, 'LSB pixel steganography', S)
    S = []; odd = [c for c in m['chunks'] if m['type'] == 'PNG' and c.rstrip('(truncated)') not in STDPNG]
    if odd: S.append((20, 'Unusual PNG chunks: ' + ', '.join(sorted(set(odd))[:8])))
    if len(tr) > 16 and entropy(tr[:20000].decode('latin1')) > 7.2: S.append((15, 'Appended data is high-entropy (encrypted or compressed).'))
    if m.get('err'): S.append((10, 'Parser error (possibly malformed/crafted file): ' + m['err']))
    lay(layers, 'Structural anomalies & polyglot indicators', S or [(0, 'File structure looks normal.')])
    score = min(100, sum(l['risk'] for l in layers)); level = 'safe' if score < 20 else 'warn' if score < 50 else 'bad'
    verdict = {'safe': 'Clean - no hidden code found', 'warn': 'Suspicious file', 'bad': 'Dangerous - hidden code detected'}[level]
    rows = [[k, v[:200].replace('\n', ' ')] for k, v in m['texts']]; tabs = [table_facts(d, m, name)]
    if rows: tabs.append({'title': 'Metadata text found', 'cols': ['Field', 'Value'], 'rows': rows})
    if strs: tabs.append({'title': 'Readable text found inside the file (strings)', 'cols': ['#', 'Text'], 'rows': [[i + 1, s[:160]] for i, s in enumerate(strs[:40])]})
    blocks = [{'title': 'Hidden / suspicious content recovered (exact)', 'text': '\n\n'.join(hidden)}] if hidden else []
    summary = 'Analysed %s (%s, %.1f KB) with 8 layers. %s Note: this scanner reads hidden/embedded text, not the visible picture text (no OCR).' % (name, t or 'unknown', len(d) / 1024, 'Hidden content was found - details below.' if hidden else 'No hidden code or payload was found.')
    return finish('Photo Hidden-Code Scan', name, layers, score, verdict, level, summary, tabs, blocks)

AIM = ['stable diffusion', 'sdxl', 'comfyui', 'automatic1111', 'negative prompt', 'cfg scale', 'midjourney', 'dall-e', 'dalle', 'openai', 'firefly', 'leonardo.ai', 'ideogram', 'novelai', 'dreamstudio', 'stability.ai',
      'imagen', 'gemini', 'bing image creator', 'playground ai', 'nightcafe', 'craiyon', 'trainedalgorithmicmedia', 'synthid', 'generated by ai', 'ai generated', 'made with ai', 'flux.1', 'sampler:']
FACE = ['faceapp', 'facetune', 'remini', 'reface', 'faceswap', 'deepfacelab', 'insightface', 'roop', 'faceapp', 'lensa', 'picsart', 'canva']
MAKES = [b'canon', b'nikon', b'sony', b'apple', b'samsung', b'google', b'pixel', b'fujifilm', b'olympus', b'panasonic', b'xiaomi', b'oneplus', b'vivo', b'oppo', b'huawei', b'leica', b'motorola']
def analyze_deepfake(d, name):
    m = load(d); t = m['type']
    if not t: raise UserError('Unsupported file. Please upload a PNG, JPG, WEBP, GIF or BMP image.')
    head = (d[:262144] + d[-65536:]).lower(); layers = []; w, h = m['w'], m['h']
    lay(layers, 'Container & format profile', [(8 if t in ('PNG', 'WEBP') else 0, 'Format %s, %.1f KB.%s' % (t, len(d) / 1024, ' PNG/WEBP is the default output of many AI generators.' if t in ('PNG', 'WEBP') else ''))])
    found = [a for a in AIM if a.encode() in head] + [k for k, _ in m['texts'] if k.lower() in ('parameters', 'prompt', 'workflow')]
    lay(layers, 'AI-generator signatures in metadata', [(95, 'AI generator marker found: ' + ', '.join(sorted(set(found))))] if found else [(0, 'No known generator signatures (prompt, sampler, seed, tool names).')])
    c2 = [x for x in (b'c2pa', b'jumb', b'contentauth') if x in d[:2000000].lower()]
    lay(layers, 'Content Credentials (C2PA provenance)', [(0, 'C2PA / Content Credentials manifest present - provenance data exists; verify it with a C2PA tool.')] if c2 else [(5, 'No C2PA provenance manifest (most images have none, so this is a weak signal).')])
    ex = m['exif'].lower(); mk = [x.decode() for x in MAKES if x in ex]; cam = bool(mk)
    S = [(0, 'Camera EXIF found. Possible make/model strings: ' + ', '.join(mk) + '.')] if cam else [(25 if t == 'JPEG' else 10, 'No camera EXIF (make, model, lens, exposure). Real photos usually carry it; AI images never do.')] if not ex else [(8, 'EXIF exists but shows no camera make.')]
    lay(layers, 'Camera / EXIF authenticity', S)
    S = []
    if w and h:
        s64 = w % 64 == 0 and h % 64 == 0; sq = w == h and w in (512, 768, 1024, 1536, 2048)
        S.append((25 if s64 else 0, '%dx%d - both sides are multiples of 64, typical of diffusion models.' % (w, h) if s64 else '%dx%d - not a typical AI grid size.' % (w, h)))
        if sq: S.append((15, 'Square power-of-two style size (512/768/1024...).'))
    else: S.append((0, 'Dimensions could not be read.'))
    lay(layers, 'Dimension fingerprint', S)
    ed = [x for x in FACE if x.encode() in head]; sw = [x for x in ('photoshop', 'gimp', 'lightroom', 'snapseed', 'adobe') if x.encode() in head]
    S = [(40, 'Face-editing / swap tool name found: ' + ', '.join(sorted(set(ed))))] if ed else []
    if sw: S.append((8, 'Edited with: ' + ', '.join(sw) + ' (editing is not the same as AI generation).'))
    if not m['texts'] and not m['exif']: S.append((10, 'All metadata is stripped (common after AI generation or social-media upload).'))
    lay(layers, 'Editing software & metadata stripping', S or [(0, 'No editing-tool traces.')])
    px = pixels(d, m); S6 = [(0, 'Pixel analysis unavailable for this file (very large, or format needs Pillow).')]; S7 = list(S6); noise = uniq = smooth = None
    if px:
        buf, bpp, pw = px; n = len(buf) // bpp; step = max(1, n // 150000); df = c = sm = 0
        for i in range(0, n - 1, step):
            if (i + 1) % pw == 0: continue
            x = abs(buf[i * bpp] - buf[(i + 1) * bpp]); df += x; c += 1; sm += x <= 1
        noise = df / max(1, c); smooth = sm / max(1, c); cols = {bytes(buf[i * bpp:i * bpp + 3]) for i in range(0, n, max(1, n // 100000))}; uniq = len(cols) / max(1, len(range(0, n, max(1, n // 100000))))
        S6 = [(30 if noise < 1.6 and uniq > 0.4 else 12 if noise < 2.5 and uniq > 0.4 else 0, 'Average neighbour-pixel noise = %.2f. %s' % (noise, 'Unnaturally smooth for a camera photo (no sensor grain).' if noise < 1.6 else 'Noise level within the usual range.'))]
        S7 = [(20 if smooth > 0.6 and uniq > 0.4 else 0, 'Smooth-gradient ratio = %.0f%%, colour variety = %.0f%%.%s' % (smooth * 100, uniq * 100, ' Very smooth yet colour-rich - common in AI renders.' if smooth > 0.6 and uniq > 0.4 else ''))]
    lay(layers, 'Pixel noise residual (sensor grain)', S6); lay(layers, 'Colour & gradient statistics', S7)
    score = sum(l['risk'] for l in layers)
    if found: score = max(score, 92)
    if cam: score -= 25
    score = max(0, min(100, score)); level = 'safe' if score < 35 else 'warn' if score < 70 else 'bad'
    verdict = {'safe': 'No strong AI / deepfake evidence', 'warn': 'Possibly AI-generated or edited', 'bad': 'Likely AI-generated / manipulated'}[level]
    summary = 'AI-likelihood score %d/100 from 8 forensic layers. %s This is a probability estimate: absence of evidence is NOT proof an image is real, and stripped metadata can hide AI origin.' % (score, 'An explicit AI-generator marker was found.' if found else 'No explicit generator marker was found.')
    return finish('DeepFake / AI-Image Forensics', name, layers, score, verdict, level, summary, [table_facts(d, m, name)], [{'title': 'How to read this result', 'text': 'Layers 1-6 inspect the file structure and metadata footprints AI tools leave behind. Layers 7-8 measure pixel statistics (sensor noise, gradients). Strong evidence = generator signature. Weak evidence = smoothness, grid-sized dimensions, missing EXIF. Always cross-check important images with a reverse image search and a human expert.'}])


# ---------------------------------------------------------------- SECRET REVEAL (multi-decoder) + wrappers
import codecs, html as _h
KEYS = re.compile(r'http|pass|flag|secret|key|token|script|select|cmd|eval|login|admin|hack', re.I)
def _cands(s):
    c = []
    for m in re.findall(r'[A-Za-z0-9+/]{16,}={0,2}', s):
        try: c.append(('Base64', base64.b64decode(m + '=' * (-len(m) % 4)).decode('utf-8')))
        except Exception: pass
    for m in re.findall(r'(?:\b[0-9a-fA-F]{2}\b[\s:,-]*){6,}|\b(?:[0-9a-fA-F]{2}){8,}\b', s):
        try: c.append(('Hex', bytes.fromhex(re.sub(r'[^0-9a-fA-F]', '', m)).decode('utf-8')))
        except Exception: pass
    for m in re.findall(r'(?:[01]{8}[\s,]*){4,}', s):
        b = re.sub(r'[^01]', '', m)
        try: c.append(('Binary', bytes(int(b[i:i + 8], 2) for i in range(0, len(b) // 8 * 8, 8)).decode('utf-8')))
        except Exception: pass
    if re.search(r'%[0-9a-fA-F]{2}', s): c.append(('URL-encoding', unquote(s)))
    if re.search(r'\\u[0-9a-fA-F]{4}|\\x[0-9a-fA-F]{2}', s):
        try: c.append(('Escape sequences', s.encode('latin1', 'ignore').decode('unicode_escape')))
        except Exception: pass
    if re.search(r'&#?\w+;', s): c.append(('HTML entities', _h.unescape(s)))
    c.append(('ROT13', codecs.decode(s, 'rot13'))); c.append(('Reversed', s[::-1]))
    return c
def reveal(s, depth=0, seen=None):
    seen = seen if seen is not None else {s}; out = []
    for meth, t in _cands(s[:20000]):
        t = t.strip()
        if len(t) < 4 or t in seen or pr(t) < 0.9: continue
        if meth in ('ROT13', 'Reversed') and (not KEYS.search(t) or KEYS.search(s)): continue
        seen.add(t); out.append((meth, t[:800]))
        if depth < 2: out += [(meth + ' > ' + a, b) for a, b in reveal(t, depth + 1, seen)]
    return out[:12]
def ws_stego(text):
    bits = ''
    for ln in text.split('\n'):
        m = re.search(r'[ \t]+$', ln)
        if m: bits += ''.join('0' if c == ' ' else '1' for c in m.group(0))
    return bits_text(bits) if len(bits) >= 16 else ''
def lsb_all(d, m):
    if m['type'] not in ('PNG', 'BMP', 'GIF', 'WEBP'): return []
    px = pixels(d, m)
    if not px: return []
    buf, bpp, _ = px; out = []
    for cn, sl in (('all channels', slice(0, None)), ('red', slice(0, None, bpp)), ('green', slice(1, None, bpp)), ('blue', slice(2, None, bpp))):
        ch = buf[sl][:160000]
        for order in ('MSB', 'LSB'):
            by = bytes(sum((ch[i * 8 + j] & 1) << ((7 - j) if order == 'MSB' else j) for j in range(8)) for i in range(len(ch) // 8))
            if len(by) >= 40 and sum(32 <= x < 127 for x in by[:200]) / len(by[:200]) > .9:
                out.append(('Pixel LSB (%s, %s-first)' % (cn, order), re.split(rb'[^\x20-\x7e\n\r\t]{3,}', by)[0].decode('latin1')[:1500]))
    return out[:3]
def _block(r, found, stego=False):
    if found: r['blocks'].insert(0, {'title': '🔓 SECRET REVEAL - hidden content decoded', 'text': '\n\n'.join('[%s]\n%s' % (a, b) for a, b in found)})
    if stego:
        r['score'] = max(r['score'], 75); r['level'] = 'bad'; r['verdict'] = 'Dangerous - hidden payload detected'
    r['report'] = make_report(r); return r
_at = analyze_text
def analyze_text(text):
    r = _at(text); found = []; st = False
    zws = [c for c in text if ord(c) in ZW | {0x200B, 0x200C, 0x200D}]; ds = sorted(set(zws))
    if len(zws) >= 8 and len(ds) == 2:
        t = bits_text([str(ds.index(c)) for c in zws])
        if t: found.append(('Zero-width bits (%s=0, %s=1)' % ('U+%04X' % ord(ds[0]), 'U+%04X' % ord(ds[1])), t)); st = True
    w = ws_stego(text)
    if w: found.append(('Trailing-whitespace steganography', w)); st = True
    vis = ''.join(c for c in text if c.isprintable() or c == '\n')
    found += reveal('\n'.join([vis] + [x for b in r['blocks'] for x in b['text'].split('\n') if x]))
    return _block(r, found, st)
_ap = analyze_photo
def analyze_photo(d, name):
    r = _ap(d, name); m = load(d); found = []; tr = m['trail']; parts = [v for _, v in m['texts']] + strings(m['exif'], 6) + strings(d)[:200]
    if len(tr) > 16:
        txt = tr.decode('utf-8', 'ignore'); found.append(('Full appended data (text view)', txt[:1500] if pr(txt) > .6 else preview(tr, 600))); parts.append(txt)
    found += reveal('\n'.join(parts)); l = lsb_all(d, m); found += l
    return _block(r, found, bool(l))
_ad = analyze_deepfake
def analyze_deepfake(d, name):
    r = _ad(d, name); m = load(d)
    ps = [(k, v) for k, v in m['texts'] if k.lower() in ('parameters', 'prompt', 'workflow', 'comment', 'description', 'software', 'xmp') or any(a in v.lower() for a in AIM)]
    return _block(r, [(k, v[:1500]) for k, v in ps])

# ---------------------------------------------------------------- SERVER
def safe_name(raw):
    n = unquote(raw or '').replace('\\', '/').split('/')[-1]
    n = ''.join(c for c in n if c.isprintable()).strip()
    return n[-100:] or 'image'
def parse_json(body, key):
    try: obj = json.loads(body.decode('utf-8'))
    except (ValueError, RecursionError): raise UserError('Invalid JSON request body.')
    if not isinstance(obj, dict) or not isinstance(obj.get(key), str): raise UserError("Invalid request: a text field named '%s' is required." % key)
    return obj[key]
# route -> (kind, JSON key or None, max body bytes)
ROUTES = {'/api/link': ('json', 'url', MAX_LINK_BODY), '/api/emoji': ('json', 'text', MAX_TEXT_BODY),
          '/api/photo': ('file', None, MAX_UPLOAD), '/api/deepfake': ('file', None, MAX_UPLOAD)}

class H(SimpleHTTPRequestHandler):
    server_version = 'CyberGuard'; sys_version = ''; timeout = 60
    def __init__(s, *a, **k): super().__init__(*a, directory=WEB, **k)
    def log_message(s, *a):
        if PUBLIC: super().log_message(*a)          # request lines go to the Render log; local mode stays silent as before
    def end_headers(s):
        s.send_header('X-Content-Type-Options', 'nosniff'); s.send_header('X-Frame-Options', 'SAMEORIGIN'); s.send_header('Referrer-Policy', 'no-referrer')
        s.send_header('Permissions-Policy', 'camera=(), microphone=(), geolocation=(), payment=()')
        if PUBLIC: s.send_header('Strict-Transport-Security', 'max-age=31536000')
        super().end_headers()
    def list_directory(s, path): s.send_error(404, 'Not found'); return None     # no folder listings (e.g. /assets/)
    def _gzip_ok(s): return 'gzip' in (s.headers.get('Accept-Encoding') or '').lower()
    def _json(s, code, obj, head=False):
        out = json.dumps(obj).encode(); enc = False
        if len(out) > 1024 and s._gzip_ok(): out = gzip.compress(out, 6); enc = True        # scan reports shrink ~5x on slow mobile data
        try:
            s.send_response(code); s.send_header('Content-Type', 'application/json; charset=utf-8'); s.send_header('Content-Length', str(len(out))); s.send_header('Cache-Control', 'no-store'); s.send_header('Vary', 'Accept-Encoding')
            if enc: s.send_header('Content-Encoding', 'gzip')
            s.end_headers()
            if not head: s.wfile.write(out)
        except (BrokenPipeError, ConnectionResetError, ConnectionAbortedError, TimeoutError): pass     # visitor already disconnected
    def _path(s): return urlparse(s.path).path
    def _ip(s):
        xf = (s.headers.get('X-Forwarded-For') or '').split(',')[0].strip() if PUBLIC else ''
        return xf or s.client_address[0]
    def _health(s): return {'status': 'ok', 'service': 'CyberGuard AI', 'mode': 'public' if PUBLIC else 'local', 'uptime_s': int(time.time() - STARTED), 'max_upload_mb': MAX_UPLOAD // 1_000_000}
    def _static(s, head=False):
        p = unquote(s._path()); name = os.path.basename(p)
        if p in ('', '/'): p = '/index.html'
        elif '.' not in name and os.path.isfile(os.path.join(WEB, p.strip('/') + '.html')): p = p.rstrip('/') + '.html'     # /link -> link.html
        fs = os.path.realpath(os.path.join(WEB, p.lstrip('/')))
        if not (fs.startswith(WEB_REAL + os.sep) and os.path.isfile(fs)):
            body = b'<!doctype html><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><body style="background:#04060f;color:#e6edf7;font:18px system-ui;text-align:center;padding:12vh 20px"><h1>404</h1><p>This page was not found.</p><p><a style="color:#00e5ff" href="/">Back to CyberGuard AI</a></p>'
            try:
                s.send_response(404); s.send_header('Content-Type', 'text/html; charset=utf-8'); s.send_header('Content-Length', str(len(body))); s.end_headers()
                if not head: s.wfile.write(body)
            except (BrokenPipeError, ConnectionResetError, ConnectionAbortedError, TimeoutError): pass
            return
        st = os.stat(fs); ct = mimetypes.guess_type(fs)[0] or 'application/octet-stream'
        if ct.startswith('text/') or ct in ('application/javascript', 'application/manifest+json'): ct += '; charset=utf-8'
        etag = '"%x-%x"' % (int(st.st_mtime), st.st_size)
        try:
            if s.headers.get('If-None-Match') == etag:
                s.send_response(304); s.send_header('ETag', etag); s.end_headers(); return
            data = None; enc = False
            if st.st_size > 600 and s._gzip_ok() and (ct.startswith('text/') or 'javascript' in ct or 'json' in ct or 'svg' in ct):
                key = (fs, st.st_mtime, st.st_size)
                if key not in _GZ:
                    with open(fs, 'rb') as f: _GZ[key] = gzip.compress(f.read(), 9)
                data, enc = _GZ[key], True
            s.send_response(200); s.send_header('Content-Type', ct); s.send_header('ETag', etag); s.send_header('Vary', 'Accept-Encoding')
            s.send_header('Cache-Control', 'public, max-age=604800' if '/assets/' in p or ct.startswith(('image/', 'font/')) else 'no-cache')   # images cached 7 days, code always revalidated
            if enc: s.send_header('Content-Encoding', 'gzip')
            s.send_header('Content-Length', str(len(data) if data is not None else st.st_size)); s.end_headers()
            if head: return
            if data is not None: s.wfile.write(data)
            else:
                with open(fs, 'rb') as f:
                    while True:
                        c = f.read(65536)
                        if not c: break
                        s.wfile.write(c)
        except (BrokenPipeError, ConnectionResetError, ConnectionAbortedError, TimeoutError): pass
    def do_GET(s):
        p = s._path()
        if p == '/health': return s._json(200, s._health())
        if p.startswith('/api/'): return s._json(405, {'error': 'Use POST for this endpoint.'})
        s._static()
    def do_HEAD(s):
        p = s._path()
        if p == '/health': return s._json(200, s._health(), head=True)
        if p.startswith('/api/'): return s._json(405, {'error': 'Use POST for this endpoint.'}, head=True)
        s._static(head=True)
    def _drain(s, n):                                  # read (and discard) an oversized upload so the browser can receive our JSON error
        left = min(n, 4 * MAX_UPLOAD)
        try:
            while left > 0:
                c = s.rfile.read(min(65536, left))
                if not c: break
                left -= len(c)
        except Exception: pass
    def do_POST(s):
        try:
            spec = ROUTES.get(s._path())
            if not spec: return s._json(404, {'error': 'Unknown endpoint.'})
            kind, key, limit = spec
            if not rate_ok(s._ip()): return s._json(429, {'error': 'Too many scans from your network. Please wait a minute and try again.'})
            if s.headers.get('Transfer-Encoding'): return s._json(411, {'error': 'Content-Length is required.'})
            cl = (s.headers.get('Content-Length') or '').strip()
            if not re.fullmatch(r'[0-9]{1,12}', cl): return s._json(411, {'error': 'Content-Length is required.'})
            n = int(cl)
            if n > limit:
                s._drain(n)
                return s._json(413, {'error': ('File too large (maximum %d MB).' % (limit // 1_000_000)) if kind == 'file' else 'Request too large.'})
            if n == 0: return s._json(400, {'error': 'Empty request body.'})
            body = s.rfile.read(n)
            if len(body) != n: return s._json(400, {'error': 'Incomplete request body.'})
            if kind == 'json':
                val = parse_json(body, key)
                if s._path() == '/api/emoji' and MAX_TEXT_CHARS and len(val) > MAX_TEXT_CHARS: raise UserError('Text is too long for the public scanner (maximum %d characters).' % MAX_TEXT_CHARS)
                fn, args = (analyze_link if key == 'url' else analyze_text), (val,)
            else:
                fn, args = (analyze_photo if s._path() == '/api/photo' else analyze_deepfake), (body, safe_name(s.headers.get('X-Filename', 'image')))
            if not SCAN_SLOTS.acquire(timeout=20): return s._json(503, {'error': 'The server is busy right now. Please try again in a moment.'})
            try: res = fn(*args)
            finally: SCAN_SLOTS.release()
            return s._json(200, res)
        except UserError as e: return s._json(400, {'error': str(e)})
        except TimeoutError: return s._json(408, {'error': 'The upload took too long. Please try again.'})
        except Exception as e:
            traceback.print_exc()                      # full details only in the server log, never to the visitor
            if PUBLIC: return s._json(500, {'error': 'The scan could not be completed because of an internal error. Please try a different input.'})
            return s._json(400, {'error': str(e)})

class PublicServer(ThreadingHTTPServer):
    request_queue_size = 64; daemon_threads = True

def run_public():
    raw = (os.environ.get('PORT') or '10000').strip()          # Render injects PORT (default 10000)
    try:
        port = int(raw)
        if not 0 < port < 65536: raise ValueError
    except ValueError: sys.exit('Invalid PORT value: %r' % raw)
    srv = PublicServer(('0.0.0.0', port), H)                   # 0.0.0.0 so Render's proxy can reach us; exact port, no searching
    def stop(signum, frame): threading.Thread(target=srv.shutdown, daemon=True).start()
    for sig in (signal.SIGTERM, signal.SIGINT): signal.signal(sig, stop)
    print('CyberGuard AI (public mode) listening on 0.0.0.0:%d' % port, flush=True)
    try: srv.serve_forever()
    finally: srv.server_close(); print('CyberGuard AI stopped.', flush=True)

def run_local():                                               # unchanged local Windows behaviour (run.bat)
    srv = None
    for port in range(8000, 8011):
        try: srv = ThreadingHTTPServer(('127.0.0.1', port), H); break
        except OSError: continue
    if not srv: sys.exit('No free port between 8000-8010.')
    url = 'http://localhost:%d' % port
    print('=' * 64 + '\n  CyberGuard AI is running at ' + url + '\n  Keep this window open. Press Ctrl+C or close it to stop.\n' + '=' * 64)
    threading.Timer(1.2, lambda: webbrowser.open(url)).start()
    try: srv.serve_forever()
    except KeyboardInterrupt: pass

if __name__ == '__main__':
    run_public() if PUBLIC else run_local()
