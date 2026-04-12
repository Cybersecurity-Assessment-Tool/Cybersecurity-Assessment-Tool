"""
Server-side network scanner.

Runs three scans against the organization's configured targets:
  - Port scan      → org.external_ip
  - Email scan     → org.email_domain
  - Infra scan     → org.website_domain (falls back to email_domain)

Entry point for Django-Q2: run_network_scan(scan_id)
"""

from ast import Lambda
import json
import re
import ssl
import socket
import logging
from datetime import datetime, timezone as dt_timezone

import requests
from django.utils import timezone
from django.conf import settings
from django.core.cache import cache
from django.urls import reverse

logger = logging.getLogger(__name__)

# ── Configuration ────────────────────────────────────────────────────────────
# Yes the ports are AI generated - but let's be real this is a great use of AI instead of my time

TCP_PORT_SERVICES = {
    # ── Core services ────────────────────────────────────────────────────────
    21:    'ftp',
    22:    'ssh',
    23:    'telnet',
    25:    'smtp',
    53:    'dns',
    80:    'http',
    110:   'pop3',
    115:   'sftp',
    135:   'msrpc',
    139:   'netbios-ssn',
    143:   'imap',
    194:   'irc',
    443:   'https',
    445:   'microsoft-ds',
    465:   'smtps',
    587:   'smtp-submission',
    993:   'imaps',
    995:   'pop3s',
    # ── Remote access — commonly left open by a non-IT "helper" ─────────────
    1723:  'pptp',            # PPTP VPN — weak encryption, often set up and forgotten
    3389:  'rdp',
    4899:  'radmin',          # Radmin remote admin — obscure but still deployed in schools/SMBs
    5800:  'vnc-http',        # VNC browser console — companion to 5900, often missed
    5900:  'vnc',
    5938:  'teamviewer',      # TeamViewer — installed for one support call, never removed
    5632:  'pcanywherestat',
    # ── Databases — frequently opened for "easy access" and never locked down ─
    1433:  'mssql',
    3306:  'mysql',
    5432:  'postgresql',
    6379:  'redis',           # Redis has no auth by default on older versions
    27017: 'mongodb',         # MongoDB had no auth by default until v3.6; many installs still don't
    # ── Container / server management — full system access if exposed ─────────
    2375:  'docker',          # Docker daemon unencrypted — complete host takeover
    2376:  'docker-tls',      # Docker daemon TLS — still shouldn't be internet-facing
    9000:  'portainer',       # Portainer Docker UI — web-based full container management
    10000: 'webmin',          # Webmin — full Linux server admin panel, often default creds
    # ── Alt web / dev servers — "I just need it running" ─────────────────────
    3000:  'http-dev',        # Node.js / React / Grafana default — dev server left running
    8000:  'http-alt',
    8080:  'http-proxy',
    8443:  'https-alt',
    8888:  'jupyter',         # Jupyter Notebook — unauthenticated = remote code execution
    8096:  'emby',            # Emby / Jellyfin media server
    # ── Media & file servers — NAS boxes set up once and never audited ────────
    111:   'rpcbind',         # RPC portmapper — prerequisite for NFS enumeration
    548:   'afp',             # Apple Filing Protocol — older Macs, Time Machine servers
    554:   'rtsp',            # RTSP — IP cameras / surveillance systems
    2049:  'nfs',             # NFS — network file shares, often world-readable
    32400: 'plex',            # Plex Media Server — frequently port-forwarded for remote access
    # ── Printers & IoT ───────────────────────────────────────────────────────
    631:   'ipp',             # IPP — CUPS print server
    1883:  'mqtt',            # MQTT — unencrypted IoT messaging broker
    9100:  'jetdirect',       # HP JetDirect raw printing — can receive/exfiltrate print jobs
    # ── Game servers — unsanctioned installs by students / younger staff ──────
    7777:  'game-server',     # Terraria, ARK, Unreal-based games
    25565: 'minecraft',       # Minecraft Java Edition
    27015: 'steam',           # Steam / Source engine games (CS:GO, TF2, GMod)
}

UDP_PORT_SERVICES = {
    53:   'dns',           # Open resolver / zone transfer risk
    69:   'tftp',          # Unauthenticated file transfer
    123:  'ntp',           # Amplification attack vector
    137:  'netbios-ns',    # Windows name resolution exposure
    161:  'snmp',          # Default community strings — high value target
    500:  'isakmp',        # VPN endpoint (IKE)
    1194: 'openvpn',       # VPN endpoint
    4500: 'ipsec-nat-t',   # VPN endpoint (IPSec NAT traversal)
}

# Findings generated for each open port (severity, description)
TCP_PORT_FINDINGS = {
    # ── Critical — direct path to full system or data compromise ─────────────
    23:    ('CRITICAL', 'Telnet port 23 open — unencrypted remote access, credentials sent in plaintext'),
    2375:  ('CRITICAL', 'Docker daemon port 2375 open — unencrypted, allows full container and host takeover'),
    6379:  ('CRITICAL', 'Redis port 6379 open — older Redis installs have no authentication by default'),
    27017: ('CRITICAL', 'MongoDB port 27017 open — many installs lack authentication, full database exposed'),
    # ── High — significant exposure, likely exploitable ───────────────────────
    3389:  ('HIGH',     'RDP port 3389 open — remote desktop exposed, common brute-force target'),
    5900:  ('HIGH',     'VNC port 5900 open — remote desktop exposed, often weak or no password'),
    5800:  ('HIGH',     'VNC HTTP console port 5800 open — browser-accessible remote desktop'),
    3306:  ('HIGH',     'MySQL port 3306 open — database port exposed to internet'),
    1433:  ('HIGH',     'MSSQL port 1433 open — database port exposed to internet'),
    5432:  ('HIGH',     'PostgreSQL port 5432 open — database port exposed to internet'),
    445:   ('HIGH',     'SMB port 445 open — Windows file sharing exposed to internet'),
    139:   ('HIGH',     'NetBIOS port 139 open — Windows sharing exposed to internet'),
    135:   ('HIGH',     'MSRPC port 135 open — Windows RPC exposed to internet'),
    4899:  ('HIGH',     'Radmin port 4899 open — remote admin tool, often installed and forgotten'),
    9000:  ('HIGH',     'Portainer port 9000 open — web UI for Docker management exposed to internet'),
    10000: ('HIGH',     'Webmin port 10000 open — full server admin panel exposed, common default credentials'),
    2049:  ('HIGH',     'NFS port 2049 open — network file share, often world-readable without auth'),
    8888:  ('HIGH',     'Jupyter Notebook port 8888 open — unauthenticated access allows arbitrary code execution'),
    1883:  ('HIGH',     'MQTT port 1883 open — unencrypted IoT broker, may expose device control or sensor data'),
    2376:  ('HIGH',     'Docker TLS port 2376 open — Docker daemon should not be internet-facing'),
    # ── Medium — notable risk, should be investigated ─────────────────────────
    21:    ('MEDIUM',   'FTP port 21 open — unencrypted file transfer, credentials sent in plaintext'),
    5632:  ('MEDIUM',   'PCAnywhere port 5632 open — legacy remote access tool, no longer patched'),
    1723:  ('MEDIUM',   'PPTP VPN port 1723 open — PPTP encryption is broken, should be replaced'),
    5938:  ('MEDIUM',   'TeamViewer port 5938 open — remote access tool, verify it is intentional and secured'),
    554:   ('MEDIUM',   'RTSP port 554 open — IP camera or media stream exposed, check for unauthenticated feeds'),
    9100:  ('MEDIUM',   'JetDirect port 9100 open — raw printer access, can receive unsolicited jobs or leak documents'),
    111:   ('MEDIUM',   'RPCbind port 111 open — allows enumeration of NFS and RPC services'),
    32400: ('MEDIUM',   'Plex port 32400 open — media server, ensure authentication is enabled'),
    8096:  ('MEDIUM',   'Emby/Jellyfin port 8096 open — media server, ensure authentication is enabled'),
    3000:  ('MEDIUM',   'Port 3000 open — commonly a Node.js, React, or Grafana dev server left running'),
    8080:  ('MEDIUM',   'HTTP alt port 8080 open — unencrypted web service, verify what is running'),
    8000:  ('MEDIUM',   'HTTP alt port 8000 open — unencrypted web service, verify what is running'),
    8443:  ('MEDIUM',   'HTTPS alt port 8443 open — verify what service is running and that certs are valid'),
    548:   ('MEDIUM',   'AFP port 548 open — Apple file sharing exposed, older protocol with known weaknesses'),
    25565: ('MEDIUM',   'Minecraft server port 25565 open — game server on network, likely unsanctioned'),
    27015: ('MEDIUM',   'Steam/Source engine port 27015 open — game server on network, likely unsanctioned'),
    7777:  ('MEDIUM',   'Game server port 7777 open — likely Terraria, ARK, or similar, unsanctioned game server'),
    # ── Low — informational with minor concern ────────────────────────────────
    110:   ('LOW',      'POP3 port 110 open — unencrypted, consider enforcing TLS (port 995)'),
    143:   ('LOW',      'IMAP port 143 open — unencrypted, consider enforcing TLS (port 993)'),
    631:   ('LOW',      'IPP port 631 open — printer accessible over network, verify access controls'),
    # ── Info — expected or low-noise ─────────────────────────────────────────
    22:    ('INFO',     'SSH port 22 open'),
    25:    ('INFO',     'SMTP port 25 open'),
    53:    ('INFO',     'DNS port 53/tcp open — typically used for zone transfers'),
    80:    ('INFO',     'HTTP port 80 open'),
    443:   ('INFO',     'HTTPS port 443 open'),
    115:   ('INFO',     'SFTP port 115 open'),
    194:   ('INFO',     'IRC port 194 open'),
    465:   ('INFO',     'SMTPS port 465 open'),
    587:   ('INFO',     'SMTP submission port 587 open'),
    993:   ('INFO',     'IMAPS port 993 open'),
    995:   ('INFO',     'POP3S port 995 open'),
}

# Additional critical CVE advisories emitted alongside the normal port finding.
# Ports listed here will produce TWO findings: the standard info/severity entry
# from TCP_PORT_FINDINGS, plus this critical warning.
# These are critical vulnerabilities that Ian could find hard yes/no evidence of issues
# - here we can only warn (formerly group 10)
TCP_PORT_CVE_WARNINGS = {
    80:  ('CRITICAL', 'CVE-2014-6271 (Shellshock) — port 80 open; verify web server and CGI scripts are patched against Shellshock'),
    443: ('CRITICAL', 'CVE-2014-0160 (Heartbleed) / CVE-2014-6271 (Shellshock) — port 443 open; verify OpenSSL and CGI scripts are patched'),
    445: ('CRITICAL', 'CVE-2017-0144 (EternalBlue / MS17-010) — port 445 open; unpatched Windows hosts can be fully compromised remotely via SMB'),
}

UDP_PORT_FINDINGS = {
    137:  ('HIGH',     'NetBIOS Name Service port 137 open — Windows name resolution exposed'),
    161:  ('HIGH',     'SNMP port 161 open — may expose device info via default community strings'),
    53:   ('MEDIUM',   'DNS port 53/udp open — potential open resolver, DDoS amplification risk'),
    69:   ('MEDIUM',   'TFTP port 69 open — unauthenticated file transfer, no encryption'),
    123:  ('MEDIUM',   'NTP port 123 open — potential DDoS amplification vector'),
    500:  ('INFO',     'ISAKMP/IKE port 500 open — VPN negotiation endpoint'),
    1194: ('INFO',     'OpenVPN port 1194 open'),
    4500: ('INFO',     'IPSec NAT-T port 4500 open'),
}

SEVERITY_ORDER = {'CRITICAL': 0, 'HIGH': 1, 'MEDIUM': 2, 'LOW': 3, 'INFO': 4}

DKIM_SELECTORS = [
    'default', 'google', 'mail', 'dkim', 'k1',
    'selector1', 'selector2', 'smtp', 'email',
]

SECURITY_HEADERS = [
    'Strict-Transport-Security',
    'Content-Security-Policy',
    'X-Frame-Options',
    'X-Content-Type-Options',
    'X-XSS-Protection',
    'Referrer-Policy',
    'Permissions-Policy',
]

PROBE_PATHS = [
    '/robots.txt', '/sitemap.xml', '/.well-known/security.txt',
    '/.env', '/.env.local', '/.env.backup',
    '/.git/HEAD', '/.git/config',
    '/admin', '/admin/login', '/login', '/dashboard',
    '/wp-admin/', '/wp-login.php', '/phpmyadmin/',
    '/backup/', '/backup.zip', '/backup.sql',
    '/config.php', '/web.config', '/.htaccess',
    '/crossdomain.xml', '/xmlrpc.php',
]

WAF_CDN_SIGNATURES = {
    'Cloudflare':  lambda h: 'CF-Ray' in h or h.get('Server', '').lower() == 'cloudflare',
    'CloudFront':  lambda h: 'X-Amz-Cf-Id' in h or 'CloudFront' in h.get('Via', ''),
    'Akamai':      lambda h: any(k.lower().startswith('x-akamai') for k in h),
    'Sucuri':      lambda h: 'X-Sucuri-ID' in h or 'X-Sucuri-Cache' in h,
    'Fastly':      lambda h: 'X-Served-By' in h and 'Fastly' in h.get('Via', ''),
    'Imperva':     lambda h: 'X-Iinfo' in h or h.get('X-CDN', '') == 'Imperva',
    'Varnish':     lambda h: 'X-Varnish' in h or 'varnish' in h.get('Via', '').lower(),
    'Nginx':       lambda h: 'nginx' in h.get('Server', '').lower(),
    'Apache':      lambda h: 'apache' in h.get('Server', '').lower(),
}

SUBDOMAINS_TO_PROBE = [
    'www', 'mail', 'webmail', 'remote', 'vpn', 'portal', 'admin',
    'ftp', 'smtp', 'pop', 'imap', 'mx', 'mx1', 'mx2',
    'ns1', 'ns2', 'dns', 'dns1', 'dns2',
    'student', 'staff', 'faculty', 'library', 'calendar',
    'learning', 'canvas', 'schoology', 'powerschool', 'sis',
    'helpdesk', 'support', 'it', 'intranet', 'internal',
    'board', 'superintendent', 'athletics', 'lunch', 'finance',
    'dev', 'staging', 'test', 'backup', 'old',
]


# ── DNS helpers ──────────────────────────────────────────────────────────────

def _make_resolver():
    import dns.resolver
    r = dns.resolver.Resolver()
    r.timeout = 5
    r.lifetime = 10
    return r


def _resolve_safe(resolver, name, rtype):
    try:
        return resolver.resolve(name, rtype)
    except Exception:
        return []


def _add_metadata(scan_type, scan_start_ts, **extras):
    scan_end_ts = datetime.now(dt_timezone.utc)
    return {
        'scan_type': scan_type,
        'scan_start': scan_start_ts.isoformat(),
        'scan_end': scan_end_ts.isoformat(),
        'scan_duration': round((scan_end_ts - scan_start_ts).total_seconds(), 2),
        **extras,
    }


# ── Banner grabbing ──────────────────────────────────────────────────────────

def _grab_banner(sock, port):
    scripts = []
    try:
        if port in (80, 443, 8080):
            sock.sendall(b'HEAD / HTTP/1.0\r\nHost: target\r\n\r\n')
        elif port not in (21, 22, 23, 25, 110, 143):
            sock.sendall(b'\r\n')
        sock.settimeout(2)
        data = sock.recv(2048)
        banner = data.decode('utf-8', errors='ignore').strip()
        if not banner:
            return scripts
        lines = banner.splitlines()
        first_line = lines[0] if lines else ''
        if port in (80, 443):
            scripts.append({'id': 'http-headers', 'output': banner[:300]})
            for line in lines:
                if line.lower().startswith('server:'):
                    scripts.append({'id': 'http-server', 'output': line.split(':', 1)[1].strip()})
        elif port == 22:
            scripts.append({'id': 'ssh-banner', 'output': first_line})
        elif port == 21:
            scripts.append({'id': 'ftp-banner', 'output': first_line})
        elif port == 25:
            scripts.append({'id': 'smtp-banner', 'output': first_line})
        elif port == 3306:
            scripts.append({'id': 'mysql-banner', 'output': first_line})
        else:
            scripts.append({'id': 'banner', 'output': first_line[:200]})
    except Exception:
        pass
    return scripts


# ── Email security helpers ────────────────────────────────────────────────────

def _check_spf(txt_records, findings):
    spf_records = [r for r in txt_records if r.startswith('v=spf1')]
    if not spf_records:
        findings.append({
            'severity': 'HIGH', 
            'scan_type': 'email',
            'category': 'spf',
            'description': 'No SPF record — domain vulnerable to email spoofing'
        })
        return {
            'found': False, 
            'issue': 'No SPF record', 
            'record': [],
            'enforcement': ''
		}
    if len(spf_records) > 1:
        findings.append({
            'severity': 'HIGH', 
            'scan_type': 'email',
            'category': 'spf',
        	'description': 'Multiple SPF records — invalid per RFC 7208'
        })
        return {
            'found': True, 
            'issue': 'Multiple SPF records', 
            'record': spf_records,
			'enforcement': 'multiple'
		}
    spf = spf_records[0]
    info = {'found': True, 'record': spf, 'enforcement': ''}
    if '+all' in spf:
        info['enforcement'] = '+all (none)'
        findings.append({
            'severity': 'CRITICAL', 
            'scan_type': 'email',
            'category': 'spf',
            'description': 'SPF uses "+all" — any server can send mail as this domain'
        })
    elif '~all' in spf:
        info['enforcement'] = '~all (softfail)'
        findings.append({
            'severity': 'LOW', 
            'scan_type': 'email',
            'category': 'spf',
            'description': 'SPF uses "~all" (softfail) — consider upgrading to "-all"'
        })
        info['issue'] = 'SPF uses "~all" (softfail) — consider upgrading to "-all"'
    elif '-all' in spf:
        info['enforcement'] = '-all (fail)'
    elif '?all' in spf:
        info['enforcement'] = '?all (neutral)'
        findings.append({
            'severity': 'MEDIUM', 
            'scan_type': 'email',
            'category': 'spf',
            'description': 'SPF uses "?all" (neutral) — provides no protection'
        })
    return info


def _check_dmarc(target, resolver, findings):
    answers = _resolve_safe(resolver, f'_dmarc.{target}', 'TXT')
    raw = [r.to_text().strip('"') for r in answers]
    if not raw:
        findings.append({
            'severity': 'HIGH', 
            'scan_type': 'email',
            'category': 'dmarc',
            'description': f'No DMARC record at _dmarc.{target}'
        })
        return {'found': False, 'record': '', 'parsed': {}, 'policy': 'none'}
    dmarc_str = raw[0]
    tags = {}
    for part in dmarc_str.split(';'):
        part = part.strip()
        if '=' in part:
            k, v = part.split('=', 1)
            tags[k.strip()] = v.strip()
    policy = tags.get('p', 'none')
    info = {'found': True, 'record': dmarc_str, 'parsed': tags, 'policy': policy}
    if policy == 'none':
        findings.append({
            'severity': 'MEDIUM', 
            'scan_type': 'email',
            'category': 'dmarc',
            'description': 'DMARC policy is "none" — unauthenticated email is delivered without action'
		})
    elif policy == 'quarantine':
        findings.append({
            'severity': 'LOW', 
            'scan_type': 'email',
            'category': 'dmarc',
        	'description': 'DMARC policy is "quarantine" — consider upgrading to "reject"'
        })
    if not tags.get('rua'):
        findings.append({
            'severity': 'LOW', 
            'scan_type': 'email',
            'category': 'dmarc',
            'description': 'DMARC has no "rua" reporting address — failures go unmonitored'
		})
    return info


def _check_dkim(target, resolver, findings):
    found = []
    for sel in DKIM_SELECTORS:
        answers = _resolve_safe(resolver, f'{sel}._domainkey.{target}', 'TXT')
        if answers:
            found.append({'selector': sel, 'record': answers[0].to_text().strip('"')[:120]})
    if not found:
        findings.append({
            'severity': 'MEDIUM', 
            'scan_type': 'email',
            'category': 'dkim',
            'description': 'No DKIM selectors found — emails cannot be cryptographically verified'
		})
    return {'selectors_probed': DKIM_SELECTORS, 'found': found}


def _check_mta_sts(target, resolver, findings):
    result = {}
    answers = _resolve_safe(resolver, f'_mta-sts.{target}', 'TXT')
    if answers:
        result['dns_record'] = answers[0].to_text().strip('"')
        result['found'] = True
    else:
        result['found'] = False
        findings.append({
            'severity': 'LOW', 
            'scan_type': 'email',
            'category': 'mta-sts',
            'description': 'No MTA-STS DNS record — inbound email TLS not enforced'
        })
    try:
        r = requests.get(f'https://mta-sts.{target}/.well-known/mta-sts.txt', timeout=5)
        if r.status_code == 200:
            result['policy'] = r.text[:500]
            if 'mode: enforce' in r.text:
                result['mode'] = 'enforce'
            elif 'mode: testing' in r.text:
                result['mode'] = 'testing'
                findings.append({
                    'severity': 'LOW', 
                    'scan_type': 'email',
                    'category': 'mta-sts',
                    'description': 'MTA-STS policy is in "testing" mode — not yet enforcing'
				})
            elif 'mode: none' in r.text:
                result['mode'] = 'none'
                findings.append({
                    'severity': 'MEDIUM', 
                    'scan_type': 'email',
                    'category': 'mta-sts',
                    'description': 'MTA-STS policy mode is "none" — provides no protection'})
        else:
            result['policy_fetch_status'] = r.status_code
    except Exception:
        result['policy_reachable'] = False
    return result


def _check_dnssec(target, resolver, findings):
    result = {}
    answers = _resolve_safe(resolver, target, 'DNSKEY')
    result['dnskey_found'] = bool(answers)
    if answers:
        result['key_count'] = len(list(answers))
    else:
        findings.append({
            'severity': 'MEDIUM', 
            'scan_type': 'email/infra',
            'category': 'dnssec',
            'description': 'No DNSKEY record — DNSSEC does not appear to be enabled'
        })
    ds = _resolve_safe(resolver, target, 'DS')
    result['ds_found'] = bool(ds)
    return result


def _attempt_zone_transfer(target, ns_records, findings):
    import dns.query
    import dns.zone

    result = {'attempted': [], 'vulnerable': []}
    for ns in ns_records[:4]:
        ns_clean = ns.rstrip('.')
        try:
            ns_ip = socket.gethostbyname(ns_clean)
            try:
                zone = dns.zone.from_xfr(dns.query.xfr(ns_ip, target, timeout=5))
                names = [str(n) for n in zone.nodes.keys()]
                result['vulnerable'].append({
                    'ns': ns_clean, 'records_exposed': len(names), 'sample': names[:10],
                })
                findings.append({
                    'severity': 'CRITICAL', 
                    'scan_type': 'email',
                    'category': 'zone transfer',
                    'description': f'Zone transfer (AXFR) succeeded on {ns_clean} — entire DNS zone exposed'
                })
            except Exception:
                result['attempted'].append({'ns': ns_clean, 'result': 'refused'})
        except Exception as e:
            result['attempted'].append({'ns': ns_clean, 'result': f'error: {str(e)[:60]}'})
    return result


# ── Infra helpers ────────────────────────────────────────────────────────────

def _check_tls(hostname, findings):
    result = {}
    try:
        # Open the TLS connection and grab initial metadata
        ctx = ssl.create_default_context()
        with ctx.wrap_socket(socket.socket(socket.AF_INET), server_hostname=hostname) as s:
            s.settimeout(10)
            s.connect((hostname, 443))
            cert = s.getpeercert()
            cipher = s.cipher()
            protocol = s.version()

		# Extract more metadata
        not_after = cert.get('notAfter', '')
        expiry = datetime.strptime(not_after, '%b %d %H:%M:%S %Y %Z').replace(tzinfo=dt_timezone.utc)
        days_left = (expiry - datetime.now(dt_timezone.utc)).days
        sans = [v for _, v in cert.get('subjectAltName', [])]

        result = {
            'valid': True,
            'subject': dict(x[0] for x in cert.get('subject', [])),
            'issuer': dict(x[0] for x in cert.get('issuer', [])),
            'not_before': cert.get('notBefore'),
            'not_after': not_after,
            'days_until_expiry': days_left,
            'subject_alt_names': sans,
            'negotiated_protocol': protocol,
            'cipher_suite': cipher[0] if cipher else None,
            'cipher_bits': cipher[2] if cipher else None,
        }

		# Warn about certificates expiring soon
        if days_left < 14:
            findings.append({
                'severity': 'CRITICAL', 
                'scan_type': 'infra',
                'category': 'tls',
                'information': f'TLS certificate expires in {days_left} days'
            })
        elif days_left < 30:
            findings.append({
                'severity': 'HIGH', 
				'scan_type': 'infra',
                'category': 'tls',
                'information': f'TLS certificate expires in {days_left} days'
            })

		# Probe for weak TLS protocol versions
        for label, min_ver in [('TLS 1.0', ssl.TLSVersion.TLSv1), ('TLS 1.1', ssl.TLSVersion.TLSv1_1)]:
            try:
                wctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
                wctx.check_hostname = False
                wctx.verify_mode = ssl.CERT_NONE
                wctx.minimum_version = min_ver
                wctx.maximum_version = min_ver
                with wctx.wrap_socket(socket.socket()) as ws:
                    ws.settimeout(5)
                    ws.connect((hostname, 443))
                result.setdefault('weak_protocols_accepted', []).append(label)
                findings.append({
                    'severity': 'HIGH', 
                    'scan_type': 'infra',
                    'category': 'tls',
                    'information': f'Server accepts deprecated {label}'
				})
            except Exception:
                pass
	# Error handle
    except ssl.SSLCertVerificationError as e:
        result = {'valid': False, 'error': str(e)[:200]}
        findings.append({
            'severity': 'CRITICAL', 
            'scan_type': 'infra',
            'category': 'tls',
            'information': f'TLS certificate validation failed: {str(e)[:120]}'
        })
    except Exception as e:
        result = {'error': str(e)[:200]}

    return result


def _check_http(hostname, session, findings):
    http_result = {}
    for scheme in ['https', 'http']:
        try:
            resp = session.head(f'{scheme}://{hostname}', timeout=10, allow_redirects=True,
                                headers={'User-Agent': 'SimpleScan/1.0'})
            all_headers = dict(resp.headers)
            redirect_chain = [{'url': r.url, 'status_code': r.status_code} for r in resp.history]

            present, missing = {}, []
            for h in SECURITY_HEADERS:
                val = resp.headers.get(h)
                if val:
                    present[h] = val
                else:
                    missing.append(h)
                    findings.append({
                        'severity': 'MEDIUM', 
                        'scan_type': 'infra',
                        'category': 'http',
                        'finding': f'Missing security header: {h}'
					})

            server    = resp.headers.get('Server', '')
            x_powered = resp.headers.get('X-Powered-By', '')
            x_aspnet  = resp.headers.get('X-AspNet-Version', '')

            if server and re.search(r'\d+\.\d+', server):
                findings.append({
                    'severity': 'LOW', 
                    'scan_type': 'infra',
                    'category': 'http',
                    'finding': f'Server header discloses version: {server}'
				})
            if x_powered:
                findings.append({
                    'severity': 'LOW', 
                    'scan_type': 'infra',
                    'category': 'http',
                    'finding': f'X-Powered-By discloses technology: {x_powered}'
				})
            if x_aspnet:
                findings.append({
                    'severity': 'LOW', 
                    'scan_type': 'infra',
                    'category': 'http',
                    'finding': f'X-AspNet-Version discloses framework version: {x_aspnet}'
				})

            if scheme == 'http':
                went_https = any(r.url.startswith('https') for r in resp.history)
                if not went_https and not resp.url.startswith('https'):
                    findings.append({
                        'severity': 'HIGH', 
                        'scan_type': 'infra',
                        'category': 'http',
                        'finding': 'Site does not redirect HTTP to HTTPS'
					})

            hsts = resp.headers.get('Strict-Transport-Security', '')
            if hsts:
                if 'preload' not in hsts.lower():
                    findings.append({
                        'severity': 'LOW', 
                        'scan_type': 'infra',
                        'category': 'http',
                        'finding': 'HSTS missing "preload" directive'
					})
                if 'includeSubDomains' not in hsts:
                    findings.append({
                        'severity': 'LOW', 
                        'scan_type': 'infra',
                        'category': 'http',
                        'finding': 'HSTS missing "includeSubDomains" directive'
					})

            base_url = f'{scheme}://{hostname}'
            http_result = {
                'final_url': resp.url,
                'status_code': resp.status_code,
                'redirect_chain': redirect_chain,
                'security_headers': {'present': present, 'missing': missing},
                'server_info': {
                    'server': server or None,
                    'x_powered_by': x_powered or None,
                    'x_aspnet_version': x_aspnet or None,
                },
                'waf_cdn_detected': _detect_waf_cdn(all_headers),
                'http_methods': _check_http_methods(base_url, session, findings),
                'path_probe': _probe_paths(base_url, session, findings),
            }
            break
        except requests.exceptions.SSLError as e:
            findings.append({
                'severity': 'HIGH', 
                'scan_type': 'infra',
                'category': 'http',
                'finding': f'SSL error on {scheme}: {str(e)[:120]}'
			})
        except Exception as e:
            http_result[f'{scheme}_error'] = str(e)[:120]
    return http_result


def _check_dns(target_domain, resolver, findings):
    a_records    = [r.address for r in _resolve_safe(resolver, target_domain, 'A')]
    aaaa_records = [r.address for r in _resolve_safe(resolver, target_domain, 'AAAA')]
    ns_records   = [str(r.target) for r in _resolve_safe(resolver, target_domain, 'NS')]
    caa_records  = [str(r) for r in _resolve_safe(resolver, target_domain, 'CAA')]
    txt_records  = [r.to_text().strip('"') for r in _resolve_safe(resolver, target_domain, 'TXT')]

    if len(ns_records) < 2:
        findings.append({
            'severity': 'MEDIUM', 
            'scan_type': 'infra',
            'category': 'dns',
            'finding': 'Fewer than 2 nameservers — single point of DNS failure'
		})
    if not caa_records:
        findings.append({
            'severity': 'LOW', 
            'scan_type': 'infra',
            'category': 'dns',
            'finding': 'No CAA records — any CA may issue TLS certificates for this domain'
		})

    return {
        'a_records':     a_records,
        'aaaa_records':  aaaa_records,
        'ns_records':    ns_records,
        'caa_records':   caa_records,
        'txt_records':   txt_records,
        'dnssec':        _check_dnssec(target_domain, resolver, findings),
        'zone_transfer': _attempt_zone_transfer(target_domain, ns_records, findings),
    }


def _check_email_secondary(target_domain, txt_records, resolver, findings):
    email_findings = []
    result = {
        'note': 'Secondary check — run Email Scan for full email security assessment',
        'spf':   _check_spf(txt_records, email_findings),
        'dmarc': _check_dmarc(target_domain, resolver, email_findings),
    }
    for f in email_findings:
        f['category'] = 'email_secondary'
    findings.extend(email_findings)
    return result


def _check_ip_intel(a_records, aaaa_records, findings):
    ip_intel = []
    for ip in (a_records + aaaa_records)[:5]:
        info = {'ip': ip}
        try:
            r = requests.get(f'https://ipinfo.io/{ip}/json', timeout=5,
                             headers={'User-Agent': 'SimpleScan/1.0'})
            if r.status_code == 200:
                data = r.json()
                info.update({
                    'hostname': data.get('hostname'),
                    'org':      data.get('org'),
                    'city':     data.get('city'),
                    'country':  data.get('country'),
                    'is_bogon': data.get('bogon', False),
                })
                if data.get('bogon'):
                    findings.append({
                        'severity': 'HIGH', 
                        'scan_type': 'infra',
                        'category': 'ip_intel',
                        'finding': f'IP {ip} is a bogon (private/reserved) address'
					})
        except Exception as e:
            info['error'] = str(e)[:100]
        ip_intel.append(info)
    return ip_intel


def _check_reverse_dns(a_records, aaaa_records, findings):
    ptr_results = {}
    for ip in (a_records + aaaa_records)[:5]:
        try:
            hostname, _, _ = socket.gethostbyaddr(ip)
            ptr_results[ip] = hostname
            try:
                fwd = socket.gethostbyname(hostname)
                ptr_results[f'{ip}_fcrdns'] = 'pass' if fwd == ip else f'fail (resolves to {fwd})'
                if fwd != ip:
                    findings.append({
                        'severity': 'LOW', 
                        'scan_type': 'infra', 
                        'category': 'dns',
                        'finding': f'FCrDNS mismatch for {ip}: PTR={hostname} resolves to {fwd}'
					})
            except Exception:
                ptr_results[f'{ip}_fcrdns'] = 'fail (forward lookup failed)'
        except Exception:
            ptr_results[ip] = None
    return ptr_results


def _check_subdomains(target_domain, resolver, findings):
    discovered = []
    for sub in SUBDOMAINS_TO_PROBE:
        fqdn = f'{sub}.{target_domain}'
        try:
            answers = resolver.resolve(fqdn, 'A')
            discovered.append({'subdomain': fqdn, 'ips': [r.address for r in answers]})
            logger.debug(f'[InfraScan] Subdomain found: {fqdn}')
        except Exception:
            pass
    if discovered:
        findings.append({
            'severity': 'INFO', 
            'scan_type': 'infra',
            'category': 'subdomain',
            'finding': f'{len(discovered)} subdomains discovered: ' + ', '.join(d['subdomain'] for d in discovered)
		})
    return {
        'probed':            len(SUBDOMAINS_TO_PROBE),
        'discovered_count':  len(discovered),
        'discovered':        discovered,
    }


# ── HTTP ─────────────────────────────────────────────────────────────────────

def _detect_waf_cdn(headers):
    return [name for name, check in WAF_CDN_SIGNATURES.items() if check(headers)]


def _probe_paths(base_url, session, findings):
    discovered = []
    sensitive = {'.env', '.git', 'backup', 'config', 'htaccess', 'web.config', 'xmlrpc'}
    for path in PROBE_PATHS:
        try:
            r = session.get(f'{base_url}{path}', timeout=5, allow_redirects=False,
                            headers={'User-Agent': 'SimpleScan/1.0'})
            if r.status_code in (200, 301, 302, 403):
                discovered.append({
                    'path': path, 
                    'status': r.status_code,
                    'content_length': r.headers.get('Content-Length', '?')
                })
                if r.status_code == 200 and any(s in path for s in sensitive):
                    findings.append({
                        'severity': 'CRITICAL', 
                        'scan_type': 'infra',
                        'category': 'paths',
                        'finding': f'Sensitive path accessible: {path} (HTTP 200)'
					})
                elif r.status_code == 403 and any(s in path for s in sensitive):
                    findings.append({
                        'severity': 'MEDIUM', 
                        'scan_type': 'infra',
                        'category': 'paths',
                        'finding': f'Sensitive path exists but forbidden: {path} (HTTP 403)'
					})
        except Exception:
            pass
    return discovered


def _check_http_methods(base_url, session, findings):
    methods = {}
    try:
        r = session.options(base_url, timeout=5, headers={'User-Agent': 'SimpleScan/1.0'})
        allow = r.headers.get('Allow', '') or r.headers.get('Public', '')
        methods['allow_header'] = allow
        dangerous = [m for m in ['TRACE', 'DELETE', 'PUT', 'CONNECT'] if m in allow]
        if dangerous:
            findings.append({
                'severity': 'MEDIUM', 
                'scan_type': 'infra',
                'category': 'http',
                'finding': f'Dangerous HTTP methods allowed: {", ".join(dangerous)}'
            })
        methods['dangerous_methods'] = dangerous
    except Exception as e:
        methods['error'] = str(e)[:100]
    return methods


# ── Scan functions ────────────────────────────────────────────────────────────

def run_tcp_port_scan(target_ip: str) -> dict:
    """Port scan against the organization's WAN IP."""
    scan_start_ts = datetime.now(dt_timezone.utc)
    target_ip = target_ip.strip()
    logger.info(f"[PortScan] Starting on '{target_ip}' (len={len(target_ip)})")
    findings = []

    for port in TCP_PORT_SERVICES:
        logger.info(f"[PortScan] Scanning TCP port {port} ({TCP_PORT_SERVICES[port]})")
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(3)
        try:
            sock.connect((target_ip, port))
            # If we get here, the connection succeeded — port is open
            scripts = _grab_banner(sock, port)
            finding = {
                'severity': 'INFO',
                'scan_type': 'tcp',
                'description': "Open port: " + str(port) + "/tcp open  " + TCP_PORT_SERVICES.get(port, 'unknown'),
                'information': "",
                'portid': str(port), 
                'protocol': 'tcp',
                'service': TCP_PORT_SERVICES.get(port, 'unknown'),
                'scripts': scripts, 
            }
            # If we have a hard coded finding for this port, use it instead of the generic INFO/Open port description
            if port in TCP_PORT_FINDINGS:
                finding['severity'], finding['information'] = TCP_PORT_FINDINGS[port]
            findings.append(finding)
            # Emit an additional critical CVE advisory if warranted (e.g. port 80/443) (Ian's Group 10)
            if port in TCP_PORT_CVE_WARNINGS:
                cve_severity, cve_info = TCP_PORT_CVE_WARNINGS[port]
                findings.append({
                    'severity': cve_severity,
					'scan_type': 'tcp',
                    'description': f"CVE advisory for port {port}/{TCP_PORT_SERVICES.get(port, 'unknown')}",
                    'information': cve_info,
                    'portid': str(port), 
                    'protocol': 'tcp',
                    'service': TCP_PORT_SERVICES.get(port, 'unknown'),
                    'scripts': [],
                })
        except socket.timeout:
            # No response within timeout — port is filtered (firewall dropping packets)
            logger.info(f"[PortScan] Port {port} timed out — filtered")
        except ConnectionRefusedError:
            # RST received — firewall allows traffic but no service is listening.
            # From a security perspective this is an open port — it's reachable from the internet.
            logger.info(f"[PortScan] Port {port} open (no service listening)")
            finding = {
                'severity': 'INFO',
                'scan_type': 'tcp',
                'description': "Open port: " + str(port) + "/tcp open  " + TCP_PORT_SERVICES.get(port, 'unknown'),
                'information': "Port is open through the firewall but no service is currently listening.",
                'portid': str(port), 
                'protocol': 'tcp',
                'service': TCP_PORT_SERVICES.get(port, 'unknown'),
                'scripts': [],
            }
            if port in TCP_PORT_FINDINGS:
                finding['severity'], finding['information'] = TCP_PORT_FINDINGS[port]
            findings.append(finding)
        except OSError as e:
            # Network unreachable or similar OS-level error
            logger.info(f"[PortScan] Port {port} OS error ({e})")
        except Exception as e:
            logger.warning(f"[PortScan] Port {port} unexpected error: {e}")
        finally:
            sock.close()
        logger.info(f"[PortScan] Finished TCP port {port}")

    open_count = sum(1 for f in findings if "Open port" in f['description']) # Get number of open ports based on descriptions
    findings.sort(key=lambda f: SEVERITY_ORDER.get(f['severity'], 99))

    results = {
        'scan_metadata': _add_metadata('tcp', scan_start_ts),
        'findings': findings
    }
    logger.info(f"[TCPPortScan] Complete — {open_count} open ports, {len(findings)} findings in {results['scan_metadata']['scan_duration']}s")
    return results


def run_udp_port_scan(target_ip: str) -> dict:
    """UDP port scan against the organization's WAN IP."""
    scan_start_ts = datetime.now(dt_timezone.utc)
    logger.info(f"[UDPPortScan] Starting on {target_ip}")
    findings = []

    for port in UDP_PORT_SERVICES:
        logger.info(f"[UDPPortScan] Scanning UDP port {port} ({UDP_PORT_SERVICES[port]})")
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(2)
        scripts = []
        try:
            sock.sendto(b'\x00', (target_ip, port))
            data, _ = sock.recvfrom(2048)
            # Got a response — port is open
            if data:
                scripts = [{'id': 'udp-response', 'output': data.decode('utf-8', errors='ignore')[:200]}]
            finding = {
                'severity': 'INFO',
                'scan_type': 'udp',
                'description': "Open port: " + str(port) + "/udp open  " + UDP_PORT_SERVICES.get(port, 'unknown'),
                'information': "",
                'portid': str(port), 'protocol': 'udp',
                'service': UDP_PORT_SERVICES.get(port, 'unknown'),
                'scripts': scripts,
            }
            if port in UDP_PORT_FINDINGS:
                finding['severity'], finding['information'] = UDP_PORT_FINDINGS[port]
            findings.append(finding)
        except socket.timeout:
            # Timeout = open|filtered - LOGIC NEEDS UPDATED
            finding = {
                'severity': 'INFO',
                'scan_type': 'udp',
                'description': "Open|Filtered port: " + str(port) + "/udp open|filtered  " + UDP_PORT_SERVICES.get(port, 'unknown'),
                'information': "",
                'portid': str(port), 'protocol': 'udp',
                'service': UDP_PORT_SERVICES.get(port, 'unknown'),
                'scripts': [],
            }
            if port in UDP_PORT_FINDINGS:
                finding['severity'], finding['information'] = UDP_PORT_FINDINGS[port]
            findings.append(finding)
        except ConnectionRefusedError:
            # ICMP port unreachable — definitively closed, skip
            pass
        except Exception:
            findings.append({
                'severity': 'INFO',
                'scan_type': 'udp',
                'description': "Port Error: " + str(port) + "/udp error  " + UDP_PORT_SERVICES.get(port, 'unknown'),
                'information': "",
                'portid': str(port), 'protocol': 'udp',
                'service': UDP_PORT_SERVICES.get(port, 'unknown'),
                'scripts': [],
            })
        finally:
            sock.close()
        logger.info(f"[UDPPortScan] Finished UDP port {port}")

    open_count = sum(1 for f in findings if "Open port" in f['description'])
    findings.sort(key=lambda f: SEVERITY_ORDER.get(f['severity'], 99))

    results = {
        'scan_metadata': _add_metadata('udp', scan_start_ts),
        'findings': findings
    }
    logger.info(f"[UDPPortScan] Complete — {open_count} open ports, {len(findings)} findings in {results['scan_metadata']['scan_duration']}s")
    return results


def run_email_scan(target_domain: str) -> dict:
    """Email security scan: MX, SPF, DMARC, DKIM, MTA-STS, DNSSEC, zone transfer."""
    scan_start_ts = datetime.now(dt_timezone.utc)
    logger.info(f"[EmailScan] Starting on {target_domain}")
    findings = []
    results = {
        'email': {
            'mx': {}, 
            'spf': {}, 
            'dmarc': {}, 
            'dkim': {}, 
            'mta_sts': {},
            'dnssec': {}, 
            'zone_transfer': {}
        },
        'findings': []
    }

    resolver = _make_resolver()

    mx_records = [{'preference': r.preference, 'exchange': str(r.exchange)}
                  for r in _resolve_safe(resolver, target_domain, 'MX')]
    results['email']['mx'] = {'records': mx_records, 'count': len(mx_records)}
    if not mx_records:
        findings.append({
            'severity': 'HIGH', 
            'scan_type': 'email',
            'category': 'mx',
            'description': 'No MX records — domain cannot receive email'
		})

    txt_records = [r.to_text().strip('"') for r in _resolve_safe(resolver, target_domain, 'TXT')]
    ns_records  = [str(r.target) for r in _resolve_safe(resolver, target_domain, 'NS')]

    results['email']['spf']           = _check_spf(txt_records, findings)
    results['email']['dmarc']         = _check_dmarc(target_domain, resolver, findings)
    results['email']['dkim']          = _check_dkim(target_domain, resolver, findings)
    results['email']['mta_sts']       = _check_mta_sts(target_domain, resolver, findings)
    results['email']['dnssec']        = _check_dnssec(target_domain, resolver, findings)
    results['email']['zone_transfer'] = _attempt_zone_transfer(target_domain, ns_records, findings)

    results['scan_metadata'] = _add_metadata('email', scan_start_ts)
    results['findings'] = findings
    logger.info(f"[EmailScan] Complete — {len(findings)} findings in {results['scan_metadata']['scan_duration']}s")
    return results


def run_infra_scan(target_domain: str) -> dict:
    """Web infrastructure scan: TLS, HTTP headers, DNS, subdomains, IP intel."""
    scan_start_ts = datetime.now(dt_timezone.utc)
    logger.info(f"[InfraScan] Starting on {target_domain}")
    findings = []
    results = {
        'infra': {
			'tls': {}, 
			'http': {}, 
			'dns': {}, 
			'email_secondary': {},
			'ip_intel': [], 
			'reverse_dns': {}, 
			'subdomains': {}
		},
		'findings': []
    }

    resolver = _make_resolver()
    session = requests.Session()

	# TLS
    results['infra']['tls'] = _check_tls(target_domain, findings)

    # HTTP
    results['infra']['http'] = _check_http(target_domain, session, findings)

    # DNS — also surfaces raw records needed by downstream helpers
    dns_data     = _check_dns(target_domain, resolver, findings)
    a_records    = dns_data.pop('a_records')
    aaaa_records = dns_data.pop('aaaa_records')
    txt_records  = dns_data.pop('txt_records')
    results['infra']['dns'] = dns_data

    # Secondary email checks (SPF/DMARC on the web domain)
    results['infra']['email_secondary'] = _check_email_secondary(target_domain, txt_records, resolver, findings)

    # IP intel
    results['infra']['ip_intel'] = _check_ip_intel(a_records, aaaa_records, findings)

    # Reverse DNS
    results['infra']['reverse_dns'] = _check_reverse_dns(a_records, aaaa_records, findings)

    # Subdomain enumeration
    results['infra']['subdomains'] = _check_subdomains(target_domain, resolver, findings)

    results['scan_metadata'] = _add_metadata('infra', scan_start_ts, target=target_domain)
    logger.info(f"[InfraScan] Complete — {len(findings)} findings in {results['scan_metadata']['scan_duration']}s")
    return results


# ── Django-Q2 task entry point ────────────────────────────────────────────────

def run_network_scan(scan_id: str, scan_arr: list = [1, 1, 1, 1]):
    """
    Django-Q2 background task.

    Flow:
        1. Validate scan record + org targets
        2. Run port scan, email scan, infra scan
        3. Persist combined findings to Scan record
        4. Trigger AI report generation (reuses existing pipeline)
        5. Email user when report is ready
    """
    from api.models import Scan
    from api.utils.email_factory import send_email_by_type
    from .generate_report_from_scan import generate_report_from_scan

    try:
        scan = Scan.objects.select_related('user', 'organization').get(id=scan_id)

        # Idempotency: if a previous retry already completed this scan, bail out
        if scan.status == Scan.Status.COMPLETE or (hasattr(scan, 'report') and scan.report_id):
            logger.info(f"[NetworkScan {scan_id}] Already complete — skipping duplicate run.")
            return {'success': True, 'report_id': str(scan.report.report_id) if scan.report_id else None}

        org  = scan.organization
        user = scan.user

        port_target   = org.external_ip
        infra_target  = org.website_domain or org.email_domain
        # email_domain may be comma-separated — scan each one
        email_domain = org.email_domain

        if not port_target or not email_domain:
            raise ValueError(
                "Organization is missing external_ip or email_domain. "
                "Complete the questionnaire in Settings → Security Posture."
            )

        # ── Step 1: Mark scan as running ──────────────────────────────────
        network_scan_start_ts = datetime.now(dt_timezone.utc)
        scan.status = Scan.Status.RUNNING
        scan.scan_started_at = timezone.now()
        scan.save(update_fields=['status', 'scan_started_at'])

        # ── Step 2: Run the selected scan types ─────────────────────────
        scan_configs = [
            ('tcp',   run_tcp_port_scan, port_target),
            ('udp',   run_udp_port_scan, port_target),
            ('email', run_email_scan,    email_domain),
            ('infra', run_infra_scan,    infra_target)
        ]

        scan_results = {}
        for i, (key, runner, target) in enumerate(scan_configs):
            if scan_arr[i] and target:
                scan_results[key] = runner(target)
            else:
                scan_results[key] = {}

        # ── Step 3: Combine + persist findings ────────────────────────────
        all_findings = []
        scan_metadata_list = [_add_metadata('network_scan', network_scan_start_ts)]
        results_obj = {}

        for key, result in scan_results.items():
            all_findings += result.get('findings', [])
            if result.get('scan_metadata'):
                scan_metadata_list.append(result['scan_metadata'])
            if result.get(key):
                results_obj[key] = result[key]

        scan.scan_completed_at = timezone.now()
        scan.target_subnet = f"{port_target} / {infra_target}"

        scan.raw_findings_json = json.dumps({
            'scan_metadata': scan_metadata_list,
            'findings': all_findings,
            'results': results_obj,
        })
        logger.info(f"Network scan results: {scan.raw_findings_json}")
        scan.tally_findings(all_findings)
        scan.status = Scan.Status.GENERATING
        scan.save()

        # ── Step 4: Generate AI report ────────────────────────────────────
        
        # 1. Create a mutable list to hold the incoming stream text
        stream_buffer = [""]
        
        # 2. Define the callback that parses the text exactly like your old JS did
        def ai_progress_callback(chunk_text):
            stream_buffer[0] += chunk_text
            current_text = stream_buffer[0]
            
            report_pct = 5
            status_text = 'Initializing AI...'
            
            if '"Conclusion"' in current_text:
                report_pct, status_text = 95, 'Concluding report'
            elif '"Observations"' in current_text:
                report_pct, status_text = 80, 'Determining observations'
            elif '"Summary"' in current_text:
                severity_hits = current_text.count('"Severity"')
                if severity_hits > 0:
                    report_pct = min(75, 35 + (severity_hits * 4))
                    status_text = f'Analyzing risk {severity_hits}...'
                else:
                    report_pct, status_text = 35, 'Providing network summary'
            elif '"report"' in current_text:
                report_pct, status_text = 20, 'Generation started'
            elif '"thought"' in current_text:
                report_pct, status_text = 10, 'Reading over report'
                
            # 3. Write ONLY the clean progress data to cache, no raw AI text!
            cache.set(f"scan_progress_{scan_id}", {
                "progress": report_pct,
                "text": status_text
            }, timeout=600)

        # 4. Pass the callback down. 
        result = generate_report_from_scan(scan_id, chunk_callback=ai_progress_callback)

        if not result or not result.get('success'):
            error_msg = result.get('error', 'Unknown error') if result else 'generate_report_from_scan returned None'
            raise RuntimeError(f"Report generation failed: {error_msg}")

        # ── Step 5: Email user ────────────────────────────────────────────
        report_id = result['report_id']
        try:
            # Generate the relative path (/reports/<uuid>/)
            relative_url = reverse('report_detail', kwargs={'report_id': report_id})
            
            # Construct the absolute URL, checking your settings for the base domain
            base_url = (
                getattr(settings, 'APP_BASE_URL', '').strip()
                or getattr(settings, 'SITE_URL', '').strip()
                or 'http://localhost:8000'
            ).rstrip('/')
            
            full_report_url = f"{base_url}{relative_url}"

            send_email_by_type('report', user.email, {
                'generated_date': timezone.now().strftime('%B %d, %Y %I:%M %p UTC'),
                #'report_id': str(report_id),
                #'report_type': 'Comprehensive Vulnerability Assessment',
                'report_url': full_report_url, 
            })
        except Exception as email_err:
            # Don't fail the task over a notification email
            logger.warning(f"[NetworkScan {scan_id}] Email notification failed: {email_err}")

        logger.info(f"[NetworkScan {scan_id}] Complete. Report {report_id} generated.")
        return {'success': True, 'report_id': str(report_id)}

    except Exception as e:
        logger.exception(f"[NetworkScan {scan_id}] Task failed: {e}")
        try:
            from api.models import Scan
            # Only mark FAILED if the scan didn't actually complete — a retry
            # that hits this block after a successful report would overwrite COMPLETE.
            updated = Scan.objects.filter(id=scan_id).exclude(
                status=Scan.Status.COMPLETE
            ).update(
                status=Scan.Status.FAILED,
                error_message=str(e)[:500],
            )
            if not updated:
                logger.warning(f"[NetworkScan {scan_id}] Exception after completion — not marking FAILED.")
        except Exception:
            pass
        # Do NOT re-raise: prevents Django-Q2 from retrying a completed scan
