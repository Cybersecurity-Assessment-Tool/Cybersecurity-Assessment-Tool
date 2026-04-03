"""
Server-side network scanner.

Runs three scans against the organization's configured targets:
  - Port scan      → org.external_ip
  - Email scan     → org.email_domain
  - Infra scan     → org.website_domain (falls back to email_domain)

Entry point for Django-Q2: run_server_scan(scan_id)
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


def _summarise(findings, results):
    results['security_findings'] = findings
    results['scan_metadata'].update({
        'total_findings': len(findings),
        'critical': sum(1 for f in findings if f['severity'] == 'CRITICAL'),
        'high':     sum(1 for f in findings if f['severity'] == 'HIGH'),
        'medium':   sum(1 for f in findings if f['severity'] == 'MEDIUM'),
        'low':      sum(1 for f in findings if f['severity'] == 'LOW'),
    })


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
            'category': 'email',
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
            'category': 'email',
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
            'category': 'email',
            'description': 'SPF uses "+all" — any server can send mail as this domain'
        })
    elif '~all' in spf:
        info['enforcement'] = '~all (softfail)'
        findings.append({
            'severity': 'LOW', 
            'category': 'email',
            'description': 'SPF uses "~all" (softfail) — consider upgrading to "-all"'
        })
        info['issue'] = 'SPF uses "~all" (softfail) — consider upgrading to "-all"'
    elif '-all' in spf:
        info['enforcement'] = '-all (fail)'
    elif '?all' in spf:
        info['enforcement'] = '?all (neutral)'
        findings.append({
            'severity': 'MEDIUM', 
            'category': 'email',
            'description': 'SPF uses "?all" (neutral) — provides no protection'
        })
    return info


def _check_dmarc(target, resolver, findings):
    answers = _resolve_safe(resolver, f'_dmarc.{target}', 'TXT')
    raw = [r.to_text().strip('"') for r in answers]
    if not raw:
        findings.append({
            'severity': 'HIGH', 
            'category': 'email',
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
            'category': 'email',
            'description': 'DMARC policy is "none" — unauthenticated email is delivered without action'
		})
    elif policy == 'quarantine':
        findings.append({
            'severity': 'LOW', 
            'category': 'email',
        	'description': 'DMARC policy is "quarantine" — consider upgrading to "reject"'
        })
    if not tags.get('rua'):
        findings.append({
            'severity': 'LOW', 
            'category': 'email',
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
            'category': 'email',
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
            'category': 'email',
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
                    'category': 'email',
                    'description': 'MTA-STS policy is in "testing" mode — not yet enforcing'
				})
            elif 'mode: none' in r.text:
                result['mode'] = 'none'
                findings.append({
                    'severity': 'MEDIUM', 
                    'category': 'email',
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
            'category': 'dns',
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
                    'category': 'dns',
                    'description': f'Zone transfer (AXFR) succeeded on {ns_clean} — entire DNS zone exposed'
                })
            except Exception:
                result['attempted'].append({'ns': ns_clean, 'result': 'refused'})
        except Exception as e:
            result['attempted'].append({'ns': ns_clean, 'result': f'error: {str(e)[:60]}'})
    return result


# ── Scan functions ────────────────────────────────────────────────────────────

def run_tcp_port_scan(target_ip: str) -> dict:
    """Port scan against the organization's WAN IP."""
    logger.info(f"[PortScan] Starting on {target_ip}")
    findings = []

    for port in TCP_PORT_SERVICES:
        logger.info(f"[PortScan] Scanning TCP port {port} ({TCP_PORT_SERVICES[port]})")
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(2)
        try:
            if sock.connect_ex((target_ip, port)) != 0:
                continue  # Port is closed/filtered — skip to next port
            scripts = _grab_banner(sock, port)
            result = {
                'severity': 'INFO',
                'category': 'port',
                'description': "Open port: " + str(port) + "/tcp open  " + TCP_PORT_SERVICES.get(port, 'unknown'),
                'information': "",
                'portid': str(port), 'protocol': 'tcp',
                'service': TCP_PORT_SERVICES.get(port, 'unknown'),
                'scripts': scripts, 
                'timestamp': timezone.now().isoformat(),
            }
            # If we have a hard coded finding for this port, use it instead of the generic INFO/Open port description
            if port in TCP_PORT_FINDINGS:
                result['severity'], result['information'] = TCP_PORT_FINDINGS[port]
            findings.append(result)
            # Emit an additional critical CVE advisory if warranted (e.g. port 80/443) (Ian's Group 10)
            if port in TCP_PORT_CVE_WARNINGS:
                cve_severity, cve_info = TCP_PORT_CVE_WARNINGS[port]
                findings.append({
                    'severity': cve_severity,
					'category': 'port',
                    'description': f"CVE advisory for port {port}/{TCP_PORT_SERVICES.get(port, 'unknown')}",
                    'information': cve_info,
                    'portid': str(port), 'protocol': 'tcp',
                    'service': TCP_PORT_SERVICES.get(port, 'unknown'),
                    'scripts': [],
                    'timestamp': timezone.now().isoformat(),
                })
        except Exception:
            findings.append({
                'severity': 'INFO',
                'category': 'port',
                'description': "Port Error: " + str(port) + "/tcp error  " + TCP_PORT_SERVICES.get(port, 'unknown'),
                'information': "",
                'portid': str(port), 'protocol': 'tcp',
                'service': TCP_PORT_SERVICES.get(port, 'unknown'),
                'scripts': "", 
                'timestamp': timezone.now().isoformat(),
            })
        finally:
            sock.close()
        logger.info(f"[PortScan] Finished TCP port {port}")

    open_count = sum(1 for f in findings if "Open port" in f['description']) # Get number of open ports based on descriptions
    findings.sort(key=lambda f: SEVERITY_ORDER.get(f['severity'], 99))

    results = {
        'scan_metadata': {
            'scan_type': 'tcp',
            'timestamp': datetime.now(dt_timezone.utc).isoformat(),
        },
        'findings': findings
    }
    logger.info(f"[TCPPortScan] Complete — {open_count} open ports, {len(findings)} findings")
    return results


def run_udp_port_scan(target_ip: str) -> dict:
    """UDP port scan against the organization's WAN IP."""
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
            result = {
                'severity': 'INFO',
                'category': 'port',
                'description': "Open port: " + str(port) + "/udp open  " + UDP_PORT_SERVICES.get(port, 'unknown'),
                'information': "",
                'portid': str(port), 'protocol': 'udp',
                'service': UDP_PORT_SERVICES.get(port, 'unknown'),
                'scripts': scripts,
                'timestamp': timezone.now().isoformat(),
            }
            if port in UDP_PORT_FINDINGS:
                result['severity'], result['information'] = UDP_PORT_FINDINGS[port]
            findings.append(result)
        except socket.timeout:
            # Timeout = open|filtered — still worth reporting
            result = {
                'severity': 'INFO',
                'category': 'port',
                'description': "Open|Filtered port: " + str(port) + "/udp open|filtered  " + UDP_PORT_SERVICES.get(port, 'unknown'),
                'information': "",
                'portid': str(port), 'protocol': 'udp',
                'service': UDP_PORT_SERVICES.get(port, 'unknown'),
                'scripts': [],
                'timestamp': timezone.now().isoformat(),
            }
            if port in UDP_PORT_FINDINGS:
                result['severity'], result['information'] = UDP_PORT_FINDINGS[port]
            findings.append(result)
        except ConnectionRefusedError:
            # ICMP port unreachable — definitively closed, skip
            pass
        except Exception:
            findings.append({
                'severity': 'INFO',
                'category': 'port',
                'description': "Port Error: " + str(port) + "/udp error  " + UDP_PORT_SERVICES.get(port, 'unknown'),
                'information': "",
                'portid': str(port), 'protocol': 'udp',
                'service': UDP_PORT_SERVICES.get(port, 'unknown'),
                'scripts': [],
                'timestamp': timezone.now().isoformat(),
            })
        finally:
            sock.close()
        logger.info(f"[UDPPortScan] Finished UDP port {port}")

    open_count = sum(1 for f in findings if "Open port" in f['description'])
    findings.sort(key=lambda f: SEVERITY_ORDER.get(f['severity'], 99))

    results = {
        'scan_metadata': {
            'scan_type': 'udp',
            'timestamp': datetime.now(dt_timezone.utc).isoformat(),
        },
        'findings': findings
    }
    logger.info(f"[UDPPortScan] Complete — {open_count} open ports, {len(findings)} findings")
    return results


def run_email_scan(target_domain: str) -> dict:
    """Email security scan: MX, SPF, DMARC, DKIM, MTA-STS, DNSSEC, zone transfer."""
    logger.info(f"[EmailScan] Starting on {target_domain}")
    findings = []
    results = {
        'scan_metadata': {
            'scan_type': 'email',
            'timestamp': datetime.now(dt_timezone.utc).isoformat(),
        },
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
    results['mx'] = {'records': mx_records, 'count': len(mx_records)}
    if not mx_records:
        findings.append({
            'severity': 'HIGH', 
            'category': 'email',
            'description': 'No MX records — domain cannot receive email'
		})

    txt_records = [r.to_text().strip('"') for r in _resolve_safe(resolver, target_domain, 'TXT')]
    ns_records  = [str(r.target) for r in _resolve_safe(resolver, target_domain, 'NS')]

    results['spf']           = _check_spf(txt_records, findings)
    results['dmarc']         = _check_dmarc(target_domain, resolver, findings)
    results['dkim']          = _check_dkim(target_domain, resolver, findings)
    results['mta_sts']       = _check_mta_sts(target_domain, resolver, findings)
    results['dnssec']        = _check_dnssec(target_domain, resolver, findings)
    results['zone_transfer'] = _attempt_zone_transfer(target_domain, ns_records, findings)

    # _summarise(findings, results)
    results['findings'] = findings
    logger.info(f"[EmailScan] Complete — {len(findings)} findings")
    return results


# ── Django-Q2 task entry point ────────────────────────────────────────────────

def run_server_scan(scan_id: str):
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
            logger.info(f"[ServerScan {scan_id}] Already complete — skipping duplicate run.")
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
        scan.status = Scan.Status.RUNNING
        scan.scan_started_at = timezone.now()
        scan.save(update_fields=['status', 'scan_started_at'])

        # ── Step 2: Run the four scan types ──────────────────────────────
        tcp_port_results = run_tcp_port_scan(port_target)

        udp_port_results = run_udp_port_scan(port_target)

        email_results_list = run_email_scan(email_domain)

        # infra_results = run_infra_scan(infra_target) if infra_target else {}

        # ── Step 3: Combine + persist findings ────────────────────────────
        all_findings = tcp_port_results.get('findings', [])
        all_findings += udp_port_results.get('findings', [])
        all_findings += email_results_list.get('findings', [])
        # all_findings += infra_results.get('security_findings', [])

        scan.scan_completed_at = timezone.now()
        scan.target_subnet = f"{port_target} / {infra_target}"
        scan.raw_findings_json = json.dumps({
            'findings': all_findings,
            # 'raw_results': {
            #     'port_scan':   tcp_port_results,
            #     'email_scans': {d: r for d, r in zip(email_targets, email_results_list)},
            #     'infra_scan':  {},  # infra_results,
            # },
        })
        logger.info(f"Network scan results: {scan.raw_findings_json}")
        scan.tally_findings(all_findings)
        scan.status = Scan.Status.GENERATING
        scan.save()

        # ── Step 4: Generate AI report ────────────────────────────────────
        result = generate_report_from_scan(scan_id)

        if not result or not result.get('success'):
            error_msg = result.get('error', 'Unknown error') if result else 'generate_report_from_scan returned None'
            raise RuntimeError(f"Report generation failed: {error_msg}")

        # ── Step 5: Email user ────────────────────────────────────────────
        report_id = result['report_id']
        try:
            send_email_by_type('report', user.email, {
                'generated_date': timezone.now().strftime('%B %d, %Y %I:%M %p UTC'),
                'report_id': str(report_id),
                'report_type': 'Comprehensive Vulnerability Assessment',
                'login_url': f'/reports/{report_id}/',
            })
        except Exception as email_err:
            # Don't fail the task over a notification email
            logger.warning(f"[ServerScan {scan_id}] Email notification failed: {email_err}")

        logger.info(f"[ServerScan {scan_id}] Complete. Report {report_id} generated.")
        return {'success': True, 'report_id': str(report_id)}

    except Exception as e:
        logger.exception(f"[ServerScan {scan_id}] Task failed: {e}")
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
                logger.warning(f"[ServerScan {scan_id}] Exception after completion — not marking FAILED.")
        except Exception:
            pass
        # Do NOT re-raise: prevents Django-Q2 from retrying a completed scan
