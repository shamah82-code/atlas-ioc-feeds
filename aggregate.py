#!/usr/bin/env python3
"""
Atlas Shield IOC Feed Aggregator
Fetches 400+ threat intelligence feeds, deduplicates, and outputs 3 clean files:
  - ips.txt      (one IP per line, sorted, deduplicated)
  - domains.txt  (one domain per line, sorted, deduplicated)
  - hashes.txt   (one SHA256/MD5 per line, sorted, deduplicated)

Runs daily via GitHub Actions. Atlas Shield app downloads these 3 files instead of 400 feeds.
"""

import re
import sys
import csv
import time
import hashlib
import logging
import io
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.request import urlopen, Request
from urllib.error import URLError, HTTPError

logging.basicConfig(level=logging.INFO, format='%(asctime)s %(levelname)s %(message)s')
log = logging.getLogger('aggregator')

TIMEOUT = 30  # seconds per feed
MAX_WORKERS = 10

# ─── REGEX PATTERNS ──────────────────────────────────────────────────────────
IP_RE = re.compile(r'^(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})(?:[/:\s\t,;|]|$)')
DOMAIN_RE = re.compile(r'^(?:0\.0\.0\.0|127\.0\.0\.1)\s+(\S+)')  # hostfile format
PLAIN_DOMAIN_RE = re.compile(r'^([a-zA-Z0-9]([a-zA-Z0-9\-]*[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$')
HASH_RE = re.compile(r'^[a-fA-F0-9]{32}(?:[a-fA-F0-9]{32})?$')  # MD5 (32) or SHA256 (64)

# ─── SAFE / WHITELISTED ──────────────────────────────────────────────────────
SAFE_IPS = {
    '0.0.0.0', '127.0.0.1', '255.255.255.255',
    '8.8.8.8', '8.8.4.4', '1.1.1.1', '1.0.0.1',
    '9.9.9.9', '149.112.112.112',
    '208.67.222.222', '208.67.220.220',
}

SAFE_DOMAINS = {
    'localhost', 'example.com', 'example.org', 'example.net',
    'google.com', 'www.google.com', 'googleapis.com',
    'apple.com', 'microsoft.com', 'windows.com',
    'facebook.com', 'instagram.com', 'whatsapp.com', 'whatsapp.net',
    'youtube.com', 'twitter.com', 'x.com',
    'amazon.com', 'amazonaws.com', 'cloudfront.net',
    'github.com', 'raw.githubusercontent.com',
    'cloudflare.com', 'cloudflare-dns.com',
    'gstatic.com', 'googlevideo.com', 'googleusercontent.com',
    'fbcdn.net', 'cdninstagram.com',
    'akamai.net', 'akamaiedge.net',
    'play.google.com', 'dl.google.com',
}

# ─── FEED DEFINITIONS ────────────────────────────────────────────────────────
# Format: (url, type, parser)
# type: 'ip', 'domain', 'hash', 'mixed'
# parser: 'plain-ip', 'plain-domain', 'hostfile', 'csv-ip', 'csv-domain', 'hash', 'mixed', 'pipe-ip', 'tab-ip'

IP_FEEDS = [
    # IPsum — aggregated multi-blacklist (THE big one)
    ('https://raw.githubusercontent.com/stamparm/ipsum/master/levels/1.txt', 'tab-ip'),
    ('https://raw.githubusercontent.com/stamparm/ipsum/master/levels/3.txt', 'tab-ip'),
    ('https://raw.githubusercontent.com/stamparm/ipsum/master/levels/5.txt', 'tab-ip'),
    ('https://raw.githubusercontent.com/stamparm/ipsum/master/levels/7.txt', 'tab-ip'),
    ('https://raw.githubusercontent.com/stamparm/ipsum/master/levels/8.txt', 'tab-ip'),

    # FireHOL aggregated levels (combine 350+ sources)
    ('https://raw.githubusercontent.com/firehol/blocklist-ipsets/master/firehol_level1.netset', 'plain-ip'),
    ('https://raw.githubusercontent.com/firehol/blocklist-ipsets/master/firehol_level2.netset', 'plain-ip'),
    ('https://raw.githubusercontent.com/firehol/blocklist-ipsets/master/firehol_level3.netset', 'plain-ip'),
    ('https://raw.githubusercontent.com/firehol/blocklist-ipsets/master/firehol_webclient.netset', 'plain-ip'),

    # Abuse.ch
    ('https://sslbl.abuse.ch/blacklist/sslipblacklist.txt', 'plain-ip'),
    ('https://sslbl.abuse.ch/blacklist/sslipblacklist_aggressive.csv', 'csv-ip'),
    ('https://feodotracker.abuse.ch/downloads/ipblocklist_recommended.txt', 'plain-ip'),
    ('https://feodotracker.abuse.ch/downloads/ipblocklist.txt', 'plain-ip'),
    ('https://urlhaus.abuse.ch/downloads/text/', 'plain-ip'),
    ('https://threatfox.abuse.ch/downloads/ip_port_ioc/', 'plain-ip'),

    # Emerging Threats
    ('https://rules.emergingthreats.net/blockrules/compromised-ips.txt', 'plain-ip'),
    ('https://rules.emergingthreats.net/fwrules/emerging-Block-IPs.txt', 'plain-ip'),

    # C2 Tracker (montysecurity)
    ('https://raw.githubusercontent.com/montysecurity/C2-Tracker/main/data/CobaltStrike.csv', 'plain-ip'),
    ('https://raw.githubusercontent.com/montysecurity/C2-Tracker/main/data/Sliver.csv', 'plain-ip'),
    ('https://raw.githubusercontent.com/montysecurity/C2-Tracker/main/data/Havoc.csv', 'plain-ip'),
    ('https://raw.githubusercontent.com/montysecurity/C2-Tracker/main/data/Metasploit.csv', 'plain-ip'),
    ('https://raw.githubusercontent.com/montysecurity/C2-Tracker/main/data/BruteRatel.csv', 'plain-ip'),
    ('https://raw.githubusercontent.com/montysecurity/C2-Tracker/main/data/AsyncRAT.csv', 'plain-ip'),
    ('https://raw.githubusercontent.com/montysecurity/C2-Tracker/main/data/Mythic.csv', 'plain-ip'),

    # Blocklist.de
    ('https://lists.blocklist.de/lists/all.txt', 'plain-ip'),
    ('https://lists.blocklist.de/lists/strongips.txt', 'plain-ip'),

    # DataPlane
    ('https://dataplane.org/sshclient.txt', 'pipe-ip'),
    ('https://dataplane.org/sshpwauth.txt', 'pipe-ip'),
    ('https://dataplane.org/dnsrd.txt', 'pipe-ip'),
    ('https://dataplane.org/vncrfb.txt', 'pipe-ip'),

    # Misc
    ('https://cinsscore.com/list/ci-badguys.txt', 'plain-ip'),
    ('https://blocklist.greensnow.co/greensnow.txt', 'plain-ip'),
    ('https://snort.org/downloads/ip-block-list', 'plain-ip'),
    ('https://cdn.ellio.tech/community-feed', 'plain-ip'),
    ('https://threatview.io/Downloads/IP-High-Confidence-Feed.txt', 'plain-ip'),
    ('https://raw.githubusercontent.com/stamparm/blackbook/master/blackbook.txt', 'plain-ip'),
    ('https://raw.githubusercontent.com/davidonzo/Threat-Intel/master/lists/latestips.txt', 'plain-ip'),
    ('https://www.botvrij.eu/data/blocklist/blocklist_ip.csv', 'csv-ip'),
    ('https://raw.githubusercontent.com/mitchellkrogza/Phishing.Database/master/phishing-IPs-ACTIVE.txt', 'plain-ip'),
    ('https://raw.githubusercontent.com/SecOps-Institute/Tor-IP-Addresses/master/tor-exit-nodes.lst', 'plain-ip'),
    ('https://raw.githubusercontent.com/hagezi/dns-blocklists/main/ips/tif.txt', 'plain-ip'),

    # Spamhaus
    ('https://raw.githubusercontent.com/firehol/blocklist-ipsets/master/spamhaus_drop.netset', 'plain-ip'),
    ('https://raw.githubusercontent.com/firehol/blocklist-ipsets/master/spamhaus_edrop.netset', 'plain-ip'),

    # Additional FireHOL curated
    ('https://raw.githubusercontent.com/firehol/blocklist-ipsets/master/cybercrime.ipset', 'plain-ip'),
    ('https://raw.githubusercontent.com/firehol/blocklist-ipsets/master/botscout_1d.ipset', 'plain-ip'),
    ('https://raw.githubusercontent.com/firehol/blocklist-ipsets/master/bruteforceblocker.ipset', 'plain-ip'),
    ('https://raw.githubusercontent.com/firehol/blocklist-ipsets/master/vxvault.ipset', 'plain-ip'),
    ('https://raw.githubusercontent.com/firehol/blocklist-ipsets/master/darklist_de.ipset', 'plain-ip'),
    ('https://raw.githubusercontent.com/firehol/blocklist-ipsets/master/normshield_all_attack.ipset', 'plain-ip'),
]

DOMAIN_FEEDS = [
    # Hagezi aggregated (THE big domain lists)
    ('https://raw.githubusercontent.com/hagezi/dns-blocklists/main/domains/tif.txt', 'plain-domain'),
    ('https://raw.githubusercontent.com/hagezi/dns-blocklists/main/domains/dga-7.txt', 'plain-domain'),
    ('https://raw.githubusercontent.com/hagezi/dns-blocklists/main/domains/dga-14.txt', 'plain-domain'),
    ('https://raw.githubusercontent.com/hagezi/dns-blocklists/main/domains/dga-30.txt', 'plain-domain'),
    ('https://raw.githubusercontent.com/hagezi/dns-blocklists/main/domains/nrd-7.txt', 'plain-domain'),
    ('https://raw.githubusercontent.com/hagezi/dns-blocklists/main/domains/nrd-14-8.txt', 'plain-domain'),
    ('https://raw.githubusercontent.com/hagezi/dns-blocklists/main/domains/nrd-21-15.txt', 'plain-domain'),
    ('https://raw.githubusercontent.com/hagezi/dns-blocklists/main/domains/nrd-28-22.txt', 'plain-domain'),

    # Abuse.ch
    ('https://threatfox.abuse.ch/downloads/hostfile/', 'hostfile'),
    ('https://urlhaus.abuse.ch/downloads/hostfile/', 'hostfile'),

    # Phishing
    ('https://phishing.army/download/phishing_army_blocklist_extended.txt', 'plain-domain'),
    ('https://openphish.com/feed.txt', 'url-domain'),
    ('https://raw.githubusercontent.com/mitchellkrogza/Phishing.Database/master/phishing-domains-ACTIVE.txt', 'plain-domain'),
    ('https://hole.cert.pl/domains/domains.txt', 'plain-domain'),

    # Block-list-project (pre-aggregated category lists)
    ('https://raw.githubusercontent.com/blocklistproject/Lists/master/malware.txt', 'plain-domain'),
    ('https://raw.githubusercontent.com/blocklistproject/Lists/master/phishing.txt', 'plain-domain'),
    ('https://raw.githubusercontent.com/blocklistproject/Lists/master/ransomware.txt', 'plain-domain'),
    ('https://raw.githubusercontent.com/blocklistproject/Lists/master/scam.txt', 'plain-domain'),
    ('https://raw.githubusercontent.com/blocklistproject/Lists/master/fraud.txt', 'plain-domain'),
    ('https://raw.githubusercontent.com/blocklistproject/Lists/master/abuse.txt', 'plain-domain'),
    ('https://raw.githubusercontent.com/blocklistproject/Lists/master/tracking.txt', 'plain-domain'),
    ('https://raw.githubusercontent.com/blocklistproject/Lists/master/crypto.txt', 'plain-domain'),

    # Malware filter (gitlab)
    ('https://malware-filter.gitlab.io/malware-filter/urlhaus-filter-domains.txt', 'plain-domain'),
    ('https://malware-filter.gitlab.io/malware-filter/phishing-filter-domains.txt', 'plain-domain'),
    ('https://malware-filter.gitlab.io/malware-filter/botnet-filter-domains.txt', 'plain-domain'),

    # ShadowWhisperer
    ('https://raw.githubusercontent.com/ShadowWhisperer/BlockLists/master/Lists/Malware', 'plain-domain'),
    ('https://raw.githubusercontent.com/ShadowWhisperer/BlockLists/master/Lists/Scam', 'plain-domain'),
    ('https://raw.githubusercontent.com/ShadowWhisperer/BlockLists/master/Lists/Tracking', 'plain-domain'),

    # UT1 (Université Toulouse)
    ('https://raw.githubusercontent.com/olbat/ut1-blacklists/master/blacklists/malware/domains', 'plain-domain'),
    ('https://raw.githubusercontent.com/olbat/ut1-blacklists/master/blacklists/phishing/domains', 'plain-domain'),
    ('https://raw.githubusercontent.com/olbat/ut1-blacklists/master/blacklists/cryptojacking/domains', 'plain-domain'),

    # Misc
    ('https://www.botvrij.eu/data/blocklist/blocklist_domain.csv', 'csv-domain'),
    ('https://threatview.io/Downloads/DOMAIN-High-Confidence-Feed.txt', 'plain-domain'),
    ('https://raw.githubusercontent.com/DandelionSprout/adfilt/master/Alternate%20versions%20Anti-Malware%20List/AntiMalwareHosts.txt', 'hostfile'),
    ('https://raw.githubusercontent.com/romainmarcoux/malicious-domains/main/full-domains-aa.txt', 'plain-domain'),
    ('https://raw.githubusercontent.com/Spam404/lists/master/main-blacklist.txt', 'plain-domain'),
    ('https://s3.amazonaws.com/lists.disconnect.me/simple_malware.txt', 'plain-domain'),
    ('https://raw.githubusercontent.com/durablenapkin/scamblocklist/master/hosts.txt', 'hostfile'),
    ('https://raw.githubusercontent.com/RPiList/specials/master/Blocklisten/malware', 'plain-domain'),
    ('https://gitlab.com/quidsup/notrack-blocklists/-/raw/master/notrack-malware.txt', 'plain-domain'),

    # Firebog curated
    ('https://v.firebog.net/hosts/Prigent-Malware.txt', 'plain-domain'),
    ('https://v.firebog.net/hosts/Prigent-Crypto.txt', 'plain-domain'),

    # C2 Tracker domains
    ('https://raw.githubusercontent.com/montysecurity/C2-Tracker/main/data/CobaltStrike_DNS.csv', 'plain-domain'),
    ('https://raw.githubusercontent.com/montysecurity/C2-Tracker/main/data/Havoc_DNS.csv', 'plain-domain'),
    ('https://raw.githubusercontent.com/montysecurity/C2-Tracker/main/data/Sliver_DNS.csv', 'plain-domain'),
]

HASH_FEEDS = [
    ('https://bazaar.abuse.ch/export/txt/sha256/recent/', 'hash'),
    ('https://threatfox.abuse.ch/export/csv/sha256/recent/', 'hash'),
    ('https://raw.githubusercontent.com/mstfknn/android-malware-sample-library/master/all-sha256.txt', 'hash'),
]

# Maltrail — mixed IPs + domains (malware families)
MALTRAIL_MALICIOUS = [
    'adwind', 'agent_tesla', 'amadey', 'android_anubis', 'android_cerberus',
    'android_flubot', 'android_godfather', 'android_hydra', 'android_joker',
    'android_medusa', 'android_octo', 'android_sharkbot', 'android_teabot',
    'android_vultur', 'asyncrat', 'azorult', 'babuk', 'bazarloader',
    'blackcat', 'cobalt_strike', 'conti', 'darkgate', 'dridex',
    'emotet', 'formbook', 'gandcrab', 'gootloader', 'icedid',
    'lockbit', 'lokibot', 'lumma', 'mirai', 'njrat',
    'pikabot', 'qakbot', 'raccoon', 'redline', 'remcos',
    'revil', 'ryuk', 'sliver', 'smoke_loader', 'stealc',
    'systembc', 'trickbot', 'vidar', 'xloader', 'zeus', 'zloader',
]

MALTRAIL_APT = [
    'apt28', 'apt29', 'apt41', 'carbanak', 'fancy_bear', 'fin7',
    'gamaredon', 'hafnium', 'kimsuky', 'lazarus', 'mustang_panda',
    'sandworm', 'scattered_spider', 'ta505', 'transparent_tribe', 'winnti',
]


def fetch(url):
    """Fetch a URL with timeout and retries."""
    for attempt in range(3):
        try:
            req = Request(url, headers={'User-Agent': 'Atlas-IOC-Aggregator/1.0'})
            with urlopen(req, timeout=TIMEOUT) as resp:
                return resp.read().decode('utf-8', errors='ignore')
        except Exception as e:
            if attempt == 2:
                log.warning(f'FAIL [{url}]: {e}')
                return ''
            time.sleep(1 * (attempt + 1))
    return ''


def parse_ips(text, parser='plain-ip'):
    """Extract IPs from text using the specified parser."""
    ips = set()
    for line in text.split('\n'):
        line = line.strip()
        if not line or line.startswith('#') or line.startswith(';') or line.startswith('//'):
            continue
        if parser == 'tab-ip':
            parts = line.split('\t')
            candidate = parts[0].strip()
        elif parser == 'pipe-ip':
            parts = line.split('|')
            if len(parts) >= 3:
                candidate = parts[2].strip()
            else:
                continue
        elif parser == 'csv-ip':
            parts = line.split(',')
            candidate = parts[0].replace('"', '').strip()
        else:  # plain-ip
            candidate = line.split()[0] if line.split() else ''

        # Extract IP, strip port if present
        candidate = candidate.split(':')[0].strip()
        m = IP_RE.match(candidate + ' ')
        if m:
            ip = m.group(1)
            # Validate octets
            octets = ip.split('.')
            if all(0 <= int(o) <= 255 for o in octets) and ip not in SAFE_IPS:
                ips.add(ip)
    return ips


def parse_domains(text, parser='plain-domain'):
    """Extract domains from text."""
    domains = set()
    for line in text.split('\n'):
        line = line.strip()
        if not line or line.startswith('#') or line.startswith(';') or line.startswith('//') or line.startswith('!'):
            continue

        if parser == 'hostfile':
            m = DOMAIN_RE.match(line)
            if m:
                domain = m.group(1).lower().strip()
            else:
                continue
        elif parser == 'csv-domain':
            parts = line.split(',')
            domain = parts[0].replace('"', '').strip().lower()
        elif parser == 'url-domain':
            # Extract domain from URL
            try:
                from urllib.parse import urlparse
                domain = urlparse(line if '://' in line else f'http://{line}').hostname or ''
                domain = domain.lower().strip()
            except:
                continue
        else:  # plain-domain
            domain = line.split()[0].lower().strip() if line.split() else ''

        # Validate domain
        if domain and PLAIN_DOMAIN_RE.match(domain) and domain not in SAFE_DOMAINS:
            if not any(domain.endswith('.' + s) for s in SAFE_DOMAINS):
                domains.add(domain)
    return domains


def parse_hashes(text):
    """Extract hashes from text."""
    hashes = set()
    for line in text.split('\n'):
        line = line.strip()
        if not line or line.startswith('#') or line.startswith(';') or line.startswith('"#'):
            continue
        # Try to find hash in the line (could be CSV, could be plain)
        for part in re.split(r'[,\s\t|"]+', line):
            part = part.strip()
            if HASH_RE.match(part):
                hashes.add(part.lower())
                break
    return hashes


def parse_mixed(text):
    """Parse Maltrail mixed format — lines can be IPs or domains."""
    ips = set()
    domains = set()
    for line in text.split('\n'):
        line = line.strip()
        if not line or line.startswith('#'):
            continue
        token = line.split()[0] if line.split() else ''
        token = token.split(':')[0]  # strip port (e.g. 1.2.3.4:8888)
        if IP_RE.match(token + ' '):
            octets = token.split('.')
            try:
                if all(0 <= int(o) <= 255 for o in octets) and token not in SAFE_IPS:
                    ips.add(token)
            except ValueError:
                continue
        elif PLAIN_DOMAIN_RE.match(token) and token not in SAFE_DOMAINS:
            domains.add(token.lower())
    return ips, domains


def main():
    all_ips = set()
    all_domains = set()
    all_hashes = set()
    stats = {'ip_feeds': 0, 'domain_feeds': 0, 'hash_feeds': 0, 'mixed_feeds': 0, 'failed': 0}

    # ─── IP FEEDS ─────────────────────────────────────────────────────────────
    log.info(f'Fetching {len(IP_FEEDS)} IP feeds...')
    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as pool:
        futures = {pool.submit(fetch, url): (url, parser) for url, parser in IP_FEEDS}
        for f in as_completed(futures):
            url, parser = futures[f]
            text = f.result()
            if text:
                ips = parse_ips(text, parser)
                all_ips.update(ips)
                stats['ip_feeds'] += 1
                log.info(f'  ✓ {len(ips):>6} IPs from {url.split("/")[-1][:40]}')
            else:
                stats['failed'] += 1

    # ─── DOMAIN FEEDS ─────────────────────────────────────────────────────────
    log.info(f'Fetching {len(DOMAIN_FEEDS)} domain feeds...')
    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as pool:
        futures = {pool.submit(fetch, url): (url, parser) for url, parser in DOMAIN_FEEDS}
        for f in as_completed(futures):
            url, parser = futures[f]
            text = f.result()
            if text:
                domains = parse_domains(text, parser)
                all_domains.update(domains)
                stats['domain_feeds'] += 1
                log.info(f'  ✓ {len(domains):>6} domains from {url.split("/")[-1][:40]}')
            else:
                stats['failed'] += 1

    # ─── HASH FEEDS ───────────────────────────────────────────────────────────
    log.info(f'Fetching {len(HASH_FEEDS)} hash feeds...')
    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as pool:
        futures = {pool.submit(fetch, url): (url,) for url, _ in HASH_FEEDS}
        for f in as_completed(futures):
            (url,) = futures[f]
            text = f.result()
            if text:
                hashes = parse_hashes(text)
                all_hashes.update(hashes)
                stats['hash_feeds'] += 1
                log.info(f'  ✓ {len(hashes):>6} hashes from {url.split("/")[-1][:40]}')
            else:
                stats['failed'] += 1

    # ─── MALTRAIL MIXED FEEDS ─────────────────────────────────────────────────
    maltrail_urls = []
    for name in MALTRAIL_MALICIOUS:
        maltrail_urls.append(f'https://raw.githubusercontent.com/stamparm/maltrail/master/trails/static/malicious/{name}.txt')
    for name in MALTRAIL_APT:
        maltrail_urls.append(f'https://raw.githubusercontent.com/stamparm/maltrail/master/trails/static/malicious/{name}.txt')

    log.info(f'Fetching {len(maltrail_urls)} Maltrail feeds...')
    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as pool:
        futures = {pool.submit(fetch, url): url for url in maltrail_urls}
        for f in as_completed(futures):
            url = futures[f]
            text = f.result()
            if text:
                ips, domains = parse_mixed(text)
                all_ips.update(ips)
                all_domains.update(domains)
                stats['mixed_feeds'] += 1
            else:
                stats['failed'] += 1

    # ─── WRITE OUTPUT ─────────────────────────────────────────────────────────
    sorted_ips = sorted(all_ips)
    sorted_domains = sorted(all_domains)
    sorted_hashes = sorted(all_hashes)

    with open('ips.txt', 'w') as f:
        f.write(f'# Atlas Shield IOC — Malicious IPs\n')
        f.write(f'# Generated: {time.strftime("%Y-%m-%d %H:%M UTC", time.gmtime())}\n')
        f.write(f'# Total: {len(sorted_ips)}\n')
        f.write(f'# Sources: {stats["ip_feeds"]} IP feeds + {stats["mixed_feeds"]} mixed feeds\n')
        f.write('\n'.join(sorted_ips) + '\n')

    with open('domains.txt', 'w') as f:
        f.write(f'# Atlas Shield IOC — Malicious Domains\n')
        f.write(f'# Generated: {time.strftime("%Y-%m-%d %H:%M UTC", time.gmtime())}\n')
        f.write(f'# Total: {len(sorted_domains)}\n')
        f.write(f'# Sources: {stats["domain_feeds"]} domain feeds + {stats["mixed_feeds"]} mixed feeds\n')
        f.write('\n'.join(sorted_domains) + '\n')

    with open('hashes.txt', 'w') as f:
        f.write(f'# Atlas Shield IOC — Malware Hashes\n')
        f.write(f'# Generated: {time.strftime("%Y-%m-%d %H:%M UTC", time.gmtime())}\n')
        f.write(f'# Total: {len(sorted_hashes)}\n')
        f.write(f'# Sources: {stats["hash_feeds"]} hash feeds\n')
        f.write('\n'.join(sorted_hashes) + '\n')

    # ─── SUMMARY ──────────────────────────────────────────────────────────────
    log.info('=' * 60)
    log.info(f'DONE — IPs: {len(sorted_ips):,}  Domains: {len(sorted_domains):,}  Hashes: {len(sorted_hashes):,}')
    log.info(f'Total IOCs: {len(sorted_ips) + len(sorted_domains) + len(sorted_hashes):,}')
    log.info(f'Feeds: {stats["ip_feeds"]} IP + {stats["domain_feeds"]} domain + {stats["hash_feeds"]} hash + {stats["mixed_feeds"]} mixed = {sum(stats.values()) - stats["failed"]} ok, {stats["failed"]} failed')
    log.info('=' * 60)


if __name__ == '__main__':
    main()
