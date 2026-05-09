#!/usr/bin/env python3
"""
Atlas Shield IP-Owner Aggregator (v2.12)

Pulls public CIDR/range files from major cloud + hosting providers,
normalizes to (start_ip uint32, end_ip uint32, org_name) tuples,
writes ip-owners.csv at repo root.

Sister script to aggregate.py — that one builds threat IOC feeds (bad IPs,
domains, hashes); this one builds enrichment data (who owns each IP) so the
Atlas Shield app can show "Owner: Microsoft Azure" next to an alert IOC.

Each source is wrapped in try/except so one provider failing does not block
the others. The workflow's `continue-on-error` is the second line of defence;
this is the first. The aggregator only fails if ALL sources fail.

Runs daily via .github/workflows/ip-owners-aggregate.yml — Atlas Shield app
syncs the resulting CSV on its existing 12h IOC sync cycle.
"""

import csv
import ipaddress
import json
import logging
import re
import sys
import urllib.request
from typing import Iterable, List, Tuple

logging.basicConfig(level=logging.INFO, format='%(asctime)s %(levelname)s %(message)s')
log = logging.getLogger('ip-owners')

OUT_PATH = "ip-owners.csv"
USER_AGENT = "atlas-ioc-feeds-aggregator/1.0 (+https://github.com/shamah82-code/atlas-ioc-feeds)"
TIMEOUT = 60  # seconds per fetch


def fetch(url: str, headers: dict = None) -> bytes:
    req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT, **(headers or {})})
    with urllib.request.urlopen(req, timeout=TIMEOUT) as resp:
        return resp.read()


def fetch_json(url: str, headers: dict = None):
    return json.loads(fetch(url, headers).decode("utf-8"))


def fetch_text(url: str, headers: dict = None) -> str:
    return fetch(url, headers).decode("utf-8", errors="replace")


def cidr_to_range(cidr: str) -> Tuple[int, int]:
    net = ipaddress.ip_network(cidr.strip(), strict=False)
    return int(net.network_address), int(net.broadcast_address)


def cidrs_with_org(cidrs: Iterable[str], org: str) -> List[Tuple[int, int, str]]:
    out: List[Tuple[int, int, str]] = []
    for c in cidrs:
        c = c.strip()
        if not c or ":" in c:  # skip empties and IPv6 (we store IPv4 only for v2.12)
            continue
        try:
            start, end = cidr_to_range(c)
            out.append((start, end, org))
        except ValueError:
            continue
    return out


# ─── SOURCE PARSERS ────────────────────────────────────────────────────────────

def src_aws() -> List[Tuple[int, int, str]]:
    """AWS — stable JSON, multiple updates per week."""
    data = fetch_json("https://ip-ranges.amazonaws.com/ip-ranges.json")
    cidrs = [p["ip_prefix"] for p in data.get("prefixes", []) if p.get("ip_prefix")]
    return cidrs_with_org(cidrs, "Amazon AWS")


def src_google_cloud() -> List[Tuple[int, int, str]]:
    """Google Cloud — stable JSON."""
    data = fetch_json("https://www.gstatic.com/ipranges/cloud.json")
    cidrs = [p["ipv4Prefix"] for p in data.get("prefixes", []) if p.get("ipv4Prefix")]
    return cidrs_with_org(cidrs, "Google Cloud")


def src_google_services() -> List[Tuple[int, int, str]]:
    """Google global goog.json — Search/Gmail/YouTube edge IPs (different from Cloud)."""
    data = fetch_json("https://www.gstatic.com/ipranges/goog.json")
    cidrs = [p["ipv4Prefix"] for p in data.get("prefixes", []) if p.get("ipv4Prefix")]
    return cidrs_with_org(cidrs, "Google")


def src_cloudflare() -> List[Tuple[int, int, str]]:
    """Cloudflare — plain text, one CIDR per line."""
    text = fetch_text("https://www.cloudflare.com/ips-v4")
    cidrs = [line for line in text.splitlines() if line.strip() and not line.startswith("#")]
    return cidrs_with_org(cidrs, "Cloudflare")


def src_digitalocean() -> List[Tuple[int, int, str]]:
    """DigitalOcean — CSV with country/region columns."""
    text = fetch_text("https://www.digitalocean.com/geo/google.csv")
    cidrs: List[str] = []
    for row in csv.reader(text.splitlines()):
        if row and row[0].strip():
            cidrs.append(row[0])
    return cidrs_with_org(cidrs, "DigitalOcean")


def src_github() -> List[Tuple[int, int, str]]:
    """GitHub — public meta endpoint, returns CIDRs grouped by purpose."""
    data = fetch_json("https://api.github.com/meta")
    cidrs: List[str] = []
    for key in ("hooks", "web", "api", "git", "packages", "pages", "importer", "actions"):
        cidrs.extend(data.get(key, []) or [])
    return cidrs_with_org(cidrs, "GitHub")


def src_fastly() -> List[Tuple[int, int, str]]:
    """Fastly — stable JSON."""
    data = fetch_json("https://api.fastly.com/public-ip-list")
    cidrs = data.get("addresses", [])
    return cidrs_with_org(cidrs, "Fastly")


def src_oracle_cloud() -> List[Tuple[int, int, str]]:
    """Oracle Cloud Infrastructure — stable JSON, regions × CIDRs."""
    data = fetch_json("https://docs.oracle.com/en-us/iaas/tools/public_ip_ranges.json")
    cidrs: List[str] = []
    for region in data.get("regions", []):
        for cidr_obj in region.get("cidrs", []):
            cidr = cidr_obj.get("cidr") if isinstance(cidr_obj, dict) else cidr_obj
            if cidr:
                cidrs.append(cidr)
    return cidrs_with_org(cidrs, "Oracle Cloud")


def src_linode() -> List[Tuple[int, int, str]]:
    """Linode (Akamai) — CSV with country/region columns."""
    text = fetch_text("https://geoip.linode.com/")
    cidrs: List[str] = []
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        # CSV: ip_range,country,region,city,postal_code
        parts = line.split(",")
        if parts:
            cidrs.append(parts[0])
    return cidrs_with_org(cidrs, "Linode")


def src_microsoft_azure() -> List[Tuple[int, int, str]]:
    """Microsoft Azure ServiceTags — page-scrape for the weekly URL.

    This is the most fragile source: Microsoft hosts a new dated JSON every
    Monday and the only stable entry point is the download confirmation page,
    which we scrape for the actual download link. If MS restructures the page,
    this source will silently produce zero rows until updated. The aggregator
    keeps shipping; the app's "Unknown · search" fallback handles the gap.
    """
    page = fetch_text("https://www.microsoft.com/en-us/download/confirmation.aspx?id=56519")
    m = re.search(r'https://download\.microsoft\.com/download/[^"\']+ServiceTags_Public_\d+\.json', page)
    if not m:
        raise RuntimeError("Could not locate ServiceTags JSON URL on confirmation page")
    data = fetch_json(m.group(0))
    cidrs: List[str] = []
    for value in data.get("values", []):
        for prefix in (value.get("properties", {}) or {}).get("addressPrefixes", []):
            if prefix and ":" not in prefix:
                cidrs.append(prefix)
    return cidrs_with_org(cidrs, "Microsoft Azure")


# ─── AGGREGATOR ────────────────────────────────────────────────────────────────

SOURCES = [
    ("AWS",                src_aws),
    ("Google Cloud",       src_google_cloud),
    ("Google Services",    src_google_services),
    ("Cloudflare",         src_cloudflare),
    ("DigitalOcean",       src_digitalocean),
    ("GitHub",             src_github),
    ("Fastly",             src_fastly),
    ("Oracle Cloud",       src_oracle_cloud),
    ("Linode",             src_linode),
    ("Microsoft Azure",    src_microsoft_azure),
]

# When two sources claim the EXACT same (start_ip, end_ip) range, the org with
# the lowest priority number wins. Rationale: cloud providers OWN their IP
# blocks; some PaaS vendors publish the same blocks under their own name
# because they're hosted on the parent's infrastructure. The user wants to see
# the parent (e.g. "Microsoft Azure") not the child (e.g. "GitHub") because
# (a) it matches what they'd find via WHOIS, and (b) it makes false positives
# easier to recognize ("Outlook contacted Microsoft Azure" reads correctly;
# "Outlook contacted GitHub" looks alarming for the wrong reason).
#
# Lower number = wins. Unlisted orgs default to DEFAULT_PRIORITY.
ORG_PRIORITY = {
    "Microsoft Azure":  1,   # parent of GitHub-on-Azure ranges
    "Amazon AWS":       2,   # parent of any *-on-AWS publishers
    "Google Cloud":     3,   # parent of any *-on-GCP publishers
    "Cloudflare":       4,   # owns its own edge IPs
    "Oracle Cloud":     5,
    "Fastly":           6,   # CDN — owns its own edge IPs
    "DigitalOcean":     7,
    "Linode":           8,
    "Google":           9,   # general Google services edge (see goog.json)
    "GitHub":          10,   # often delegated from Microsoft Azure
}
DEFAULT_PRIORITY = 99


def dedupe_by_priority(rows: List[Tuple[int, int, str]]) -> List[Tuple[int, int, str]]:
    """Collapse exact (start, end) duplicates by ORG_PRIORITY (lowest wins)."""
    best: dict = {}  # (start, end) -> (priority, org)
    for start, end, org in rows:
        prio = ORG_PRIORITY.get(org, DEFAULT_PRIORITY)
        key = (start, end)
        if key not in best or prio < best[key][0]:
            best[key] = (prio, org)
    return [(start, end, org) for (start, end), (_, org) in best.items()]


def main() -> int:
    all_rows: List[Tuple[int, int, str]] = []
    failures = 0

    for name, fn in SOURCES:
        try:
            rows = fn()
            all_rows.extend(rows)
            log.info(f"  OK   {name:20} {len(rows):>6} ranges")
        except Exception as e:
            failures += 1
            log.warning(f"  FAIL {name:20} {type(e).__name__}: {e}")

    # Step 1: collapse exact (start, end) overlaps using ORG_PRIORITY
    deduped = dedupe_by_priority(all_rows)
    collapsed = len(all_rows) - len(deduped)
    log.info(f"Collapsed {collapsed:,} duplicate ranges via ORG_PRIORITY")

    # Step 2: sort by (start, end) so the SQLite index is in physical insert order
    unique = sorted(deduped, key=lambda r: (r[0], r[1]))

    with open(OUT_PATH, "w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(["start_ip", "end_ip", "org_name"])
        w.writerows(unique)

    log.info(f"Total unique ranges written: {len(unique):,} -> {OUT_PATH}")
    log.info(f"Sources OK: {len(SOURCES) - failures}/{len(SOURCES)}")

    # Workflow fails only if ALL sources fail. One bad source must not break the build.
    if failures == len(SOURCES):
        log.error("Every source failed. Refusing to write empty CSV.")
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
