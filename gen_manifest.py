#!/usr/bin/env python3
"""
Atlas Shield — feed manifest generator.

Runs right after aggregate.py. Writes manifest.json with a content hash + row
count for every output feed file, so the Atlas Shield app can skip feeds that
have not changed since its last sync: the app downloads this ~1 KB manifest
first, compares each file's hash against the one it stored last time, and only
re-downloads the (large) feed files whose hash actually changed.

IMPORTANT: the hash is computed over the IOC LINES ONLY — comment/header lines
(starting with '#') are excluded. The feed files carry a "# Generated: <time>"
header that changes on every run; hashing only the data lines keeps the hash
stable when the actual IOC content is unchanged day-to-day, which is what makes
the skip-unchanged optimization work.
"""
import glob
import hashlib
import json
import time

# Output files produced by aggregate.py (legacy plain domains.txt is excluded —
# the app downloads the numbered domains_N.txt chunks).
files = sorted(glob.glob('ips.txt') + glob.glob('domains_*.txt') + glob.glob('hashes.txt'))

manifest = {
    'generated_at': time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime()),
    'files': {},
}

for path in files:
    with open(path, 'r', encoding='utf-8', errors='ignore') as fh:
        lines = [ln.strip() for ln in fh]
    content = [ln for ln in lines if ln and not ln.startswith('#')]
    digest = hashlib.sha256('\n'.join(content).encode('utf-8')).hexdigest()
    manifest['files'][path] = {'sha256': digest, 'rows': len(content)}
    print(f'{path}: {len(content)} rows, sha256 {digest[:12]}...')

with open('manifest.json', 'w', encoding='utf-8') as fh:
    json.dump(manifest, fh, indent=2, sort_keys=True)

print(f'Wrote manifest.json ({len(manifest["files"])} files)')
