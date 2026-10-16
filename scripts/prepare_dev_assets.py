#!/usr/bin/env python3
"""Generate a local RSA fixture pair. Private/public key files are never source inputs.

The public repository deliberately contains no original application key. A fresh
pair is generated once per checkout for loopback fixtures. Existing matching keys
are retained, so rebuilding does not invalidate an already running fixture server.
"""
from pathlib import Path
import fcntl
import json
import os
import shutil
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[1]
KEY_DIR = ROOT / 'app/src/main/assets/key'
PRIVATE_NAME = 'private_key.pem'
PUBLIC_NAME = 'pub_key.pem'

def openssl(*args):
    binary = shutil.which('openssl')
    if not binary:
        raise RuntimeError('OpenSSL is required to prepare local RSA fixture assets.')
    result = subprocess.run([binary, *map(str, args)], capture_output=True)
    if result.returncode:
        # Do not echo key contents or command output into public build reports.
        raise RuntimeError('OpenSSL failed while preparing local RSA fixture assets.')
    return result.stdout

def _prepare_locked():
    KEY_DIR.mkdir(parents=True, exist_ok=True)
    private = KEY_DIR / PRIVATE_NAME
    public = KEY_DIR / PUBLIC_NAME
    if private.exists() != public.exists():
        raise RuntimeError('Incomplete local RSA pair: move both key PEM files aside and prepare again.')
    if private.exists():
        expected = openssl('pkey', '-in', private, '-pubout', '-outform', 'DER')
        observed = openssl('pkey', '-pubin', '-in', public, '-pubout', '-outform', 'DER')
        if expected != observed:
            raise RuntimeError('Local private/public RSA assets do not match.')
        return {'status': 'READY', 'generated': False, 'scope': 'local fixture assets; excluded from source distribution'}
    with tempfile.TemporaryDirectory(prefix='.prepare-', dir=KEY_DIR) as temporary:
        staging = Path(temporary)
        draft_private = staging / PRIVATE_NAME
        draft_public = staging / PUBLIC_NAME
        openssl('genpkey', '-algorithm', 'RSA', '-pkeyopt', 'rsa_keygen_bits:2048', '-out', draft_private)
        os.chmod(draft_private, 0o600)
        openssl('pkey', '-in', draft_private, '-pubout', '-out', draft_public)
        draft_private.replace(private)
        draft_public.replace(public)
    report = {'status': 'READY', 'generated': True, 'algorithm': 'RSA-2048',
              'scope': 'fresh local development fixture pair; no original application keys'}
    output = ROOT / 'build/dev-assets.json'
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(report, indent=2) + '\n')
    return report

def prepare():
    # Serialize concurrent Gradle, SDK and fixture invocations so a pair cannot
    # be assembled from two independent first-run generations.
    lock_path = ROOT / 'build/.dev-assets.lock'
    lock_path.parent.mkdir(parents=True, exist_ok=True)
    with lock_path.open('a') as lock:
        fcntl.flock(lock, fcntl.LOCK_EX)
        return _prepare_locked()

if __name__ == '__main__':
    print(json.dumps(prepare()))
