#!/usr/bin/env python3
"""Extract observed Cargo versions and verify their literals in the original ELF.

Reads local data only. It does not load native libraries, execute the APK, or
contact any network service. This is a partial version inventory, not Cargo.lock.
"""
from __future__ import annotations

from _paths import app_root, workspace_root

import hashlib
import json
import re
from pathlib import Path


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main() -> None:
    root = app_root()
    strings = root / 'analysis/native/librust_lib_distinguish/strings_utf8.json'
    library = root / 'unpacked/lib/arm64-v8a/librust_lib_distinguish.so'
    output = root / 'analysis/open_source/rust_crate_versions.json'
    blob = library.read_bytes()
    source_hash = sha256(strings)
    pattern = re.compile(
        r'registry[\\/]src[\\/][^\\/]+[\\/]'
        r'([A-Za-z0-9_-]+)-([0-9][^\\/\s]*)[\\/]'
    )
    pairs: dict[tuple[str, str], list[dict]] = {}
    for row in json.loads(strings.read_text(encoding='utf-8')):
        literal = row['text']
        matches = list(pattern.finditer(literal))
        if not matches:
            continue
        offset = row['offset']
        raw = literal.encode('utf-8')
        if blob[offset:offset + len(raw)] != raw:
            raise ValueError(f'Literal mismatch at ELF file offset {offset:#x}')
        for match in matches:
            pairs.setdefault((match[1], match[2]), []).append({
                'file': str(strings),
                'file_sha256': source_hash,
                'elf_file_offset': hex(offset),
                'literal': literal,
                'raw_bytes_match': True,
            })
    data = {
        'scope': 'Cargo crate versions observed in original Rust ELF build-path strings; not full Cargo.lock',
        'library': str(library),
        'library_sha256': hashlib.sha256(blob).hexdigest(),
        'crate_version_pairs': len(pairs),
        'crates': [{
            'name': name,
            'observed_version': version,
            'version_basis': 'embedded Cargo registry build path, not current upstream version',
            'evidence': evidence,
        } for (name, version), evidence in sorted(pairs.items())],
        'business_source_repo_established': False,
        'target_executed': False,
    }
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(data, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')
    print(json.dumps({
        'output': str(output),
        'crate_version_pairs': len(pairs),
        'verified_literals': sum(len(v) for v in pairs.values()),
        'library_sha256': data['library_sha256'],
    }, ensure_ascii=False))


if __name__ == '__main__':
    main()
