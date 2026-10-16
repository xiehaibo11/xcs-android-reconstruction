#!/usr/bin/env python3
"""Read a validated string sequence in this APK's arm64 Dart AOT snapshot.

The start and stop offsets were established from consecutive strings in this
specific libapp.so. This is a string extractor, not a Dart source decompiler.
"""

from _paths import app_root, workspace_root
import argparse
import json
import re
from pathlib import Path


def read_string(data, position):
    value = 0
    shift = 0
    for _ in range(5):
        byte = data[position]
        position += 1
        value |= (byte & 127) << shift
        if byte & 128:
            break
        shift += 7
    else:
        raise ValueError('Invalid string length prefix')
    length = value >> 1
    if length > 100000:
        raise ValueError('String length exceeds validated range')
    wide = bool(value & 1)
    encoding = 'utf-16-le' if wide else 'latin-1'
    size = length * (2 if wide else 1)
    text = data[position:position + size].decode(encoding)
    return {'offset': position, 'length': length, 'encoding': encoding, 'text': text}, position + size


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('library', type=Path)
    parser.add_argument('output', type=Path)
    parser.add_argument('--start', type=lambda s: int(s, 0), default=0x278c4)
    parser.add_argument('--stop', type=lambda s: int(s, 0), default=0xa0b79)
    args = parser.parse_args()
    data = args.library.read_bytes()
    position = args.start
    entries = []
    while position < args.stop:
        entry, next_position = read_string(data, position)
        if next_position > args.stop or next_position <= position:
            raise ValueError(f'String sequence boundary mismatch at {position:#x}')
        entries.append(entry)
        position = next_position
    args.output.mkdir(parents=True, exist_ok=True)
    def save(name, content):
        (args.output / name).write_text(json.dumps(content, ensure_ascii=False, indent=2), encoding='utf-8')
    save('snapshot_strings.json', entries)
    (args.output / 'snapshot_strings.txt').write_text(''.join(f"0x{x['offset']:x}\t{x['text']}\n" for x in entries), encoding='utf-8')
    packages = [x for x in entries if x['text'].startswith('package:distinguish/')]
    endpoints = [x for x in entries if x['text'].startswith('/api/') and not x['text'].endswith('.dart')]
    chinese = [x for x in entries if x['encoding']=='utf-16-le' and re.search('[\u4e00-\u9fff]', x['text']) and all(c.isprintable() or c in '\n\r\t' for c in x['text'])]
    save('application_packages.json', packages)
    save('api_candidates.json', {'evidence': 'Dart snapshot constants; HTTP methods and request schemas unverified', 'endpoints': endpoints})
    save('chinese_ui_strings.json', chinese)
    save('snapshot_extraction.json', {'start': args.start, 'stop': position, 'count': len(entries), 'packages':len(packages), 'api_candidates':len(endpoints), 'chinese_strings':len(chinese)})
    print(f'Parsed {len(entries)} strings; {len(packages)} application paths; {len(endpoints)} API candidates; {len(chinese)} Chinese strings')


if __name__ == '__main__':
    main()
