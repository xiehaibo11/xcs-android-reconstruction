#!/usr/bin/env python3
"""Create and verify a complete, non-filtering APP workspace snapshot.

Regular-file hashes are calculated from the same reads supplied to tarfile.
Archive and original-source verification are independent subsequent passes.
No file is excluded, including hidden files and nested Git metadata.
"""
from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import json
import os
from pathlib import Path
import stat
import sys
import tarfile
import time

CHUNK = 1024 * 1024


def digest_file(path):
    h = hashlib.sha256()
    with open(path, "rb") as stream:
        for block in iter(lambda: stream.read(CHUNK), b""):
            h.update(block)
    return h.hexdigest()


def kind(mode):
    if stat.S_ISREG(mode):
        return "file"
    if stat.S_ISDIR(mode):
        return "directory"
    if stat.S_ISLNK(mode):
        return "symlink"
    if stat.S_ISFIFO(mode):
        return "fifo"
    if stat.S_ISCHR(mode):
        return "character-device"
    if stat.S_ISBLK(mode):
        return "block-device"
    if stat.S_ISSOCK(mode):
        return "socket"
    return "unknown"


def signature(s):
    return (s.st_mode, s.st_size, s.st_mtime_ns, s.st_ino, s.st_dev)


def inventory(source):
    result = {}

    def visit(path):
        s = path.lstat()
        rel = path.relative_to(source.parent).as_posix()
        result[rel] = (path, s)
        if stat.S_ISDIR(s.st_mode):
            with os.scandir(path) as entries:
                names = sorted(entry.name for entry in entries)
            for name in names:
                visit(path / name)

    visit(source)
    return result


class HashingReader:
    def __init__(self, stream):
        self.stream = stream
        self.hash = hashlib.sha256()
        self.bytes = 0

    def read(self, size=-1):
        block = self.stream.read(size)
        self.hash.update(block)
        self.bytes += len(block)
        return block


def write_json(path, obj):
    with open(path, "x", encoding="utf-8") as stream:
        json.dump(obj, stream, ensure_ascii=False, indent=2)
        stream.write("\n")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("source", type=Path)
    parser.add_argument("output", type=Path)
    args = parser.parse_args()
    source = args.source.resolve(strict=True)
    output = args.output.resolve()
    if not source.is_dir() or source.is_symlink():
        parser.error("Source must be a real directory")
    if output == source or source in output.parents:
        parser.error("Output must be outside the source tree")
    output.mkdir(parents=True, exist_ok=True)
    archive_path = output / (source.name + "-complete.tar.gz")
    manifest_path = output / "files.jsonl"
    summary_path = output / "snapshot.json"
    verification_path = output / "verification.json"
    for path in [archive_path, manifest_path, summary_path, verification_path]:
        if path.exists():
            parser.error("Refusing to overwrite existing output: " + str(path))

    started = time.time()
    records = []
    problems = []
    counts = {}
    total_bytes = 0
    before = inventory(source)
    print("Inventory: %d entries; excluding nothing" % len(before), flush=True)
    # tar has no portable representation for a live Unix-domain socket.
    # Refuse rather than silently omit or claim to preserve such an entry.
    unsupported = [rel for rel, (_, s) in before.items()
                   if kind(s.st_mode) in ("socket", "unknown")]
    if unsupported:
        write_json(verification_path, {
            "status": "FAIL", "stage": "inventory",
            "errors": [{"path": rel, "error": "Unsupported special entry; no omission allowed"}
                       for rel in unsupported]})
        return 1

    with open(manifest_path, "x", encoding="utf-8") as manifest:
        with tarfile.open(archive_path, "x:gz", compresslevel=1,
                          format=tarfile.PAX_FORMAT, dereference=False) as archive:
            for index, (rel, (path, initial)) in enumerate(before.items(), 1):
                current = path.lstat()
                if signature(current) != signature(initial):
                    problems.append({"stage": "archive-write", "path": rel,
                                     "error": "Source metadata changed after initial inventory"})
                entry_kind = kind(current.st_mode)
                info = archive.gettarinfo(str(path), arcname=rel)
                record = {
                    "path": rel, "type": entry_kind,
                    "bytes": current.st_size if entry_kind == "file" else 0,
                    "mode": stat.S_IMODE(current.st_mode),
                    "mode_octal": format(stat.S_IMODE(current.st_mode), "04o"),
                    "mtime_ns": current.st_mtime_ns,
                    "uid": current.st_uid, "gid": current.st_gid,
                }
                if entry_kind == "file":
                    # Materialize each hard-linked file so every listed hash is
                    # bound to the actual bytes stored for that exact path.
                    info.type = tarfile.REGTYPE
                    info.linkname = ""
                    info.size = current.st_size
                    with open(path, "rb") as source_stream:
                        reader = HashingReader(source_stream)
                        archive.addfile(info, reader)
                        if reader.bytes != current.st_size:
                            raise RuntimeError("Wrong archived byte count: " + rel)
                        record["sha256"] = reader.hash.hexdigest()
                        if source_stream.read(1):
                            problems.append({"stage": "archive-write", "path": rel,
                                             "error": "Source grew during read"})
                    total_bytes += reader.bytes
                elif entry_kind == "symlink":
                    target = os.readlink(path)
                    record["link_target"] = target
                    record["link_target_sha256"] = hashlib.sha256(os.fsencode(target)).hexdigest()
                    archive.addfile(info)
                else:
                    if entry_kind in ("character-device", "block-device"):
                        record["device_major"] = os.major(current.st_rdev)
                        record["device_minor"] = os.minor(current.st_rdev)
                    archive.addfile(info)
                if signature(path.lstat()) != signature(current):
                    problems.append({"stage": "archive-write", "path": rel,
                                     "error": "Source metadata changed while writing"})
                counts[entry_kind] = counts.get(entry_kind, 0) + 1
                records.append(record)
                manifest.write(json.dumps(record, ensure_ascii=False, separators=(",", ":")) + "\n")
                if index % 2000 == 0:
                    print("Archived %d/%d entries, %d bytes" % (index, len(before), total_bytes), flush=True)

    print("Archive complete; verifying every stored member", flush=True)
    expected = {record["path"]: record for record in records}
    seen = set()
    archive_files = 0
    archive_bytes = 0
    with tarfile.open(archive_path, "r|gz") as archive:
        for member in archive:
            rel = member.name.rstrip("/")
            if rel in seen:
                problems.append({"stage": "archive-verify", "path": rel, "error": "Duplicate member"})
            seen.add(rel)
            record = expected.get(rel)
            if record is None:
                problems.append({"stage": "archive-verify", "path": rel, "error": "Unexpected member"})
                continue
            actual_kind = ("file" if member.isfile() else "directory" if member.isdir()
                           else "symlink" if member.issym() else "fifo" if member.isfifo()
                           else "character-device" if member.ischr()
                           else "block-device" if member.isblk() else "unknown")
            if actual_kind != record["type"] or member.mode != record["mode"]:
                problems.append({"stage": "archive-verify", "path": rel, "error": "Type or mode mismatch"})
            if actual_kind == "file":
                stream = archive.extractfile(member)
                h = hashlib.sha256()
                length = 0
                for block in iter(lambda: stream.read(CHUNK), b""):
                    h.update(block)
                    length += len(block)
                if length != record["bytes"] or h.hexdigest() != record["sha256"]:
                    problems.append({"stage": "archive-verify", "path": rel, "error": "Content mismatch"})
                archive_files += 1
                archive_bytes += length
            elif actual_kind == "symlink" and member.linkname != record["link_target"]:
                problems.append({"stage": "archive-verify", "path": rel, "error": "Symlink target mismatch"})
            elif actual_kind in ("character-device", "block-device"):
                if member.devmajor != record["device_major"] or member.devminor != record["device_minor"]:
                    problems.append({"stage": "archive-verify", "path": rel, "error": "Device number mismatch"})
    for rel in sorted(set(expected) - seen):
        problems.append({"stage": "archive-verify", "path": rel, "error": "Missing member"})

    print("Archive members verified; checking source hashes and path set", flush=True)
    after = inventory(source)
    for rel in sorted(set(before) ^ set(after)):
        problems.append({"stage": "source-verify", "path": rel, "error": "Source path set changed"})
    source_files = 0
    source_bytes = 0
    for index, (rel, record) in enumerate(expected.items(), 1):
        if rel not in after:
            continue
        path, current = after[rel]
        if signature(current) != signature(before[rel][1]):
            problems.append({"stage": "source-verify", "path": rel, "error": "Source metadata changed"})
        if kind(current.st_mode) != record["type"]:
            problems.append({"stage": "source-verify", "path": rel, "error": "Source type changed"})
            continue
        if record["type"] == "file":
            source_hash = digest_file(path)
            if current.st_size != record["bytes"] or source_hash != record["sha256"]:
                problems.append({"stage": "source-verify", "path": rel, "error": "Source content changed"})
            source_files += 1
            source_bytes += current.st_size
        elif record["type"] == "symlink" and os.readlink(path) != record["link_target"]:
            problems.append({"stage": "source-verify", "path": rel, "error": "Source symlink changed"})
        if index % 5000 == 0:
            print("Source verified %d/%d entries" % (index, len(expected)), flush=True)
    final_paths = inventory(source)
    for rel in sorted(set(after) ^ set(final_paths)):
        problems.append({"stage": "source-verify", "path": rel, "error": "Source path set changed during verification"})
    for rel in set(after) & set(final_paths):
        if signature(after[rel][1]) != signature(final_paths[rel][1]):
            problems.append({"stage": "source-verify", "path": rel, "error": "Source metadata changed during verification"})

    archive_hash = digest_file(archive_path)
    status = "PASS" if not problems else "FAIL"
    summary = {
        "status": status,
        "created_at_utc": dt.datetime.now(dt.timezone.utc).isoformat(),
        "source": str(source), "archive_root": source.name,
        "exclusions": [], "public_subtree_included": True,
        "hidden_files_included": True, "embedded_git_metadata_included": True,
        "archive": {"filename": archive_path.name, "bytes": archive_path.stat().st_size,
                    "sha256": archive_hash, "format": "PAX tar + gzip", "gzip_level": 1},
        "manifest": {"filename": manifest_path.name, "bytes": manifest_path.stat().st_size,
                     "sha256": digest_file(manifest_path), "entries": len(records)},
        "counts": counts, "regular_file_bytes": total_bytes,
        "snapshot_script_sha256": digest_file(Path(__file__)),
        "elapsed_seconds": round(time.time() - started, 3),
    }
    verification = {
        "status": status,
        "archive_members_equal_manifest": seen == set(expected),
        "archive_member_hashes_checked": archive_files,
        "archive_member_bytes_checked": archive_bytes,
        "source_file_hashes_checked": source_files,
        "source_file_bytes_checked": source_bytes,
        "source_path_sets_unchanged": set(before) == set(after) == set(final_paths),
        "archive_sha256": archive_hash,
        "errors": problems,
    }
    write_json(summary_path, summary)
    write_json(verification_path, verification)
    print(json.dumps(summary, ensure_ascii=False, indent=2), flush=True)
    print("Verification %s: %d errors" % (status, len(problems)), flush=True)
    return 0 if not problems else 1


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except Exception as error:
        print("Snapshot failed: %s: %s" % (type(error).__name__, error), file=sys.stderr)
        raise
