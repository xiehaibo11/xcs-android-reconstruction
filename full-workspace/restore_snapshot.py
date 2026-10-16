#!/usr/bin/env python3
"""Verify and concatenate a complete workspace snapshot using only stdlib.

Run from any working directory:
  python3 full-workspace/restore_snapshot.py --output /path/APP-complete.tar.gz

This reconstructs the archive; it does not extract the archived files.
Part paths are resolved relative to parts.json and cannot escape its directory.
The output must not already exist. Failed restores remove the temporary file.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import sys
import tempfile

BLOCK_SIZE = 1024 * 1024
SHA256_PATTERN = re.compile(r"[0-9a-f]{64}")


def safe_part_path(base: Path, raw: str) -> Path:
    if not isinstance(raw, str) or not raw or "\\" in raw or ":" in raw:
        raise ValueError("Invalid part path")
    components = raw.split("/")
    if any(component in ("", ".", "..") for component in components):
        raise ValueError("Part path traversal or empty component rejected")
    path = PurePosixPath(raw)
    if path.is_absolute():
        raise ValueError("Absolute part path rejected")
    result = (base / Path(*path.parts)).resolve(strict=True)
    if result == base or base not in result.parents:
        raise ValueError("Part path escapes manifest directory")
    if not result.is_file():
        raise ValueError("Part path is not a regular file")
    return result


def checked_hash(value, label):
    if not isinstance(value, str) or SHA256_PATTERN.fullmatch(value) is None:
        raise ValueError("Invalid SHA-256 for " + label)
    return value


def checked_length(value, label):
    if type(value) is not int or value < 0:
        raise ValueError("Invalid byte length for " + label)
    return value


def restore(manifest_path: Path, output: Path | None) -> tuple[Path, int, str]:
    manifest_path = manifest_path.resolve(strict=True)
    base = manifest_path.parent
    with open(manifest_path, encoding="utf-8") as stream:
        manifest = json.load(stream)
    if manifest.get("format_version") != 1:
        raise ValueError("Unsupported parts manifest version")
    archive = manifest["archive"]
    filename = archive["filename"]
    if not isinstance(filename, str) or filename in ("", ".", "..") or any(c in filename for c in "/\\:"):
        raise ValueError("Invalid archive filename")
    expected_bytes = checked_length(archive["bytes"], "archive")
    expected_hash = checked_hash(archive["sha256"], "archive")
    parts = manifest["parts"]
    if not isinstance(parts, list) or not parts:
        raise ValueError("No parts listed")
    seen = set()
    inputs = []
    for index, part in enumerate(parts):
        if part.get("index") != index:
            raise ValueError("Parts must have contiguous ordered indices")
        path = safe_part_path(base, part["path"])
        if path in seen:
            raise ValueError("Duplicate part path")
        seen.add(path)
        size = checked_length(part["bytes"], "part %d" % index)
        digest = checked_hash(part["sha256"], "part %d" % index)
        inputs.append((index, path, size, digest))
    if sum(item[2] for item in inputs) != expected_bytes:
        raise ValueError("Part lengths do not sum to archive length")

    output = (base / filename if output is None else output).expanduser().absolute()
    if output.exists() or output.is_symlink():
        raise FileExistsError("Refusing to overwrite existing output: " + str(output))
    if not output.parent.is_dir():
        raise FileNotFoundError("Output parent directory does not exist: " + str(output.parent))
    temporary = None
    archive_hash = hashlib.sha256()
    total = 0
    try:
        with tempfile.NamedTemporaryFile(mode="wb", prefix="." + output.name + ".partial-",
                                         dir=output.parent, delete=False) as destination:
            temporary = Path(destination.name)
            for index, path, expected_part_bytes, expected_part_hash in inputs:
                part_hash = hashlib.sha256()
                part_bytes = 0
                with open(path, "rb") as source:
                    for block in iter(lambda: source.read(BLOCK_SIZE), b""):
                        destination.write(block)
                        part_hash.update(block)
                        archive_hash.update(block)
                        part_bytes += len(block)
                        total += len(block)
                if part_bytes != expected_part_bytes or part_hash.hexdigest() != expected_part_hash:
                    raise ValueError("Part verification failed: index %d" % index)
                print("Verified part %d/%d: %d bytes" % (index + 1, len(inputs), part_bytes), flush=True)
            actual_hash = archive_hash.hexdigest()
            if total != expected_bytes or actual_hash != expected_hash:
                raise ValueError("Restored archive length or SHA-256 mismatch")
            destination.flush()
            os.fsync(destination.fileno())
        # Atomically publish without overwriting. Unlike os.replace/rename on
        # POSIX, link fails if another process created the output meanwhile.
        os.link(temporary, output)
        temporary.unlink()
        temporary = None
        return output, total, actual_hash
    finally:
        if temporary is not None:
            try:
                temporary.unlink()
            except FileNotFoundError:
                pass


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path,
                        help="New archive output path; refuses to overwrite an existing path")
    parser.add_argument("--manifest", type=Path,
                        default=Path(__file__).resolve().parent / "parts.json",
                        help="Parts manifest (default: next to this script)")
    args = parser.parse_args()
    try:
        output, size, digest = restore(args.manifest, args.output)
    except (OSError, ValueError, KeyError, TypeError) as error:
        print("Restore failed: %s" % error, file=sys.stderr)
        return 1
    print("PASS: %s\nBytes: %d\nSHA256: %s" % (output, size, digest))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
