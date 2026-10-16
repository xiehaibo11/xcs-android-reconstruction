#!/usr/bin/env python3
"""Offline static image-codec evidence generator; never executes the target.

Reads local AOT/ELF and already fetched official SDK reference snapshots.
LLVM only disassembles bytes. Synthetic inputs are created here and passed to
our own reconstructed Python codec, never to APK/native code or a server.
"""

from _paths import app_root, workspace_root
import base64
import hashlib
import importlib.util
import json
import re
import struct
import subprocess
import sys
import zlib
from pathlib import Path

APP = app_root()
OUT = APP / "analysis/image_codec"
AOT = APP / "analysis/aot_dump"
LIB = APP / "unpacked/lib/arm64-v8a/libapp.so"
LLVM = Path("/opt/homebrew/opt/llvm/bin/llvm-objdump")
INPUTS = {}
EVIDENCE = {}


def digest(data):
    return hashlib.sha256(data).hexdigest()


def read(path):
    data = path.read_bytes()
    INPUTS[str(path)] = digest(data)
    return data.decode("utf-8")


def ref(path, needle, occurrence=0):
    lines = read(path).splitlines()
    hits = [(i, s) for i, s in enumerate(lines, 1) if needle in s]
    assert len(hits) > occurrence, (str(path), needle)
    line, excerpt = hits[occurrence]
    return {"file": str(path), "line": line, "excerpt": excerpt.strip(),
            "sha256": INPUTS[str(path)]}


def following_ref(path, needle, offset=1):
    entry = ref(path, needle)
    entry["line"] += offset
    entry["excerpt"] = read(path).splitlines()[entry["line"] - 1].strip()
    return entry


def write_json(name, value):
    # ASCII encoding also faithfully displays isolated UTF-16 surrogate tests.
    (OUT / name).write_text(json.dumps(value, ensure_ascii=True, indent=2) + "\n")


def va_offset(data, address):
    phoff = struct.unpack_from("<Q", data, 32)[0]
    entsize, count = struct.unpack_from("<HH", data, 54)
    for i in range(count):
        typ, _, off, va, _, size, _, _ = struct.unpack_from("<IIQQQQQQ", data, phoff + i * entsize)
        if typ == 1 and va <= address < va + size:
            return off + address - va
    raise ValueError(hex(address))


def main():
    OUT.mkdir(parents=True, exist_ok=True)
    data = LIB.read_bytes()
    INPUTS[str(LIB)] = digest(data)
    ranges = [
        ("configuration_base64_rsa_json_and_string_assignments", 0x4923fc, 0x492504),
        ("decode_data_complete", 0x528074, 0x5281d8),
        ("http_cache_and_url_request", 0x528330, 0x5287e8),
        ("http_response_restore_decode_and_write", 0x5291a4, 0x5292d4),
        ("get_image_url_complete", 0x528820, 0x5288c4),
        ("frame_decode_data_calls", 0x5275bc, 0x5276f4),
        ("preview_jpeg_to_png_and_image_memory", 0x463e98, 0x463f1c),
        ("base64_codec_decode", 0x486ea8, 0x486edc),
        ("string_replace_all_entry", 0x2c7a2c, 0x2c7b30),
        ("base64_decoder_convert_entry", 0x5e00ac, 0x5e01c8),
        ("rsa_padding_instantiation", 0x49bc8c, 0x49bcc4),
    ]
    chunks = []
    for label, start, end in ranges:
        output = subprocess.run([str(LLVM), "-D", f"--start-address={hex(start)}",
                                 f"--stop-address={hex(end)}", str(LIB)],
                                check=True, text=True, capture_output=True).stdout
        chunks.append(f"// RANGE {label}: ELF VA {hex(start)}..{hex(end)} exclusive\n" + output)
    raw = OUT / "raw_image_instructions.asm.txt"
    raw.write_text("\n".join(chunks))
    raw_text = read(raw)
    raw_hits = {}
    for hit in re.finditer(r"^\s*([0-9a-f]+):\s+([0-9a-f]{8})\s+(.+)$", raw_text, re.M):
        address, word = int(hit[1], 16), int(hit[2], 16)
        offset = va_offset(data, address)
        assert word == struct.unpack_from("<I", data, offset)[0], hex(address)
        raw_hits[address] = (hit, offset)
    expected_count = sum((end - start) // 4 for _, start, end in ranges)
    assert len(raw_hits) == expected_count, (len(raw_hits), expected_count)
    raw_entries = []

    def rawref(address, bl_target=None):
        hit, offset = raw_hits[address]
        entry = ref(raw, hit[0].strip())
        word = int(hit[2], 16)
        entry.update(elf_virtual_address=hex(address), file_offset=hex(offset),
                     raw_bytes_hex=data[offset:offset + 4].hex(),
                     instruction_word_hex=f"{word:08x}")
        if bl_target is not None:
            assert word & 0xFC000000 == 0x94000000
            imm = word & 0x3FFFFFF
            if imm & 0x2000000:
                imm -= 0x4000000
            actual = address + imm * 4
            assert actual == bl_target, (hex(address), hex(actual), hex(bl_target))
            entry["bl_target"] = hex(actual)
        raw_entries.append(entry)
        return entry

    utils = AOT / "asm/distinguish/common/utils.dart"
    login = AOT / "asm/distinguish/pages/login/login_page.dart"
    mainpage = AOT / "asm/distinguish/pages/main/main_page.dart"
    preview = AOT / "asm/distinguish/pages/frame_preview/frame_preview_page.dart"
    urlfn = AOT / "asm/distinguish/common/function.dart"
    encrypt = AOT / "asm/encrypt/encrypt.dart"
    std = OUT / "standard_reference"
    string = std / "dart_3_5_2_string_patch.dart"
    b64 = std / "dart_3_5_2_base64.dart"
    date = std / "dart_3_5_2_date_patch.dart"
    filemode = std / "dart_3_5_2_file.dart"

    def add(name, meaning, refs, confidence="confirmed_static"):
        EVIDENCE[name] = {"claim": meaning, "confidence": confidence, "references": refs}

    add("rules_configuration", "Response msg is Base64 decoded, RSA decrypted, jsonDecoded; consumes index0 host and index1 String rules. No local runtime rule value is available.",
        [ref(login, "0x492404: bl"), rawref(0x492404, 0x486ea8),
         ref(login, "0x492424: bl"), rawref(0x492424, 0x493be4),
         ref(login, "0x49242c: bl"), rawref(0x49242c, 0x493ba4),
         ref(login, "0x492434: stp"), rawref(0x492434),
         ref(login, "0x492494: str"), rawref(0x492494),
         ref(login, "0x49249c: mov"), rawref(0x49249c),
         ref(login, "0x4924a0: stp"), rawref(0x4924a0),
         ref(login, "0x4924f4: bl"), rawref(0x4924f4, 0x6ff6c8),
         ref(login, "0x492500: str"), rawref(0x492500),
         ref(utils, "0x528098: ldr"), rawref(0x528098)])
    add("upstream_rsa_is_separate", "Upstream configuration decryption instantiates RSAEngine/PKCS1Encoding. decode_data itself is ordered literal substitution, not this RSA operation.",
        [ref(encrypt, "0x49bc8c: bl"), rawref(0x49bc8c, 0x49bd04),
         ref(encrypt, "0x49bcac: bl"), rawref(0x49bcac, 0x49bcf8)])
    add("rule_order_and_delimiters", "Split rules by literal |, iterate forward, split each segment by literal comma, feed each result into the next iteration.",
        [ref(utils, '0x5280a4: r2 = "|"'), ref(utils, "0x5280b4: blr"), rawref(0x5280b4),
         ref(utils, "0x528120: add"), rawref(0x528120),
         ref(utils, '0x528130: r2 = ","'), ref(utils, "0x52813c: blr"), rawref(0x52813c),
         ref(utils, "0x52818c: b "), rawref(0x52818c)])
    add("replacement_direction_and_arity", "pair[1] loads into x2 search, pair[0] into x3 replacement, x1 current String; only pair.length >=2 checked; additional fields ignored.",
        [ref(utils, "0x528150: mov"), rawref(0x528150),
         ref(utils, "0x528158: b.hs"), rawref(0x528158),
         ref(utils, "0x528164: ldur"), rawref(0x528164),
         ref(utils, "0x52816c: ldur"), rawref(0x52816c),
         ref(utils, "0x528174: ldur"), rawref(0x528174),
         ref(utils, "0x528178: bl"), rawref(0x528178, 0x2c7a2c),
         ref(utils, "0x52817c: mov"), rawref(0x52817c),
         ref(utils, "0x5281d4: bl")])
    add("dart_string_semantics", "Dart 3.5.2 VM String matching is literal, nonoverlapping over UTF16 code units; empty matches advance one code unit. No trim/regex/escape handling is added by decode_data.",
        [ref(string, "String replaceAll(Pattern pattern, String replacement)"),
         ref(string, "for (Match match in pattern.allMatches(this))", 1),
         ref(string, "int end = index + _pattern.length"),
         ref(string, "if (end == _index) end++"),
         ref(string, "List<String> split(Pattern pattern)", 1),
         ref(string, "parts.add(this._substringUnchecked(start, i))")],
        "official_versioned_reference_plus_matching_local_call")
    add("http_response_chain", "HTTP response data field is cast to String ->decode_data ->Base64Codec.decode ->writeAsBytesSync, with no image decoder/PNG encoder in this segment.",
        [ref(mainpage, "0x5291a8: ldur"), rawref(0x5291a8),
         ref(mainpage, "0x5291e8: bl"), rawref(0x5291e8, 0x6ff6c8),
         ref(mainpage, "0x5291f0: bl"), rawref(0x5291f0, 0x528074),
         ref(mainpage, "0x5291fc: bl"), rawref(0x5291fc, 0x486ea8),
         ref(mainpage, "0x5292d0: bl"), rawref(0x5292d0, 0x48c9fc)])
    add("http_cache_shape", "Temporary directory/cacheImg/unpadded local year month day/unpadded random integer 0<=n<1000000.png; recursive directory creation; conditional file creation; mode index3 is writeOnly overwrite.",
        [ref(mainpage, "0x5284d0: bl"), rawref(0x5284d0, 0x452dac),
         ref(mainpage, "0x5284f0: mov"), rawref(0x5284f0), rawref(0x5284f4),
         ref(mainpage, "0x5284f8: bl"), rawref(0x5284f8, 0x528d70),
         ref(mainpage, '0x52854c: r16 = ".png"'),
         ref(mainpage, "0x5285c0: mov"), rawref(0x5285c0),
         ref(mainpage, "0x52860c: mov"), rawref(0x52860c),
         ref(mainpage, "0x528660: mov"), rawref(0x528660),
         ref(date, "static const _YEAR_INDEX = 8"),
         ref(date, "static const _MONTH_INDEX = 7"), ref(date, "static const _DAY_INDEX = 5"),
         ref(mainpage, '0x5286a8: r16 = "/cacheImg/"'),
         ref(mainpage, "0x528770: bl"), rawref(0x528770),
         ref(mainpage, "0x528788: bl"), rawref(0x528788),
         ref(mainpage, "0x5292b4: bl"), rawref(0x5292b4),
         ref(mainpage, "0x5292c8: ldr"), rawref(0x5292c8),
         ref(AOT / "objs.txt", "Obj!FileMode@750cf1"),
         following_ref(AOT / "objs.txt", "Obj!FileMode@750cf1"),
         ref(AOT / "pp.txt", "[pp+0x2f28] Obj!FileMode@750cf1"),
         following_ref(AOT / "pp.txt", "[pp+0x2f28] Obj!FileMode@750cf1"),
         ref(filemode, "static const writeOnly = const FileMode._internal(3)")])
    add("url_construction_and_placeholder", "getImgUrl returns String beginning http:// or https:// unchanged, otherwise http://host/img; placeholder img=x chooses bundled empty.jpg and bypasses HTTP branch.",
        [ref(urlfn, "0x528850: bl"), rawref(0x528850, 0x2c0ec0),
         ref(urlfn, "0x528868: bl"), rawref(0x528868, 0x2c0ec0),
         ref(urlfn, "0x528884: ldr"), rawref(0x528884),
         ref(urlfn, '0x528898: r16 = "/"'),
         ref(mainpage, "0x528798: bl"), rawref(0x528798, 0x528820),
         ref(mainpage, "0x5287a8: bl"), rawref(0x5287a8, 0x457e8c),
         ref(mainpage, '0x528338: r16 = "x"'),
         ref(mainpage, '0x528380: r3 = "images/other/empty.jpg"')])
    add("preview_pipeline_distinction", "msg_type102 invokes the same rules for framed/unframed content; preview reads restored Base64 and explicitly decodeJpg ->encodePng ->Image.memory. It is distinct from HTTP image disk cache.",
        [ref(mainpage, "0x5276b8: bl"), rawref(0x5276b8, 0x528074),
         ref(mainpage, "0x5276e4: bl"), rawref(0x5276e4, 0x528074),
         ref(preview, "0x463eac: bl"), rawref(0x463eac, 0x486e74),
         ref(preview, "0x463eb4: bl"), rawref(0x463eb4, 0x47ac6c),
         ref(preview, "0x463f00: bl"), rawref(0x463f00, 0x464018),
         ref(preview, "0x463f18: bl"), rawref(0x463f18, 0x463f34)])
    add("base64_semantics", "Base64Codec.decode directly calls decoder.convert; both ordinary/URLsafe alphabets, terminal '='/'%3D'/'%3d', canonical unused bits, no whitespace/no auto-padding/no general unescape.",
        [rawref(0x486ec4, 0x5e00ac),
         ref(b64, "Uint8List decode(String encoded) => decoder.convert(encoded)"),
         ref(b64, "var buffer = decoder.decode(input, start, end)!"),
         ref(b64, "decoder.close(input, end)"),
         ref(b64, "if ((bits & 0x03) != 0)"),
         ref(b64, "if ((bits & 0x0F) != 0)"),
         ref(b64, "if (char == _char_percent) expectedPadding += 2"),
         ref(b64, "if ((char | 0x20) != _char_d) break"),
         ref(b64, 'throw FormatException("Missing padding character"'),
         ref(b64, '"Invalid length, must be multiple of four"')],
        "official_versioned_reference_plus_matching_local_call")
    add("runtime_version", "libflutter contains Dart3.5.2 stable android_arm64 version; official reference snapshots use tag3.5.2, not moving latest docs.",
        [ref(APP / "analysis/native/libflutter/strings.txt", "3.5.2 (stable)")])

    write_json("evidence.json", EVIDENCE)
    write_json("raw_instruction_checks.json", {"library": str(LIB), "sha256": INPUTS[str(LIB)],
        "address_space": "ELF virtual address; no Ghidra base adjustment", "ranges":
        [{"label": label, "start": hex(start), "end_exclusive": hex(end)} for label, start, end in ranges],
        "all_llvm_words_checked_against_original_elf": len(raw_hits), "key_references": raw_entries,
        "bl_target_calculation": "sign_extend(word &0x03ffffff,26)*4 + instruction VA"})

    spec = importlib.util.spec_from_file_location("reconstructed_image_codec", OUT / "reconstructed_codec.py")
    codec = importlib.util.module_from_spec(spec)
    sys.dont_write_bytecode = True
    spec.loader.exec_module(codec)
    INPUTS[str(OUT / "reconstructed_codec.py")] = digest((OUT / "reconstructed_codec.py").read_bytes())
    rule_cases = [
        ("direction", "abba", "X,a", "XbbX", None),
        ("overlap", "aaa", "X,aa", "Xa", None),
        ("overlap_many", "aaaaa", "X,aa", "XXa", None),
        ("cascade_forward", "aa", "b,a|c,b", "cc", None),
        ("cascade_reverse", "aa", "c,b|b,a", "bb", None),
        ("self_expansion_single_pass", "a", "aa,a", "aa", None),
        ("regex_characters_literal", "a.*b.a", "X,.*", "aXb.a", None),
        ("replacement_dollar_literal", "aa", "$1,a", "$1$1", None),
        ("backslash_literal", "a", "\\n,a", "\\n", None),
        ("case_sensitive", "aA", "X,a", "XA", None),
        ("no_trim", "a a", "X, a", "aX", None),
        ("delete", "aba", ",a", "b", None),
        ("empty_search", "ab", "X,", "XaXbX", None),
        ("empty_search_empty_input", "", "X,", "X", None),
        ("empty_search_utf16", "😀", "X,", "X\ud83dX\ude00X", None),
        ("empty_source_and_destination", "abc", ",", "abc", None),
        ("no_match", "abc", "X,z", "abc", None),
        ("extra_components_ignored", "a", "X,a,ignored,more", "X", None),
        ("empty_rule_string_is_error", "abc", "", None, 0),
        ("missing_comma", "a", "a", None, 0),
        ("trailing_pipe", "a", "X,a|", None, 1),
        ("leading_pipe", "a", "|X,a", None, 0),
        ("middle_empty_segment", "a", "X,a||Y,X", None, 1),
        ("literal_utf16_surrogate_search", "😀", "X,\ud83d", "X\ude00", None),
    ]
    rule_results = []
    for name, source, rules, expected, error_index in rule_cases:
        trace = []
        entry = {"id": name, "synthetic": True, "input": source, "rules": rules}
        try:
            actual = codec.decode_data(source, rules, trace=trace)
            assert error_index is None and actual == expected, (name, repr(actual), repr(expected))
            entry.update(output=actual, expected=expected, passed=True)
        except codec.RuleFormatError as error:
            assert error_index == error.segment_index, (name, error.segment_index)
            entry.update(error="RuleFormatError (Dart RangeError semantic)",
                         segment_index=error.segment_index, passed=True)
        entry["analyst_trace"] = trace
        rule_results.append(entry)

    b64_cases = [
        ("empty", "", b""), ("one_byte", "Zg==", b"f"),
        ("two_bytes", "Zm8=", b"fo"), ("quartet", "Zm9v", b"foo"),
        ("url_safe", "-_8=", b"\xfb\xff"), ("mixed_alphabet", "+_8=", b"\xfb\xff"),
        ("percent_padding_upper", "Zg%3D%3D", b"f"),
        ("percent_padding_lower", "Zg%3d%3d", b"f"),
        ("mixed_padding1", "Zg=%3D", b"f"), ("mixed_padding2", "Zg%3d=", b"f"),
        ("one_percent_padding", "Zm8%3D", b"fo"),
        ("missing_padding", "Zg", None), ("partial_padding", "Zg=", None),
        ("too_much_padding", "Zg===", None), ("padding_before_data", "=Zg=", None),
        ("whitespace", "Zg==\n", None), ("space_in_data", "Z g==", None),
        ("nonzero_unused_bits_4", "Zh==", None),
        ("nonzero_unused_bits_2", "Zm9=", None),
        ("percent_data_not_unescaped", "%5Ag==", None),
        ("invalid_percent_escape", "Zg%3C%3D", None),
        ("trailing_data", "Zg==A", None), ("non_ascii", "éAAA", None),
        ("incomplete_quartet", "A", None), ("padding_after_full_quartet", "Zm9v=", None),
    ]
    b64_results = []
    for name, source, expected in b64_cases:
        entry = {"id": name, "synthetic": True, "input": source}
        try:
            result = codec.dart_base64_decode(source)
            assert expected is not None and result == expected, name
            entry.update(output_hex=result.hex(), passed=True)
        except codec.Base64FormatError:
            assert expected is None, name
            entry.update(error="Base64FormatError (Dart FormatException semantic)", passed=True)
        b64_results.append(entry)

    # Generate a 1x1 RGBA PNG ourselves: no captured image and no bundled asset.
    def chunk(kind, content):
        return struct.pack(">I", len(content)) + kind + content + struct.pack(">I", zlib.crc32(kind + content) & 0xFFFFFFFF)
    png = b"\x89PNG\r\n\x1a\n" + chunk(b"IHDR", struct.pack(">IIBBBBB", 1, 1, 8, 6, 0, 0, 0))
    png += chunk(b"IDAT", zlib.compress(b"\0\x20\x60\xa0\xff")) + chunk(b"IEND", b"")
    canonical = base64.b64encode(png).decode()
    # Obfuscate one symbol, using synthetic rules I,@; no online rule is guessed.
    encoded = canonical.replace("I", "@")
    synth_rules = "I,@"
    restored = codec.decode_http_image_body(encoded, synth_rules)
    assert restored == png and restored.startswith(b"\x89PNG\r\n\x1a\n")
    synthetic_path = OUT / "synthetic_restored_1x1.png"
    synthetic_path.write_bytes(restored)
    pos = 8
    png_checks = []
    idat = b""
    dimensions = None
    while pos < len(restored):
        length = struct.unpack_from(">I", restored, pos)[0]
        kind = restored[pos + 4:pos + 8]
        payload = restored[pos + 8:pos + 8 + length]
        crc = struct.unpack_from(">I", restored, pos + 8 + length)[0]
        assert crc == zlib.crc32(kind + payload) & 0xFFFFFFFF
        if kind == b"IHDR":
            dimensions = struct.unpack(">IIBBBBB", payload)
            assert dimensions == (1, 1, 8, 6, 0, 0, 0)
        if kind == b"IDAT":
            idat += payload
        png_checks.append({"type": kind.decode(), "length": length, "crc_valid": True})
        pos += 12 + length
    assert pos == len(restored)
    scanline = zlib.decompress(idat)
    assert scanline == b"\0\x20\x60\xa0\xff"
    synthetic_pipeline = {"synthetic": True, "not_server_data": True,
        "rules": synth_rules, "body": encoded, "restored_base64": canonical,
        "result_file": str(synthetic_path), "sha256": digest(restored),
        "size_bytes": len(restored), "png_chunks": png_checks,
        "png_scanline_hex": scanline.hex(), "ihdr_fields": dimensions,
        "path_example": codec.cache_relative_path(2026, 1, 2, 7),
        "note": "PNG checks are analyst validation of this synthetic fixture, absent from the app HTTP write routine."}
    assert codec.decode_http_image_body("SGVsbG8=", ",") == b"Hello"
    synthetic_pipeline["non_png_bytes_also_accepted_by_decode_routine"] = {"body": "SGVsbG8=", "rules": ",", "result_hex": "48656c6c6f"}
    url_cases = [("a/b", "example.invalid", "http://example.invalid/a/b"),
                 ("https://example.invalid/x", "ignored.invalid", "https://example.invalid/x"),
                 ("/a", "example.invalid/", "http://example.invalid///a"),
                 ("HTTPS://x", "example.invalid", "http://example.invalid/HTTPS://x")]
    urls = []
    for img, host, expected in url_cases:
        actual = codec.get_img_url(img, host)
        assert actual == expected
        urls.append({"synthetic": True, "img": img, "host": host, "output": actual, "passed": True})
    write_json("synthetic_validation.json", {"boundary": "Own Python implementation vs statically reconstructed contract; APK and Dart runtime were not executed.",
        "rule_cases": rule_results, "base64_cases": b64_results, "url_cases": urls,
        "http_png_roundtrip": synthetic_pipeline,
        "counts": {"rule": len(rule_results), "base64": len(b64_results), "url": len(urls), "png_roundtrip": 1},
        "all_passed": True})

    sdk_sources = json.loads(read(std / "retrieval.json"))
    for entry in sdk_sources:
        if entry.get("status") == "retrieved":
            p = Path(entry["file"])
            assert digest(p.read_bytes()) == entry["sha256"]
    contract = {"artifact_kind": "人工静态重建；不是原源码或服务器流量", "target_library_sha256": INPUTS[str(LIB)],
        "rule_value": {"status": "unknown_runtime_server_value", "default_not_invented": True,
            "source": "server msg -> Base64 -> RSA PKCS1 ->jsonDecode ->element[1] String ->static0xbc0",
            "exact_original_field_name": "analyst alias Utils.rules; confirmed shared static field0xbc0"},
        "rule_model": {"kind": "delimiter String, no JSON rule objects", "segment_separator": "|", "component_separator": ",",
            "destination_index": 0, "source_index": 1, "minimum_components": 2,
            "extra_components": "ignored", "ordering": "left to right, each output feeds next rule",
            "matching": "literal String, nonoverlapping over UTF16 code units, case sensitive",
            "replacement": "literal String including $ and backslash", "trim": False, "escape_syntax": False,
            "empty_whole_rule": "RangeError on pair[1]", "empty_segment": "RangeError",
            "empty_source": "insert destination at every UTF16 boundary including ends",
            "empty_destination": "delete matched source", "empty_source_and_destination": "valid identity",
            "delimiter_limit": "comma and pipe cannot be represented inside source/destination by an observed escaping scheme"},
        "http_pipeline": ["response.data required String", "Utils.decode_data", "Base64Codec.decode", "bytes written synchronously with FileMode.writeOnly"],
        "http_cache": {"root": "getTemporaryDirectory() runtime result", "directory": "cacheImg/{year}{month}{day} (local DateTime.now(), unpadded)",
            "file": "{Random().nextInt(1000000)}.png (unpadded)", "recursive_directory_creation": True,
            "file_mode": "FileMode.writeOnly index3, overwrite existing", "png_validation_or_transcode": "absent from this HTTP callback",
            "collision_handling": "no uniqueness retry observed; FileMode.writeOnly overwrites"},
        "url": {"pass_through_prefixes": ["http://", "https://"], "relative": "http://{static0xbb4}/{img}",
            "case_sensitive": True, "slash_normalization": False},
        "preview_pipeline": ["msg_type102 -> optional device|payload routing ->Utils.decode_data ->reactive frame String",
                             "base64Decode ->image.decodeJpg ->updateDrawImg ->image.encodePng ->Image.memory"],
        "base64": {"alphabet": "standard and URL-safe mixed accepted", "whitespace": "rejected", "automatic_padding": False,
            "padding": "= or %3D/%3d only at end, exact count; leftover bits must be zero", "general_percent_unescape": False,
            "empty_input": "empty bytes", "normalization_call": "not called at observed Base64Codec.decode entry"},
        "unknowns": ["Actual server-supplied rule String and its changes over time", "Actual HTTP response image format and bytes", "Backend encoding implementation and rule-generation procedure", "Runtime temporary directory absolute path", "Allocation/OOM/string maximum-length exception parity outside ordinary inputs"],
        "python_compatibility": "Literal matching preserves UTF16 code units; exceptions emulate semantic categories, not exact Dart exception messages or indices. Does not implement JPEG/image rendering.",
        "evidence_groups": list(EVIDENCE), "official_sources": sdk_sources}
    write_json("algorithm_contract.json", contract)

    # Verify every evidence reference now, not merely record proposed checks.
    references = [r for group in EVIDENCE.values() for r in group["references"]]
    for r in references:
        p = Path(r["file"])
        assert digest(p.read_bytes()) == r["sha256"]
        assert p.read_text().splitlines()[r["line"] - 1].strip() == r["excerpt"]
    INPUTS[str(Path(__file__).resolve())] = digest(Path(__file__).read_bytes())
    for name in ["reconstructed_decode.dart", "图片响应还原说明.txt"]:
        if (OUT / name).exists():
            INPUTS[str(OUT / name)] = digest((OUT / name).read_bytes())
    write_json("source_manifest.json", {"inputs": INPUTS,
        "artifacts": {str(p): digest(p.read_bytes()) for p in sorted(OUT.rglob("*"))
                      if p.is_file() and p.name != "source_manifest.json" and "__pycache__" not in p.parts},
        "validation": {"reference_count": len(references), "evidence_groups": len(EVIDENCE),
            "raw_ranges": len(ranges), "raw_llvm_words_verified": len(raw_hits),
            "key_instruction_refs": len(raw_entries), "key_bl_targets_verified": sum("bl_target" in r for r in raw_entries),
            "synthetic_rule_cases": len(rule_results), "synthetic_base64_cases": len(b64_results),
            "synthetic_url_cases": len(urls), "synthetic_png_roundtrip": 1, "all_passed": True},
        "notes": ["No target execution or business-server request", "Official SDK fetch snapshots are read-only references; script itself has no network code", "ELF VA for Dart libapp.so uses no Ghidra base", "Generated source is an analyst reconstruction"]})
    print(json.dumps(json.loads((OUT / "source_manifest.json").read_text())["validation"], ensure_ascii=False))


if __name__ == "__main__":
    main()
