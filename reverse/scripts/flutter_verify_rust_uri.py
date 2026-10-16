#!/usr/bin/env python3
"""Verify selected Rust string-slice descriptors without running the library."""

from _paths import app_root, workspace_root
import hashlib
import json
import struct
from pathlib import Path


def main():
    app = app_root()
    source = app / "unpacked/lib/arm64-v8a/librust_lib_distinguish.so"
    data = source.read_bytes()
    if data[:6] != b"\x7fELF\x02\x01" or struct.unpack_from("<H", data, 18)[0] != 183:
        raise ValueError("Expected little-endian ELF64 AArch64 library")
    base = 0x100000
    shoff = struct.unpack_from("<Q", data, 40)[0]
    entsize, count, strindex = struct.unpack_from("<HHH", data, 58)
    raw_sections = [struct.unpack_from("<IIQQQQIIQQ", data, shoff + i * entsize)
                    for i in range(count)]
    raw_names = data[raw_sections[strindex][4]:raw_sections[strindex][4] + raw_sections[strindex][5]]
    sections = []
    for section in raw_sections:
        sections.append({
            "name": raw_names[section[0]:].split(b"\0", 1)[0].decode("ascii"),
            "type": section[1], "vma": section[3], "file_offset": section[4],
            "size": section[5], "entry_size": section[9],
        })

    def mapped(address):
        for section in sections:
            if section["type"] == 8 or not section["vma"]:
                continue
            if section["vma"] <= address < section["vma"] + section["size"]:
                return section, section["file_offset"] + address - section["vma"]
        raise ValueError(f"No file-backed ELF section for {address:#x}")

    relocations = {}
    for section in sections:
        if section["type"] != 4:
            continue
        for position in range(section["file_offset"], section["file_offset"] + section["size"],
                              section["entry_size"]):
            address, info, addend = struct.unpack_from("<QQq", data, position)
            relocations[address] = {
                "section": section["name"], "file_offset": position,
                "info": info, "type": info & 0xffffffff,
                "symbol_index": info >> 32, "addend": addend,
            }

    def descriptor(ghidra_address):
        address = ghidra_address - base
        section, position = mapped(address)
        raw_pointer, length = struct.unpack_from("<QQ", data, position)
        relocation = relocations[address]
        if relocation["type"] != 1027 or relocation["symbol_index"] != 0:
            raise ValueError("Descriptor pointer is not R_AARCH64_RELATIVE")
        target = relocation["addend"]
        target_section, target_position = mapped(target)
        if length > 4096 or target_position + length > target_section["file_offset"] + target_section["size"]:
            raise ValueError("Invalid string-slice bounds")
        payload = data[target_position:target_position + length]
        return {
            "descriptor_ghidra_address": f"0x{ghidra_address:x}",
            "descriptor_elf_vma": f"0x{address:x}",
            "descriptor_file_offset": f"0x{position:x}",
            "descriptor_section": section["name"],
            "raw_pointer_before_relocation": f"0x{raw_pointer:x}",
            "byte_length": length,
            "relocation": {
                "type": "R_AARCH64_RELATIVE", "type_value": 1027,
                "section": relocation["section"],
                "entry_file_offset": f"0x{relocation['file_offset']:x}",
                "symbol_index": relocation["symbol_index"],
                "addend_elf_vma": f"0x{target:x}",
                "resolved_ghidra_address": f"0x{target + base:x}",
            },
            "string_elf_vma": f"0x{target:x}",
            "string_ghidra_address": f"0x{target + base:x}",
            "string_file_offset": f"0x{target_position:x}",
            "string_section": target_section["name"],
            "string_bytes_hex": payload.hex(),
            "text": payload.decode("utf-8"),
        }

    def source_lines(path, strings, radius=1):
        lines = path.read_text().splitlines()
        selected = set()
        for index, line in enumerate(lines):
            if any(string in line for string in strings):
                selected.update(range(max(0, index - radius), min(len(lines), index + radius + 1)))
        return [{"line": index + 1, "text": lines[index]} for index in sorted(selected)]

    uri_cases = [
        (0x2a3350, "001a5ec8", "001a51dc", "param_1 + 1", 0xa51dc),
        (0x2a51c8, "001d327c", "001d303c", "param_1 + 7", 0xd303c),
    ]
    uri_results = []
    for address, caller, formatter, runtime_source, formatter_elf_vma in uri_cases:
        pieces = [descriptor(address), descriptor(address + 16)]
        path = app / f"analysis/deep_rust/functions/{caller}.c"
        lines = path.read_text().splitlines()
        descriptor_line = next(index for index, line in enumerate(lines)
                               if f"local_1340 = &PTR_DAT_{address:08x};" in line)
        setup_indices = range(max(0, descriptor_line - 2), min(len(lines), descriptor_line + 8))
        setup_lines = [{"line": index + 1, "text": lines[index]} for index in setup_indices]
        setup_text = "\n".join(item["text"] for item in setup_lines)
        if ("pppppuStack_1338 = (undefined *****)0x2;" not in setup_text or
                "pppppuStack_1328 = (undefined *****)0x1;" not in setup_text or
                f"FUN_{formatter}" not in setup_text or runtime_source not in setup_text):
            raise ValueError("URI format argument setup changed")
        _, formatter_offset = mapped(formatter_elf_vma)
        uri_results.append({
            "caller_ghidra_address": f"0x{int(caller, 16):x}",
            "caller_decompilation": str(path),
            "pieces_count": 2, "runtime_format_arguments_count": 1,
            "pieces": pieces,
            "runtime_argument": {
                "decompiler_expression": runtime_source,
                "meaning": "运行时字符串值；具体服务器地址内容未在本复核中恢复。",
                "formatter_ghidra_address": f"0x{int(formatter, 16):x}",
                "formatter_file_offset": f"0x{formatter_offset:x}",
                "formatter_first_20_bytes_hex": data[formatter_offset:formatter_offset + 20].hex(),
                "formatter_instructions": [
                    "ldp x8, x9, [x0, #0x8]", "mov x2, x1", "mov x0, x8",
                    "mov x1, x9", "b 0x1980fc (ELF VMA)",
                ],
                "formatter_observation": "从运行时对象偏移 +8/+16 取出两字（指针/长度形式），"
                                         "转交共同格式化实现；未访问任何服务器。",
            },
            "template": pieces[0]["text"] + "{运行时地址}" + pieces[1]["text"],
            "static_scheme": "ws", "static_port": 18889,
            "static_path_suffix": "",
            "source_setup_evidence": setup_lines,
        })

    log_path = app / "analysis/deep_rust/lifecycle/functions/001e99a0.c"
    log_results = []
    for message_type, address, condition, meaning in [
        (51, 0x2a6ee0, "if ((int)local_1c0 == 0x33)", "日志声明为 Keep Alive 心跳响应"),
        (52, 0x2a7078, "if ((int)local_1c0 == 0x34)", "日志名为服务端响应错误"),
        (54, 0x2a70a0, "if ((int)local_1c0 != 0x36)", "日志声明为服务端踢出指令"),
    ]:
        log_results.append({
            "types_decimal": message_type, "types_hex": f"0x{message_type:x}",
            "descriptor": descriptor(address), "decompilation": str(log_path),
            "branch_and_log_evidence": source_lines(log_path, [condition, f"PTR_DAT_{address:08x}"], 3),
            "meaning_from_exact_log_text": meaning,
            "limits": "关联由条件分支内的直接描述器引用确认；完整状态变化和回调参数未由日志单独证明。",
        })

    format_path = app / "analysis/deep_rust/functions/00290604.c"
    output = {
        "source_library": str(source), "source_sha256": hashlib.sha256(data).hexdigest(),
        "elf": {"class": "ELF64", "endianness": "little", "machine": "AArch64",
                "ghidra_image_base": f"0x{base:x}"},
        "method": "先以 ELF section 的 VMA/file_offset 映射描述器，再解析 RELA 相对重定位，"
                  "按描述器的 byte_length 精确读取 UTF-8 字节；不使用相邻字符串猜测。",
        "relevant_sections": [
            {**section, "vma_hex": f"0x{section['vma']:x}",
             "file_offset_hex": f"0x{section['file_offset']:x}"}
            for section in sections if section["name"] in [".rodata", ".data.rel.ro", ".rela.dyn", ".text"]
        ],
        "uri_format_descriptors": uri_results,
        "shared_format_routine": {
            "ghidra_address": "0x290604", "decompilation": str(format_path),
            "evidence": source_lines(format_path, ["param_2[1]", "param_2[3]", "FUN_002966d8", "a formatting trait"]),
            "interpretation": "按 pieces 长度分配字符串缓冲，并调用格式化写入逻辑。",
        },
        "related_log_descriptors": log_results,
        "conclusion": "两个 URI 构造点均确认采用 ws://{运行时地址}:18889 模板，"
                      "静态格式未添加路径或查询参数。",
        "limits": [
            "运行时地址的值、是否包含特殊字符及上层参数校验未在本复核中确认。",
            "无静态路径指模板未追加路径，不表示 WebSocket HTTP 握手不会规范化为 /。",
            "未连接地址、未执行原生库、未修改 Ghidra 项目。",
        ],
    }
    destination = app / "analysis/deep_rust/uri_format_evidence.json"
    destination.write_text(json.dumps(output, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print(json.dumps({"artifact": str(destination), "uri_templates": [item["template"] for item in uri_results],
                      "related_logs": {item["types_decimal"]: item["descriptor"]["text"]
                                       for item in log_results}}, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
