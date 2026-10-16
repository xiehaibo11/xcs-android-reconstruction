#!/usr/bin/env python3
"""Reproduce the static heartbeat/QoS audit from Ghidra C and ELF instructions.

No APK/native code is loaded or executed. llvm-objdump only reads the ELF.
Dependencies: Python 3, pyelftools, llvm-objdump; prior Ghidra exports are retained.
"""
from __future__ import annotations

from _paths import app_root, workspace_root

import argparse
import hashlib
import json
import re
import shutil
import struct
import subprocess
from pathlib import Path

from elftools.elf.elffile import ELFFile

BASE = 0x100000
EXPECTED_SHA = "0af3f1f12e57e9b5f2d409343421c1fa21b0bcffe7860a30cf972a1265399847"


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=workspace_root())
    parser.add_argument("--asm-cache", type=Path, help="Optional prior llvm-objdump -d text")
    parser.add_argument("--objdump", default=shutil.which("llvm-objdump") or "/opt/homebrew/opt/llvm/bin/llvm-objdump")
    args = parser.parse_args()
    root = args.root.resolve()
    out = root / "APP/analysis/ws_heartbeat"
    cdir = out / "native_pseudocode/functions"
    library = root / "APP/unpacked/lib/arm64-v8a/librust_lib_distinguish.so"
    out.mkdir(parents=True, exist_ok=True)
    if sha(library) != EXPECTED_SHA:
        raise RuntimeError("Input ELF SHA256 differs from audited artifact")
    evidence, facts = {}, []

    def ref(address, needle=None, context=4, occurrence=1):
        path = cdir / f"{address:08x}.c"
        lines = path.read_text().splitlines()
        hits = [i for i, line in enumerate(lines) if needle is None or needle in line]
        if len(hits) < occurrence:
            raise RuntimeError(f"Evidence anchor missing: {path.name}: {needle!r}")
        i = hits[occurrence - 1]
        lo, hi = max(0, i - context), min(len(lines), i + context + 1)
        key = f"C_{address:08x}_{i + 1}"
        evidence[key] = {"file": str(path), "line": i + 1, "excerpt_start": lo + 1,
                         "excerpt_end": hi, "excerpt": "\n".join(lines[lo:hi]),
                         "sha256": sha(path), "ghidra_address": hex(address),
                         "elf_virtual_address": hex(address - BASE)}
        return key

    def dart_ref(relative, needle, context=3):
        path = root / relative
        lines = path.read_text().splitlines()
        i = next(i for i, line in enumerate(lines) if needle in line)
        key = f"DART_{path.name}_{i + 1}"
        evidence[key] = {"file": str(path), "line": i + 1, "sha256": sha(path),
                         "excerpt": "\n".join(lines[max(0, i-context):i+context+1])}
        return key

    def fact(identifier, status, description, value=None, refs=()):
        item = {"id": identifier, "status": status, "description_zh": description,
                "evidence": list(refs)}
        if value is not None:
            item["value"] = value
        facts.append(item)

    # Recover actual bytes, RELA references, and AArch64 direct branches.
    with library.open("rb") as f:
        elf = ELFFile(f)
        segments = [(s["p_vaddr"], s.data()) for s in elf.iter_segments() if s["p_type"] == "PT_LOAD"]
        reloc = {r["r_offset"]: r["r_addend"] for sec in elf.iter_sections()
                 if hasattr(sec, "iter_relocations") for r in sec.iter_relocations() if r.is_RELA()}

    def read(address, length):
        for start, data in segments:
            if start <= address and address + length <= start + len(data):
                return data[address-start:address-start+length]
        raise ValueError(f"ELF VA unmapped {address:#x}")

    def direct_target(address, link=False):
        word, = struct.unpack("<I", read(address, 4))
        opcode = 0x94000000 if link else 0x14000000
        if word & 0xfc000000 != opcode:
            raise ValueError(f"No {'BL' if link else 'B'} at {address:#x}")
        immediate = word & 0x3ffffff
        if immediate & 0x2000000:
            immediate -= 0x4000000
        return address + (immediate << 2)

    binding_specs = [
        ("heartbeat_send", 0x1bfbf8, [0x1dc9d4, 0x1d29e4], [0x1a2c04, 0x1a38ac], [0x1a2be8, 0x1a2eb8], 0xa4988, 0xa49bc, 0xa5a18),
        ("heartbeat_check", 0x1bf508, [0x1dd09c, 0x1d2c9c], [0x1a3188, 0x1a3e74], [0x1a2d28, 0x1a2ff8], 0xa4524, 0xa4558, 0xa5b78),
        ("auto_relogin", 0x1bfa3c, [0x1dc8dc, 0x1d2acc], [0x1a2764, 0x1a25e4], [0x1a2af8, 0x1a2aa8], 0xa4318, 0xa434c, 0xa5cd0),
        ("qos_receive_cleanup", 0x1c0164, [0x1dd194, 0x1d272c], [0x1a3a2c, 0x1a35c8], [0x1a2f08, 0x1a2e18], 0xa4280, 0xa42b4, 0xa5768),
        ("qos_send_retry", 0x1bf34c, [0x1dcfa4, 0x1d2644], [0x1a233c, 0x1a21bc], [0x1a2a08, 0x1a29b8], 0xa48f0, 0xa4924, 0xa58c0),
        ("public_ws_logout", 0x1b8248, [0x1dceac, 0x1d255c], [0x1a3464, 0x1a3ff4], [0x1a2dc8, 0x1a3048], 0xa4670, 0xa46a4, 0x9e008),
    ]
    bindings = []
    worker_ranges = []
    for name, entry, runtime, ctors, vtables, wrapper, call, poll in binding_specs:
        rows = []
        for ctor, vt in zip(ctors, vtables):
            thunk = reloc[vt]
            worker = direct_target(thunk)
            calls = [a for a in range(worker, worker+0x100, 4)
                     if (struct.unpack("<I", read(a, 4))[0] & 0xfc000000 == 0x94000000)
                     and direct_target(a, True) == wrapper]
            if len(calls) != 1:
                raise RuntimeError(f"Worker call not unambiguous: {name}")
            rows.append({"constructor_ghidra": hex(ctor), "constructor_evidence": ref(ctor, "local_1f0 ="),
                         "vtable_elf_va": hex(vt), "relocation_addend": hex(thunk),
                         "thunk_instruction_hex": read(thunk, 4).hex(), "worker_elf_va": hex(worker),
                         "worker_call_elf_va": hex(calls[0]), "worker_call_hex": read(calls[0], 4).hex()})
            worker_ranges.append((worker, worker+0x90, f"{name}_worker_{worker:x}"))
        if direct_target(call, True) != poll:
            raise RuntimeError(f"Poll binding mismatch {name}")
        bindings.append({"name": name, "async_entry_ghidra": hex(entry),
                         "runtime_ghidra": [hex(a) for a in runtime], "branches": rows,
                         "wrapper_elf_va": hex(wrapper), "poll_call_elf_va": hex(call),
                         "poll_ghidra": hex(poll+BASE), "poll_call_hex": read(call, 4).hex(),
                         "entry_evidence": ref(entry), "wrapper_evidence": ref(wrapper+BASE)})

    fact("timing_units", "confirmed", "interval 构造保存秒、纳秒两个字段；tick 实际以秒×10^9+纳秒运算。1000000000 是 poll Pending 返回哨兵，不能读成间隔。",
         {"duration_pair": ["seconds:i64", "nanoseconds:i32"], "pending_sentinel": 1000000000},
         [ref(0x2248c0, "*param_1 = param_4"), ref(0x2249b4, "uVar3 * 1000000000"), ref(0x2249b4, "uVar9 = 1000000000")])
    fact("clock_sources", "confirmed", "interval 取 clock_gettime(1)；时间戳取 clock_gettime(0)→Chrono 日期/日内秒，再换回 epoch seconds。定时与超时判断使用两种时钟。",
         {"interval_clock_id": 1, "timestamp_clock_id": 0, "timestamp_unit": "seconds", "calendar_days_multiplier": 86400},
         [ref(0x2776fc, "FUN_0027be18(1)"), ref(0x277860, "FUN_0027be18(0)"), ref(0x27be18, "clock_gettime"), ref(0x2113cc, "local_60 % 0x15180"), ref(0x20a878, "FUN_002113cc")])
    fact("heartbeat_period", "confirmed", "发送周期从 SDK global+0x30 读取，0 时默认 30 秒。该 getter 获取锁超过 1000 次也返回 30；1000 是尝试次数，非毫秒。",
         {"period_global_offset": "0x30", "default_seconds": 30, "lock_retry_limit": 1000},
         [ref(0x1e253c, "lVar2 = 0x1e"), ref(0x1e253c, "return 0x1e")])
    fact("heartbeat_schedule", "confirmed", "认证 code=0 分支启动两个 keep-alive future：发送立即执行，然后按周期；检查先等首个 2 秒 tick，然后每 2 秒。",
         {"send_first": "immediate", "checker_first_seconds": 2, "checker_period_seconds": 2,
          "send_join_global_offset": "0x60", "check_join_global_offset": "0x78"},
         [ref(0x1e1b0c, "FUN_001bfbf8"), ref(0x1e1b0c, "FUN_001bf508"), ref(0x1a5a18, "goto LAB_001a5af4"), ref(0x1a5b78, "goto LAB_001a5c80"), ref(0x1e99a0, "FUN_001e1b0c")])
    fact("heartbeat_message", "confirmed", "心跳业务协议 types=1、data_content='💓'、qos=false；from 克隆 SDK global+0x160 String，to 为空，fp 新 UUID。全路径1e1110→1eb3d4→1c5d3c→1eb854。",
         {"types": 1, "data_content": "💓", "utf8_hex": "f09f9293", "qos": False, "from_source": "SDK+0x160", "to": "", "fp": "fresh UUID"},
         [ref(0x1e1110, "FUN_001eb3d4"), ref(0x1eb3d4, "FUN_001c5d3c"), ref(0x1c5d3c, "0x93929ff0")])
    fact("heartbeat_last_response", "confirmed", "types51 回复更新 global+0x48 的 epoch seconds。每次发送后只在 last_time==0 时初始化；发送本身不持续刷新回复时间。",
         {"last_time_global_offset": "0x48", "response_types": 51, "write_helper": "0x1e207c", "getter": "0x1e236c"},
         [ref(0x1e99a0, "(int)local_1c0 == 0x33"), ref(0x1e99a0, "FUN_001e207c"), ref(0x1e1110, "if (lVar1 != 0)"), ref(0x1e207c, "+ 0x48"), ref(0x1e236c, "return 0")])
    fact("heartbeat_timeout", "confirmed", "若 now_epoch_seconds-last_time >= configured_period+5，1e1270调用1e1e9c；默认比较阈值为35秒。1e1e9c停两个keep-alive任务并向内部bool channel发送true。",
         {"elapsed_comparison": ">=", "threshold_seconds": "period+5", "default_threshold_seconds": 35,
          "timeout_handler": "0x1e1e9c", "internal_channel_sender_global_offset": "0x18"},
         [ref(0x1e1270, "if (lVar4 + 5 <=", context=7), ref(0x1e1e9c, "FUN_001e13c8"), ref(0x1e1e9c, "FUN_001b3b14")])
    fact("internal_disconnect_monitor", "confirmed", "认证成功建立的内部bool监视future在Pending外接收到值后调用1eab5c，不按bool内容区分；channel已关闭路径则退出。此监视器和产生Flutter event10的网络连接监视器不同。",
         {"monitor_poll": "0x1a5430", "handler": "0x1eab5c", "pending_tag": 3, "closed_tag": 2},
         [ref(0x1a5430, "FUN_001b39d8", context=8), ref(0x1a5430, "FUN_001eab5c"), ref(0x1e99a0, "FUN_001bfdb4"), ref(0x1a51f0, "FUN_001ec7f0")])
    fact("auto_relogin_cleanup_order", "confirmed", "断连回调1eab5c先清+0x2a5、撤内部bool sender、调用关闭辅助函数、停keep-alive、停QoS接收、停QoS发送、停旧relogin，再启动新relogin并保存join handle于global+0xf8。",
         {"order": ["2a5=false", "internal sender removed", "close helper called", "heartbeat stop", "QoS receive stop", "QoS send stop", "old relogin stop", "new relogin start"], "join_global_offset": "0xf8"},
         [ref(0x1eab5c, "FUN_001e2d2c", context=17), ref(0x1eab5c, "FUN_001bfa3c", context=12)])
    fact("auto_relogin_schedule", "confirmed", "relogin周期由global+0xe8非零值决定，0时默认3秒；启动立即执行，此后固定周期。该poll中未出现指数退避或总重试次数上限。",
         {"first_attempt": "immediate", "default_period_seconds": 3, "config_global_offset": "0xe8", "poll": "0x1a5cd0"},
         [ref(0x1ec69c, "lVar1 = 3", context=5), ref(0x1a5cd0, "goto LAB_001a5e40"), ref(0x1a5cd0, "FUN_001ec068")])
    fact("authentication_reuse", "confirmed", "每次自动重登录先调用关闭辅助函数，再克隆此前ws_login保存于global+0x110的String，交给1eaf88→types6登录发送；此链未刷新JWT。Dart已确认传入值是JWT。认证code=0和非0分支都停止旧relogin。",
         {"saved_input_global_offset": "0x110", "relogin_send": "0x1eaf88", "login_types": 6, "refresh_token_in_this_chain": False},
         [ref(0x1ec068, "FUN_001e8b4c"), ref(0x1ec068, "FUN_00290ab4(&local_80,puVar5 + 0x110", context=5), ref(0x1e99a0, "FUN_001ec290", occurrence=1), ref(0x1e99a0, "FUN_001ec290", occurrence=2)])
    fact("qos_track", "confirmed", "发送函数1eb5a4只有传输返回0且qos=true并且fp尚未入表时调用1e06c4；跟踪两张表：state+0x10保存Protocol，state+0x50保存发送epoch seconds，state基址为SDK+0x1f8。空fp拒绝入表。",
         {"state_global_offset": "0x1f8", "protocol_map_state_offset": "0x10", "timestamp_map_state_offset": "0x50", "track_after": "transport return0 AND qos=true AND absent fp"},
         [ref(0x1eb5a4, "if ((iVar2 == 0)", context=10), ref(0x1eb5a4, "FUN_001e06c4"), ref(0x1e06c4, "param_2[0xb] == 0"), ref(0x1e06c4, "FUN_001e7178"), ref(0x1e06c4, "FUN_001e6d94", context=6)])
    fact("qos_retry_timer", "confirmed", "发送扫描poll1a58c0先立即调用1df0cc，再每60秒扫描；重入保护字段为sender state+0x95。",
         {"first_scan": "immediate", "scan_period_seconds": 60, "guard_state_offset": "0x95"},
         [ref(0x1a58c0, "0x3c,0"), ref(0x1a58c0, "goto LAB_001a5994"), ref(0x1df0cc, "+ 0x95")])
    fact("qos_retry_threshold", "confirmed", "发送时间差以epoch seconds计算；cmp 0xbb9 / b.ge意味着 >=3001秒才重发。日志模板明确使用“秒”，配套常数3000，所以不会将其改写为3秒或3000毫秒。",
         {"threshold_seconds": 3001, "equivalent_minutes_seconds": [50, 1], "logged_no_retry_limit_seconds": 3000,
          "condition": "now_epoch_seconds-stored_epoch_seconds>=3001"},
         [ref(0x1e06c4, "0x15180"), ref(0x1df0cc, "local_150 =", context=8), ref(0x1df0cc, "local_150 < 0xbb9", context=5)])
    fact("qos_retry_count", "confirmed", "Protocol+0x64是本地重发计数，默认构造清零；成功重发返回0才加1。计数>1移入本地丢失vector并移除跟踪；零初值因此最多两次成功重发，传输失败不增加计数。",
         {"counter_protocol_offset": "0x64", "counter_initial": 0, "remove_when_counter": ">1", "successful_resends_max": 2, "failed_attempts_increment": False},
         [ref(0x1c5ce4, "param_1[0xc]"), ref(0x1df0cc, "1 < (int)auStack_160._4_4_", context=5), ref(0x1df0cc, "iVar9 == 0", context=6), ref(0x1df0cc, "= uVar8 + 1"), ref(0x1df0cc, "FUN_001e0cf4")])
    fact("qos_no_timestamp_refresh", "confirmed", "成功重发调用同一个1eb5a4，原fp仍在表中，因此跳过1e06c4；1df0cc成功分支只更新counter，没有刷新发送时间戳。",
         {"reuse_original_fp": True, "successful_resend_updates_timestamp": False},
         [ref(0x1eb5a4, "if ((uVar3 & 1) == 0)", context=6), ref(0x1df0cc, "= uVar8 + 1"), ref(0x1df0cc, "FUN_001eb5a4", context=6)])
    fact("qos_after_timeout", "inferred", "时间戳不刷新且扫描仍每60秒，达到3001秒之后两次成功重发可在相邻扫描发生，下一次扫描移除；失败尝试可能持续。调度暂停/赶补tick可缩短扫描间实际间隔。",
         refs=[ref(0x1df0cc, "local_150 < 0xbb9"), ref(0x1a58c0, "FUN_001df0cc")])
    fact("qos_ack_asymmetry", "confirmed", "ACK构造types4把received.fp放在data_content、生成新的ACK fp；接收ACK的1e0cf4实际拿param_2+0x48即ACK自身fp删除两张发送表，而非data_content。",
         {"ack_types": 4, "ack_content": "received.fp", "ack_fp": "fresh UUID", "received_ack_removal_key": "ACK.fp", "original_message_fp_field_in_ack": "data_content"},
         [ref(0x1c5e50, "FUN_0020a4a4"), ref(0x1c5e50, "param_2 + 0x48", context=6), ref(0x1e0cf4, "lVar2 = param_2 + 0x48", context=7), ref(0x1e0cf4, "FUN_001cdcb8"), ref(0x1e99a0, "FUN_001e0cf4", context=5)])
    fact("qos_ack_impact", "inferred", "若服务器返回的ACK也将ACK.fp设为新UUID而只在data_content带原fp，本地跟踪无法按原消息清除，会进入上述超时/重发路径。服务器实际ACK格式仍未知。",
         refs=[ref(0x1e0cf4, "lVar2 = param_2 + 0x48"), ref(0x1c5e50, "FUN_00290ab4")])
    fact("qos_receive_duplicate", "confirmed", "收到qos=true的包按fp字节长度和memcmp查去重表。未命中：记fp/time，发ACK，再业务分派；命中：再次记fp/time、再次发ACK，跳过业务分派。重复包会刷新去重时间。qos=true但types50且登录响应code非0时绕开此去重/ACK段。",
         {"state_global_offset": "0x80", "dedup_map_state_offset": "0x10", "key": "fp bytes", "duplicate_ack": True, "duplicate_business_dispatch": False, "duplicate_refreshes_time": True},
         [ref(0x1e99a0, "FUN_001de924", context=8), ref(0x1e99a0, "FUN_001de38c", occurrence=1, context=8), ref(0x1e99a0, "FUN_001de38c", occurrence=2, context=8), ref(0x1de924, "memcmp", context=4), ref(0x1de38c, "FUN_001e6d94", context=6), ref(0x1e99a0, "(int)local_180 != 0", context=5)])
    fact("qos_receive_expiry", "confirmed", "接收清理poll1a5768立即扫描后每60秒；1dd7e4仅当now_seconds-stored_seconds>59时删记录。去重过期检查不在查询1de924内部。",
         {"first_scan": "immediate", "scan_period_seconds": 60, "delete_when_age_seconds": ">59 (>=60)", "guard_state_offset": "0x59"},
         [ref(0x1a5768, "goto LAB_001a583c"), ref(0x1a5768, "0x3c,0"), ref(0x1dd7e4, "0x3b <", context=6), ref(0x1dd7e4, "FUN_001cde9c"), ref(0x1dd7e4, "+ 0x59")])
    fact("qos_expiry_window", "inferred", "无新重复包且调度正常，fp记录实际存留约60至120秒，取决于扫描相位；不断到达的重复包刷新时间可延长存留。调度停顿或墙上时钟回拨会改变这些范围。",
         refs=[ref(0x1a5768, "FUN_001dd7e4"), ref(0x1de38c, "FUN_001e6d94"), ref(0x1dd7e4, "0x3b <")])
    fact("qos_lost_event", "confirmed", "超过计数上限或跟踪包qos=false会移除；本地收集的Protocol vector最终交给1c57b0释放String。该路径未直接调用Flutter事件发送1ec7f0。",
         {"direct_flutter_callback_in_retry_poll": False},
         [ref(0x1df0cc, "if (((ulong)pppppplStack_1e8 & 1) == 0)", context=5), ref(0x1df0cc, "FUN_001c57b0", context=7), ref(0x1c57b0, "free")])
    fact("task_stop", "confirmed", "各stop函数对保存join handle调用218fe0取消，再drop/清零。keep-alive分别清global+60/+78；QoS receiver清state+48；sender清state+88；relogin清state+18(global+f8)。这些stop函数内未清时间戳或QoS map。",
         {"heartbeat_join_offsets_global": ["0x60", "0x78"], "receive_join_state": "0x48", "send_join_state": "0x88", "relogin_join_global": "0xf8"},
         [ref(0x1e13c8, "FUN_00218fe0"), ref(0x1dd2a0, "FUN_00218fe0"), ref(0x1deb88, "FUN_00218fe0"), ref(0x1ec290, "FUN_00218fe0"), ref(0x218fe0, "uVar6 = uVar5 | 0x20")])
    fact("interval_missed_ticks", "confirmed", "interval构造将state+0x18策略字节置0；tick发现deadline迟于当前超过5ms时，策略0仍将下次deadline设为旧deadline+period，允许赶补已错过tick。",
         {"strategy_byte": 0, "lateness_comparison_nanoseconds": 5000000},
         [ref(0x2248c0, "*(undefined1 *)(param_1 + 3) = 0"), ref(0x2249b4, "0,5000000", context=5), ref(0x2249b4, "if ((char)param_1[3] == '\\0')", context=8)])
    fact("stale_heartbeat_after_relogin", "inferred", "start/stop链未清last_response时间，发送只在0时初始化；重新认证后若没有及时收到types51，新检查线程可能在约2秒首tick就再次判超时。只是此链推论，未进行动态时序验证。",
         refs=[ref(0x1e1110, "if (lVar1 != 0)"), ref(0x1a5b78, "FUN_001e1270"), ref(0x1e13c8)])
    fact("close_helper_guard", "confirmed", "1e8b4c(close_local_socket)先读global+2a5，false直接返回；true才可能往global+1d8消息channel送固定控制对象。1eab5c和1e2ea0都先清2a5再调用，故仅凭该调用不能断言发送Close帧。",
         {"guard_global_offset": "0x2a5", "message_channel_global_offset": "0x1d8", "control_object_elf_va": "0x443b0", "control_hex": read(0x443b0, 16).hex()},
         [ref(0x1e8b4c, "if ((uVar6 & 1) == 0)", context=5), ref(0x1e8b4c, "FUN_001b3bf8", context=5), ref(0x1e2c04, "+ 0x2a5"), ref(0x1eab5c, "FUN_001e2d2c", context=15), ref(0x1e2ea0, "FUN_001e2d2c", context=10)])
    fact("full_stop_order", "confirmed", "被踢types54与主动logout均调用1e2ea0：清2a5，撤内部bool sender，撤socket连接通知sender(global+1e8/+1f0)，停relogin、QoS sender、QoS receiver、keep-alive，调用关闭辅助函数，清2b1；该函数不新建relogin。",
         {"order": ["2a5=false", "internal bool sender removed", "socket connection bool sender removed", "relogin stop", "QoS send stop", "QoS receive stop", "heartbeat stop", "close helper called", "2b1=false"]},
         [ref(0x1e2ea0, "FUN_001e2d2c", context=12), ref(0x1e2ea0, "+ 0x2b1"), ref(0x1e9794, "+ 0x28", context=5), ref(0x1e99a0, "(int)local_1c0 != 0x36", context=4)])
    fact("transport_exit", "confirmed", "连接worker1a5ec8退出路径清global+2a5，撤连接bool通知sender，调用1e1e9c通知内部断连监视器。正常退出和错误分支前置匹配细节仍以原C为准。",
         refs=[ref(0x1a5ec8, "FUN_001e9794", context=12), ref(0x1a5ec8, "FUN_001e1e9c", context=8)])
    fact("public_logout", "confirmed", "Dart wsLogout→FRB funcId7→1b02ac→1b8248 future→1a4670→19e008→1cec94。先构造默认Protocol改types3并尝试发送；不检查返回成功再清JWT+110/+118/+120及完整stop。Dart bridge使用unit解码的正常异步任务。",
         {"frb_func_id": 7, "network_types": 3, "send_result_checked_before_cleanup": False, "saved_token_cleared": True},
         [dart_ref("APP/analysis/aot_dump/asm/distinguish/src/rust/api/simple.dart", "crateApiSimpleWsLogout"), dart_ref("APP/analysis/aot_dump/asm/distinguish/src/rust/frb_generated.dart", "0x4a9898: r3 = 7"), dart_ref("APP/analysis/aot_dump/asm/distinguish/src/rust/frb_generated.dart", "sse_decode_unit"), ref(0x1b02ac, "FUN_001b8248"), ref(0x19e008, "FUN_001cec94"), ref(0x1cec94, "local_f0 = 3", context=5), ref(0x1cec94, "+ 0x120) = 0", context=7), ref(0x1cec94, "FUN_001e2ea0")])
    fact("event_not_auth", "confirmed", "Flutter event integer10属于网络连接成功通知，Dart随后才调用wsLogin；认证成功的证据是types50 code=0分支，而非event10或本地wsLogin返回0。",
         {"event_integer": 10, "interpretation": "transport connected, before authentication"},
         [ref(0x1a51f0, "FUN_001ec7f0"), ref(0x1e99a0, "(int)local_108 == 0", context=6), dart_ref("APP/analysis/aot_dump/asm/distinguish/pages/main/main_page.dart", "0x527f34: r0 = wsLogin()", context=7)])
    for ident, desc in [
        ("backend_ack_unknown", "服务器返回ACK是否复用原fp、是否适配本地ACK清表字段未验证；没有连接服务器。"),
        ("config_setter_unknown", "尚未证明Dart本轮业务设置global+30心跳周期或global+e8重登录周期；报告只确认getter及其默认值。"),
        ("token_refresh_unknown", "本原生重登录链不刷新JWT；HTTP刷新机制和JWT过期后服务器处理超出本轮证据。"),
        ("close_frame_unknown", "固定控制对象的完整tungstenite enum名称以及最终实际Close帧发送未绑定；取消join handle也不等同对端已收到关闭帧。"),
        ("runtime_scheduling_unknown", "实际心跳/重发时序、时间回拨、暂停后的赶补、并发关闭重登录竞态未进行运行验证。"),
        ("flutter_auth_callback_unknown", "未在成功/失败/被踢及丢包路径确认独立Flutter WsEvent认证状态字段值；不能凭日志回调名或String邻近关系建立字段映射。"),
    ]:
        fact(ident, "unknown", desc)

    literal_specs = [(0x1a6030, 4), (0x1a6088, 4), (0x1a61d0, 2), (0x1a5f80, 4),
                     (0x1a5fd8, 4), (0x1a62a8, 1), (0x1a62d0, 1), (0x1a6b90, 1),
                     (0x1a6ff8, 1), (0x1a7050, 1), (0x1a7240, 1)]
    literals = []
    for address, count in literal_specs:
        parts = []
        for i in range(count):
            p = reloc.get(address + 16*i, struct.unpack("<Q", read(address+16*i, 8))[0])
            length, = struct.unpack("<Q", read(address+16*i+8, 8))
            if length > 250:
                raise RuntimeError("Unexpected log literal length")
            parts.append({"pointer_elf_va": hex(p), "length": length, "text": read(p, length).decode("utf8")})
        literals.append({"descriptor_elf_va": hex(address), "parts": parts})

    asm = args.asm_cache.read_text() if args.asm_cache else subprocess.run(
        [args.objdump, "-d", str(library)], check=True, capture_output=True, text=True).stdout
    disasm = []
    for line in asm.splitlines():
        m = re.match(r"\s*([0-9a-f]+):\s+[0-9a-f]{8}\s+", line)
        if m:
            disasm.append((int(m.group(1), 16), line))
    ranges = worker_ranges + [(0xbacb8, 0xbad14, "async_thunks"), (0xa4280, 0xa4a20, "async_poll_wrappers"),
        (0xa5768, 0xa5ec8, "timed_future_polls"), (0xdf0cc, 0xe0008, "qos_retry_worker"),
        (0xe06c4, 0xe0cf4, "qos_timestamp_insert"), (0xdd7e4, 0xde38c, "qos_receive_expiry"),
        (0xe0cf4, 0xe1110, "ack_remove_maps"), (0xe1110, 0xe13c8, "heartbeat_send_check"),
        (0xc5ce4, 0xc5f58, "protocol_default_heartbeat_ack"), (0xcec94, 0xcf040, "public_logout_poll"),
        (0x9e008, 0x9e178, "public_logout_wrapper_poll"), (0x1776fc, 0x177710, "monotonic_clock"),
        (0x177860, 0x177868, "wall_clock"), (0x17be18, 0x17bee0, "clock_gettime"),
        (0x1113cc, 0x111518, "chrono_utc_time_conversion"), (0x1248c0, 0x124c04, "interval_units"),
        (0xeb5a4, 0xeb854, "qos_send_tracking_gate"), (0xe8b4c, 0xe8de4, "close_helper_guard")]
    instruction_evidence = []
    asm_dir = out / "instructions"
    asm_dir.mkdir(exist_ok=True)
    for start, end, name in ranges:
        rows = [line for a, line in disasm if start <= a < end]
        if not rows:
            raise RuntimeError(f"Missing disassembly range {name}")
        path = asm_dir / f"{start:08x}_{name}.txt"
        path.write_text(f"# ELF virtual addresses; Ghidra address = ELF VA + 0x100000\n# {start:#x}..{end:#x}\n"+"\n".join(rows)+"\n")
        instruction_evidence.append({"file": str(path), "sha256": sha(path), "line": 3,
                                     "elf_va_start": hex(start), "elf_va_end_exclusive": hex(end),
                                     "ghidra_start": hex(start+BASE), "summary": name})

    # Critical independent byte checks: constants, timestamp multiplier, ACK key offset.
    byte_checks = [
        (0xdf8b0, "1fe52ef1", "cmp x8,#0xbb9 (3001)"),
        (0xdf8b4, "8a040054", "b.ge resend"),
        (0xe0a4c, "09308a52", "mov w9,#0x5180"),
        (0xe0a50, "2900a072", "movk w9,#1,lsl16 ->86400"),
        (0xe0a64, "a0420191", "timestamp_map state+0x50"),
        (0xddb54, "1fed00f1", "cmp x8,#59"),
        (0xced1c, "68008052", "mov w8,#3 logout network type"),
        (0xc5d28, "7f3200f9", "default protocol types+counter cleared"),
    ]
    verified_bytes = []
    for address, expected, explanation in byte_checks:
        actual = read(address, 4).hex()
        if actual != expected:
            raise RuntimeError(f"Instruction bytes mismatch {address:#x}: {actual} != {expected}")
        verified_bytes.append({"elf_va": hex(address), "ghidra": hex(address+BASE), "hex": actual, "meaning": explanation})
    report = {"scope": "静态逆向；不运行目标、不联系业务服务器、不输出密钥", "library": str(library),
              "library_sha256": EXPECTED_SHA, "addressing": {"ghidra_base": hex(BASE), "rule": "Ghidra=ELF VA+0x100000"},
              "facts": facts, "async_bindings": bindings, "evidence_index": evidence,
              "selected_log_literals": literals, "instruction_evidence": instruction_evidence,
              "critical_instruction_byte_checks": verified_bytes,
              "selected_static_constants": {"ELF_0x44748_u64": struct.unpack("<Q", read(0x44748, 8))[0],
                                            "ELF_0x4544c_u32": struct.unpack("<I", read(0x4544c, 4))[0]},
              "validation": {"all_anchors_found": True, "all_branch_bindings_checked": True,
                             "critical_bytes_match": True, "code_execution": False, "network_requests": False}}
    (out / "heartbeat_lifecycle.json").write_text(json.dumps(report, ensure_ascii=False, indent=2)+"\n")
    notes = ["Rust WebSocket 心跳、QoS 与关闭生命周期静态提取", "", "仅分析 arm64 ELF；地址采用 Ghidra+0x100000 基址。反编译类型是近似值，关键常量/async绑定已和原始指令交叉核验。", ""]
    for status, title in [("confirmed", "已确认"), ("inferred", "依据确认链推断"), ("unknown", "尚未确认")]:
        notes += [title, ""]
        for item in facts:
            if item["status"] != status:
                continue
            notes.append(f"[{item['id']}] {item['description_zh']}")
            for key in item["evidence"]:
                e = evidence[key]
                notes.append(f"  证据 {e['file']}:{e['line']}" + (f" Ghidra {e['ghidra_address']} / ELF {e['elf_virtual_address']}" if "ghidra_address" in e else ""))
            notes.append("")
    notes += ["关键比较表", "心跳发送：立即，随后默认30秒。", "心跳检查：首个2秒tick，默认 elapsed>=35秒。",
              "自动重登录：立即，随后默认3秒，复用已保存JWT。", "QoS发送扫描：立即，随后60秒；elapsed>=3001秒重发；零计数初值下最多2次成功重发。",
              "QoS接收清理：立即，随后60秒；age>=60秒删除；重复包更新时间。", "ACK清表：收到ACK的自身fp，而非data_content。",
              "退出：先发types3，然后清JWT及停任务；没有确认对端收到Close帧。", "", "复现命令", "python3 APP/scripts/ws_heartbeat_extract.py",
              "可使用 --asm-cache 指向既有 llvm-objdump -d 输出；否则脚本只运行分析工具 llvm-objdump。", "伪代码重新导出见本目录 ghidra_reproduce.txt。"]
    (out / "中文说明.txt").write_text("\n".join(notes)+"\n")
    print(json.dumps({"facts": len(facts), "evidence_refs": len(evidence), "instruction_ranges": len(instruction_evidence),
                      "async_bindings": len(bindings), "output": str(out / "heartbeat_lifecycle.json")}, ensure_ascii=False))


if __name__ == "__main__":
    main()
