#!/usr/bin/env python3
"""Recover Go 1.18+ pclntab metadata and FastRSA bridge models from a local ELF.

No library is loaded or executed. Names/addresses come from Go metadata; field
layouts and bridge dispatch are cross-checked against AArch64 instructions.
"""

from _paths import app_root, workspace_root
import argparse
import bisect
import hashlib
import json
import re
import struct
import subprocess
from pathlib import Path


class ELF64:
    def __init__(self, blob):
        self.b = blob
        assert blob[:6] == b'\x7fELF\x02\x01', 'requires little-endian ELF64'
        hdr = struct.unpack_from('<16sHHIQQQIHHHHHH', blob, 0)
        self.machine = hdr[2]
        self.segments = []
        for i in range(hdr[10]):
            t, flags, off, va, pa, filesz, memsz, align = struct.unpack_from(
                '<IIQQQQQQ', blob, hdr[5] + i * hdr[9])
            if t == 1:
                self.segments.append((off, va, filesz, memsz, flags))
        self.sections = []
        for i in range(hdr[12]):
            self.sections.append(struct.unpack_from('<IIQQQQIIQQ', blob,
                                 hdr[6] + i * hdr[11]))
        st = self.sections[hdr[13]]
        names = blob[st[4]:st[4] + st[5]]
        self.sections = [dict(name=names[x[0]:].split(b'\0', 1)[0].decode(),
                              type=x[1], va=x[3], off=x[4], size=x[5])
                         for x in self.sections]
        self.memory = bytearray(blob)
        self.relative_relocations = {}
        for sec in self.sections:
            if sec['name'] != '.rela.dyn':
                continue
            for pos in range(sec['off'], sec['off'] + sec['size'], 24):
                address, info, addend = struct.unpack_from('<QQq', blob, pos)
                if info & 0xffffffff == 1027: # R_AARCH64_RELATIVE, image base 0
                    try:
                        at = self.file_offset(address)
                    except ValueError:
                        continue
                    struct.pack_into('<Q', self.memory, at, addend)
                    self.relative_relocations[address] = addend

    def file_offset(self, va):
        for off, start, size, _, _ in self.segments:
            if start <= va < start + size:
                return off + va - start
        raise ValueError(hex(va))

    def va(self, off):
        for start, va, size, _, _ in self.segments:
            if start <= off < start + size:
                return va + off - start
        raise ValueError(hex(off))

    def read_va(self, va, size):
        off = self.file_offset(va)
        return bytes(self.memory[off:off + size])


def uvarint(b, pos):
    value, shift = 0, 0
    for i in range(10):
        v = b[pos + i]
        value |= (v & 127) << shift
        if v < 128:
            return value, pos + i + 1
        shift += 7
    raise ValueError('invalid uvarint')


def buildinfo(elf):
    marker = b'\xff Go buildinf:'
    pos = elf.b.find(marker)
    if pos == -1:
        return None
    ptrsz, flags = elf.b[pos + 14:pos + 16]
    result = dict(file_offset=hex(pos), virtual_address=hex(elf.va(pos)),
                  pointer_size=ptrsz, flags=flags)
    if flags & 2:
        size, start = uvarint(elf.b, pos + 32)
        result['go_version'] = elf.b[start:start + size].decode()
        size, start = uvarint(elf.b, start + size)
        module = elf.b[start:start + size]
        # Go framing is 16 bytes before/after the text payload.
        if len(module) > 32:
            module = module[16:-16]
        result['module_build_info'] = module.decode('utf-8', 'replace')
    return result


def metadata(elf):
    b = elf.b
    candidates = [m.start() for m in re.finditer(re.escape(b'\xf1\xff\xff\xff\0\0\x04\x08'), b)]
    for p in candidates:
        n, nf, text, fn, cu, files, pc, tab = struct.unpack_from('<8Q', b, p + 8)
        if not (1 <= n <= 100000 and p + tab + 8 * (n + 1) <= len(b)):
            continue
        functions = []
        try:
            for i in range(n):
                entry, func = struct.unpack_from('<II', b, p + tab + i * 8)
                next_entry = struct.unpack_from('<I', b, p + tab + (i + 1) * 8)[0]
                meta_entry, name_off, args, defer_return, pcsp, pcfile, pcline = struct.unpack_from(
                    '<IiIIIII', b, p + tab + func)
                assert entry == meta_entry
                name_at = p + fn + name_off
                name = b[name_at:b.index(b'\0', name_at)].decode('utf-8')
                cu_index, start_line = struct.unpack_from('<II', b, p + tab + func + 32)
                source_file = None
                if pcfile != 0:
                    delta, _ = uvarint(b, p + pc + pcfile)
                    file_index = -1 + (-(delta & 1) ^ (delta >> 1))
                    if file_index >= 0 and cu_index != 0xffffffff:
                        file_name_off = struct.unpack_from('<I', b, p + cu + (cu_index + file_index) * 4)[0]
                        file_at = p + files + file_name_off
                        source_file = b[file_at:b.index(b'\0', file_at)].decode('utf-8')
                functions.append(dict(address=text + entry, end=text + next_entry,
                                      bytes=next_entry - entry, name=name,
                                      metadata_file_offset=p + tab + func,
                                      name_file_offset=name_at, args_bytes=args,
                                      defer_return_offset=defer_return,
                                      pcsp=pcsp, pcfile=pcfile, pcline=pcline,
                                      start_line=start_line, source_file=source_file))
            return dict(pclntab_file_offset=hex(p), pclntab_virtual_address=hex(elf.va(p)),
                        magic='0xfffffff1', pointer_size=8, minimum_instruction_bytes=4,
                        function_count=n, file_count=nf, text_start=hex(text),
                        funcname_offset=hex(fn), filetab_offset=hex(files),
                        pcln_offset=hex(tab)), functions
        except (AssertionError, UnicodeDecodeError, ValueError, struct.error):
            continue
    raise ValueError('no validated Go 1.20+ pclntab found')


def go_response_types(elf, meta):
    """Decode selected Go structs via moduledata/typelinks (Go 1.21 layout).

    Relative ELF relocations are applied at image base zero in a separate memory
    view. The raw .so bytes and working APK remain unchanged.
    """
    header = int(meta['pclntab_virtual_address'], 16)
    module_at = elf.b.find(struct.pack('<Q', header), 0x3e0000)
    if module_at == -1:
        return None
    module_va = elf.va(module_at)
    module = elf.read_va(module_va, 0x178)
    types = struct.unpack_from('<Q', module, 0x128)[0]
    typelinks, count = struct.unpack_from('<QQ', module, 0x160)
    offsets = struct.unpack('<' + str(count) + 'i', elf.read_va(typelinks, count * 4))
    selected = {}
    def name_at(address):
        pos = elf.file_offset(address)
        size, at = uvarint(elf.b, pos + 1)
        return elf.b[at:at + size].decode('utf-8')
    for relative in offsets:
        address = types + relative
        rt = elf.read_va(address, 56)
        off = struct.unpack_from('<i', rt, 40)[0]
        name = name_at(types + off)
        if name not in ['*rsa.KeyPair', '*rsa.PKCS12KeyPair', '*rsa.PrivateKeyInfo', '*rsa.PublicKeyInfo']:
            continue
        if rt[23] & 31 != 22:
            continue
        struct_va = struct.unpack_from('<Q', rt, 48)[0]
        st = elf.read_va(struct_va, 80)
        fields, n = struct.unpack_from('<QQ', st, 56)
        result = []
        for j in range(n):
            np, tp, field_offset = struct.unpack('<3Q', elf.read_va(fields + j * 24, 24))
            td = elf.read_va(tp, 48)
            type_name = name_at(types + struct.unpack_from('<i', td, 40)[0])
            result.append(dict(name=name_at(np), go_type=type_name,
                               go_kind=td[23] & 31, go_size=struct.unpack_from('<Q', td)[0],
                               memory_offset=field_offset))
        selected[name[1:]] = dict(pointer_type_address=hex(address),
                                 struct_address=hex(struct_va), fields=result,
                                 confidence='Go runtime struct metadata, after ELF relative relocation resolution')
    return dict(moduledata_virtual_address=hex(module_va), types_base=hex(types),
                typelinks_address=hex(typelinks), typelinks_count=count,
                relative_relocations_applied=len(elf.relative_relocations), structs=selected)


def direct_calls(elf, f, byaddr):
    calls = []
    for address in range(f['address'], f['end'], 4):
        ins = struct.unpack('<I', elf.read_va(address, 4))[0]
        if ins & 0xfc000000 == 0x94000000:
            imm = ins & 0x3ffffff
            if imm & 0x2000000:
                imm -= 0x4000000
            target = address + imm * 4
            calls.append(dict(site=hex(address), target=hex(target),
                              name=byaddr.get(target, {}).get('name', 'unknown')))
    return calls


def disassemble(elf_path, selected, llvm, output):
    sections = []
    for groupname, begin, end in selected:
        text = subprocess.check_output([llvm, '-d', '--start-address=' + hex(begin),
                                       '--stop-address=' + hex(end), str(elf_path)], text=True)
        sections.append('/* ' + groupname + ' */\n' + text)
    output.write_text('\n'.join(sections), encoding='utf-8')


def schema_getters(elf, funcs, calls, llvm, path):
    models = {}
    for f in funcs:
        match = re.fullmatch(r'github\.com/jerson/rsa-mobile/bridge/model\.\(\*([^)]*Request)\)\.([^.]+)', f['name'])
        if not match:
            continue
        cls, field = match.groups()
        dis = subprocess.check_output([llvm, '-d', '--start-address=' + hex(f['address']),
                                       '--stop-address=' + hex(f['end']), str(path)], text=True)
        lines = dis.splitlines()
        offset = None
        for i, line in enumerate(lines):
            if 'bl\t' in line and '0x1097c0' in line: # flatbuffers.Table.Offset, metadata-checked below
                for previous in reversed(lines[max(0, i - 4):i]):
                    m = re.search(r'(?:mov\tx1,|orr\tx1, xzr,) #?(0x[0-9a-f]+)', previous)
                    if m:
                        offset = int(m.group(1), 16)
                        break
                break
        target_names = [x['name'] for x in calls[f['name']]]
        if any('ByteVector' in n for n in target_names):
            typ = '[ubyte]' if field.endswith('Bytes') else 'string'
            confidence = 'ByteVector accessor confirmed; string vs byte vector derived from wrapper conversion and field name'
        else:
            typ = 'int32'
            confidence = '32-bit load confirmed; signedness/enum semantic inferred from field name'
        models.setdefault(cls, []).append(dict(name=field, index=(offset - 4) // 2 if offset is not None else None,
                                               vtable_offset=offset, storage_type=typ,
                                               getter_address=hex(f['address']), confidence=confidence))
    for fields in models.values():
        fields.sort(key=lambda x: x['index'] if x['index'] is not None else 1000)
    return models


def dispatch_literals(elf, disassembly, byaddr):
    """Cross-check bridge string-switch comparisons against handler names.

    This extracts only MOV/MOVK immediates compared to method bytes, or full
    literals passed to runtime.memequal. It is not a general emulator.
    """
    instructions = []
    for line in disassembly.splitlines():
        m = re.match(r'\s*([0-9a-f]+):\s+[0-9a-f]+\s+([\w.]+)\s*(.*?)(?:\s+//.*)?$', line)
        if m and 0x1f56c0 <= int(m[1], 16) < 0x1f5f5c:
            instructions.append((int(m[1], 16), m[2], m[3].strip()))
    registers, facts, full_literal = {}, {}, None
    checks = {}
    def reg(n):
        return 'x' + n[1:] if n.startswith('w') else n
    def imm(s):
        return int(s.lstrip('#'), 0)
    for i, (address, mnemonic, operands) in enumerate(instructions):
        if mnemonic in ['mov', 'orr']:
            m = re.fullmatch(r'([xw]\d+), (?:(xzr), )?(#(?:0x[\da-f]+|\d+))', operands)
            if m:
                registers[reg(m[1])] = ('constant', imm(m[3]))
                continue
            m = re.fullmatch(r'([xw]\d+), ([xw]\d+|xzr|wzr)', operands)
            if m:
                # Conditional success call blocks are skipped on failure; avoid
                # invalidating the method input when linearly inspecting them.
                if m[1] != 'x0':
                    registers[reg(m[1])] = registers.get(reg(m[2]), ('unknown', 0))
                continue
        if mnemonic == 'movk':
            m = re.fullmatch(r'([xw]\d+), (#0x[\da-f]+)(?:, lsl #(\d+))?', operands)
            if m:
                rn, shift = reg(m[1]), int(m[3] or 0)
                value = registers.get(rn, ('constant', 0))[1]
                registers[rn] = ('constant', (value & ~(0xffff << shift)) | (imm(m[2]) << shift))
                continue
        if mnemonic in ['ldr', 'ldrh', 'ldrb']:
            m = re.fullmatch(r'([xw]\d+), \[x0(?:, (#0x[\da-f]+))?\]', operands)
            if m:
                size = 1 if mnemonic == 'ldrb' else 2 if mnemonic == 'ldrh' else 4 if m[1].startswith('w') else 8
                registers[reg(m[1])] = ('method_bytes', imm(m[2]) if m[2] else 0, size)
                continue
        if mnemonic == 'adrp':
            m = re.match(r'([xw]\d+), (0x[\da-f]+)', operands)
            if m:
                registers[reg(m[1])] = ('constant', int(m[2], 16))
                continue
        if mnemonic == 'add':
            m = re.fullmatch(r'([xw]\d+), ([xw]\d+), (#0x[\da-f]+)', operands)
            if m and registers.get(reg(m[2]), ('unknown',))[0] == 'constant':
                registers[reg(m[1])] = ('constant', registers[reg(m[2])][1] + imm(m[3]))
                continue
        if mnemonic == 'cmp' and i + 1 < len(instructions) and instructions[i + 1][1] == 'b.ne':
            m = re.fullmatch(r'([xw]\d+), ([xw]\d+|#0x[\da-f]+)', operands)
            if m:
                left = registers.get(reg(m[1]), ('unknown',))
                right = ('constant', imm(m[2])) if m[2].startswith('#') else registers.get(reg(m[2]), ('unknown',))
                if left[0] == 'method_bytes' and right[0] == 'constant':
                    for j, value in enumerate(right[1].to_bytes(left[2], 'little')):
                        facts[left[1] + j] = dict(byte=value, compare_site=hex(address))
                continue
        if mnemonic == 'bl':
            m = re.match(r'0x([\da-f]+)', operands)
            if not m:
                continue
            target = int(m[1], 16)
            name = byaddr.get(target, {}).get('name', '')
            if name == 'runtime.memequal':
                at = registers.get('x1', ('unknown',))
                size = registers.get('x2', ('unknown',))
                if at[0] == size[0] == 'constant':
                    full_literal = dict(method=elf.read_va(at[1], size[1]).decode(),
                                        virtual_address=hex(at[1]), bytes=size[1],
                                        compare_site=hex(address))
                    facts = {}
            elif name.startswith('github.com/jerson/rsa-mobile/bridge.instance.'):
                method = name.rsplit('.', 1)[1]
                if full_literal:
                    check = dict(method=full_literal['method'], kind='full literal passed to runtime.memequal',
                                 literal=full_literal, matches_handler=full_literal['method'] == method)
                else:
                    literal = bytes(facts[j]['byte'] for j in range(len(method)) if j in facts).decode('ascii')
                    check = dict(method=literal, kind='method byte comparisons against ARM64 immediates',
                                 compared_bytes={str(j): v for j, v in sorted(facts.items())},
                                 matches_handler=literal == method and len(facts) == len(method))
                checks[method] = check
                facts, full_literal = {}, None
    return checks


def main():
    p = argparse.ArgumentParser()
    p.add_argument('--library', type=Path, default=Path('APP/unpacked/lib/arm64-v8a/librsa_bridge.so'))
    p.add_argument('--output', type=Path, default=Path('APP/analysis/deep_rsa'))
    p.add_argument('--llvm-objdump', default='/opt/homebrew/opt/llvm/bin/llvm-objdump')
    a = p.parse_args()
    a.output.mkdir(parents=True, exist_ok=True)
    elf = ELF64(a.library.read_bytes())
    meta, funcs = metadata(elf)
    byaddr = {f['address']: f for f in funcs}
    business = [f for f in funcs if '/rsa-mobile/' in f['name'] or f['name'].startswith('main.')]
    calls = {f['name']: direct_calls(elf, f, byaddr) for f in business}
    meta['library'] = str(a.library.resolve())
    meta['sha256'] = hashlib.sha256(elf.b).hexdigest()
    meta['build_info'] = buildinfo(elf)
    meta['business_function_count'] = len(business)
    meta['address_convention'] = 'ELF virtual addresses, no ASLR base; earlier Ghidra project used +0x100000'
    def save(name, data):
        (a.output / name).write_text(json.dumps(data, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')
    save('go_metadata.json', meta)
    save('go_functions.json', funcs)
    save('business_functions.json', business)
    save('business_calls.json', calls)
    save('go_response_structs.json', go_response_types(elf, meta))
    with (a.output / 'go_functions.tsv').open('w', encoding='utf-8') as w:
        w.write('elf_address\tend\tbytes\tname\tsource_file\tstart_line\n')
        for f in funcs:
            w.write(f"0x{f['address']:x}\t0x{f['end']:x}\t{f['bytes']}\t{f['name']}\t{f['source_file']}\t{f['start_line']}\n")
    (a.output / 'go_build_info.txt').write_text(meta['build_info']['module_build_info'], encoding='utf-8')
    disassemble(a.library, [('request model accessors and enum initialization', 0x109a20, 0x10cef0),
                           ('bridge dispatch and operations', 0x1f56c0, 0x1fc7a0),
                           ('FastRSA routines', 0x1f0700, 0x1f5430)],
                a.llvm_objdump, a.output / 'business_disassembly.asm')
    schema = schema_getters(elf, funcs, calls, a.llvm_objdump, a.library)
    save('request_models.json', schema)
    literal_checks = dispatch_literals(elf, (a.output / 'business_disassembly.asm').read_text(), byaddr)
    save('dispatch_literal_checks.json', literal_checks)
    bridge = calls['github.com/jerson/rsa-mobile/bridge.Call']
    ops = []
    for call in bridge:
        if not call['name'].startswith('github.com/jerson/rsa-mobile/bridge.instance.'):
            continue
        operation = call['name'].rsplit('.', 1)[1]
        called = calls[call['name']]
        model_names = sorted({m.group(1) for c in called
                              if (m := re.search(r'\(\*([^)]*Request)\)', c['name']))})
        response_names = sorted({c['name'].rsplit('.', 1)[1] for c in called
                                 if '/bridge.instance._' in c['name']})
        rsa_names = sorted({c['name'] for c in called if '/rsa.(*FastRSA).' in c['name']})
        ops.append(dict(operation=operation, dispatch_call_site=call['site'],
                        handler_address=call['target'], handler_name=call['name'],
                        request_models=model_names,
                        fields={m: schema[m] for m in model_names},
                        response_builders=response_names, rsa_methods=rsa_names,
                        dispatch_literal_check=literal_checks.get(operation),
                        confidence='handler dispatch and calls confirmed from instructions; operation string independently checked against complete literal or immediate byte comparisons'))
    assert len(literal_checks) == len(ops) and all(v['matches_handler'] for v in literal_checks.values()), 'dispatch literal verification failed'
    save('operations.json', ops)
    lines=['// Reconstructed FlatBuffers tables. Field order verified from vtable offsets.',
           '// ByteVector is shared by strings and byte vectors; signedness/enum aliases are approximate.',
           '// Namespace and source formatting are reconstructed, not original source.',
           'namespace reconstructed_rsa;\n']
    for name, fields in sorted(schema.items()):
        lines.append('table '+ name +' {')
        for field in fields:
            lines.append('  '+ field['name'][0].lower() + field['name'][1:] + ': ' + field['storage_type'] + '; // slot ' + str(field['index']))
        lines.append('}\n')
    (a.output / 'request_models_reconstructed.fbs').write_text('\n'.join(lines)+'\n', encoding='utf-8')
    print(json.dumps(dict(functions=len(funcs), business_functions=len(business),
                          operations=len(ops), request_models=len(schema),
                          go_version=meta['build_info']['go_version'], output=str(a.output.resolve())), ensure_ascii=False))


if __name__ == '__main__':
    main()
