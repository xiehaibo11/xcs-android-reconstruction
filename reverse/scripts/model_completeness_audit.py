#!/usr/bin/env python3
"""Inventory every emitted business model and its JSON keys; static evidence only."""

from _paths import app_root, workspace_root
import argparse
import hashlib
import json
import re
from pathlib import Path
from elftools.elf.elffile import ELFFile
from capstone import Cs, CS_ARCH_ARM64, CS_MODE_ARM

APP = app_root()
OUT = APP / 'analysis/completeness_audit/models'
INDEX = APP / 'analysis/aot_runtime/function_index.json'
ELF = APP / 'unpacked/lib/arm64-v8a/libapp.so'
KEY = re.compile(r'^    // (0x[0-9a-f]+): r(2|16) = "([^"\n]*)"$', re.M)
INS = re.compile(r'^    //\s+(0x[0-9a-f]+):\s+([a-z][a-z.]*)\s+(.*)$', re.M)

def sha(p):
    return hashlib.sha256(p.read_bytes()).hexdigest()

def dump(p, value):
    p.write_text(json.dumps(value, ensure_ascii=False, indent=2) + '\n')

def collect():
    functions = json.loads(INDEX.read_text())['functions']
    files = sorted((APP / 'analysis/aot_dump/asm/distinguish/model').glob('*.dart'))
    models, methods, inputs = [], [], [{'file': str(INDEX), 'sha256': sha(INDEX)},
                                       {'file': str(ELF), 'sha256': sha(ELF)}]
    with ELF.open('rb') as stream:
        elf = ELFFile(stream)
        segments = [(s['p_vaddr'], s['p_offset'], s['p_filesz']) for s in elf.iter_segments()
                    if s['p_type'] == 'PT_LOAD']
    binary = ELF.read_bytes()
    decoder = Cs(CS_ARCH_ARM64, CS_MODE_ARM)
    decoder.detail = True
    for source in files:
        text = source.read_text()
        lines = text.splitlines(keepends=True)
        inputs.append({'file': str(source), 'sha256': sha(source)})
        subset = [f for f in functions if APP / f['path'] == source]
        classes = re.findall(r'^class ([^\s{]+).*\{$', text, re.M)
        model = {'file': str(source), 'classes': classes, 'emitted_method_count': len(subset),
                 'json_method_addresses': [], 'fields': [], 'limits': []}
        directions = {}
        for f in subset:
            start = f['line'] - 1
            end = next((i for i in range(start + 2, len(lines))
                        if re.match(r'  \S.*\{', lines[i]) or lines[i].startswith('// class id:')), len(lines))
            body = ''.join(lines[start:end])
            instructions = [(int(m[1], 16), m[2], m[3]) for m in INS.finditer(body)]
            address = int(f['address'], 16)
            effective_end = max(x[0] for x in instructions) + 4
            assert [x[0] for x in instructions] == list(range(address, effective_end, 4)), f
            offset = next(off + address - va for va, off, size in segments
                          if va <= address and effective_end <= va + size)
            raw = binary[offset:offset + effective_end - address]
            item = {key: f[key] for key in ['class', 'signature', 'address', 'size', 'line']}
            item.update(source=str(source), source_sha256=sha(source), line_end=end,
                        effective_size=hex(effective_end-address), raw_body_sha256=hashlib.sha256(raw).hexdigest(),
                        declared_size_overreport=int(f['size'],16)-(effective_end-address),
                        keys=[])
            if 'fromJson' in f['signature'] or 'toJson' in f['signature']:
                direction = 'fromJson' if 'fromJson' in f['signature'] else 'toJson'
                item['direction'] = direction
                model['json_method_addresses'].append(f['address'])
                excerpt = OUT / 'complete_methods' / (f['address'][2:] + '.asm.txt')
                item['complete_excerpt'] = str(excerpt)
                item['complete_excerpt_sha256'] = hashlib.sha256(body.encode()).hexdigest()
                item['_body'] = body
                occurrences = list(KEY.finditer(body))
                for i, match in enumerate(occurrences):
                    finish = occurrences[i+1].start() if i+1 < len(occurrences) else len(body)
                    block = body[match.start():finish]
                    # Array-literal serializers load values after r16 key; MjConfig setter loads before r2 key.
                    readblock = block
                    read_start = match.start()
                    if direction == 'toJson' and match[2] == '2':
                        previous = occurrences[i-1].end() if i else 0
                        readblock = body[previous:match.start()]
                        read_start = previous
                    slots = re.findall(r'LoadField:.*?->field_([0-9a-f]+)', readblock)
                    slots += [hex(int(x, 0))[2:] for x in re.findall(
                        r'ArrayLoad:[^\n]+\n    //\s+0x[0-9a-f]+: ldur\s+[wdx]\d+, \[x\d+, #((?:0x)?[0-9]+)\]', readblock)]
                    # Preserve each observed type test, without inventing a validator for untyped fields.
                    record = {'key': match[3], 'key_address': match[1],
                              'source_line_start': start + body[:match.start()].count('\n') + 1,
                              'source_line_end': start + body[:finish].count('\n'),
                              'type_tests': re.findall(r'r8 = ([^\n]+)', block) if direction == 'fromJson' else [],
                              'model_slot': '0x' + slots[-1] if direction == 'toJson' and len(set(slots)) == 1 else None,
                              'observed_slot_candidates': sorted(set('0x'+s for s in slots)) if direction == 'toJson' else [],
                              'direct_conversion_calls': re.findall(r'; \[(dart:core\] DateTime::[^\n]+|package:distinguish/model/[^\n]+)', block),
                              'status': 'observed key and local operations; not server-side schema'}
                    if direction == 'toJson':
                        record['slot_read_source_line_start'] = start + body[:read_start].count('\n') + 1
                        record['slot_read_source_line_end'] = start + body[:read_start+len(readblock)].count('\n')
                        record['slot_instruction_evidence'] = []
                        pattern = r'^    // (0x[0-9a-f]+): (?:LoadField:|ArrayLoad:)[^\n]+\n    //     (0x[0-9a-f]+): ldur\s+([wdx]\d+), \[x\d+, #((?:0x)?[0-9a-f]+)\]'
                        for load in re.finditer(pattern, readblock, re.M):
                            va = int(load[2],16)
                            displacement = int(load[4],0)
                            raw_off = next(off+va-v for v,off,n in segments if v<=va and va+4<=v+n)
                            word = binary[raw_off:raw_off+4]
                            decoded = next(decoder.disasm(word,va))
                            assert load[1] == load[2] and decoded.mnemonic == 'ldur'
                            assert decoded.operands[-1].mem.disp == displacement
                            record['slot_instruction_evidence'].append({
                                'address':load[2], 'slot':hex(displacement),
                                'source_line':start + body[:read_start+load.start()].count('\n')+2,
                                'elf_file':str(ELF), 'file_offset':raw_off, 'bytes_le':word.hex(),
                                'decoded_mnemonic':decoded.mnemonic,'decoded_operands':decoded.op_str})
                    item['keys'].append(record)
                    directions.setdefault((f['class'], match[3]), {}).setdefault(direction, []).append(record)
            methods.append(item)
        for (cls, key), detail in directions.items():
            readers = detail.get('fromJson', [])
            writers = detail.get('toJson', [])
            field = {'class': cls, 'key': key, 'fromJson': readers, 'toJson': writers,
                     'model_slot': next((x['model_slot'] for x in writers if x['model_slot']), None),
                     'observed_input_type_tests': sorted(set(t for x in readers for t in x['type_tests'])),
                     'interpretation': 'Local getter/type-test and serializer field-read contract.'}
            if cls == 'Message' and key == 'msg_content':
                field['interpretation'] = 'fromJson preserves dynamic content; toJson writes null for null content, otherwise calls GDT[cid+0x6d49] on field_b. Indirect target semantics not inferred here.'
            if cls == 'Devices':
                if key == 'create_time':
                    field['interpretation'] = 'Non-null String type test then DateTime.parse; serialization calls toIso8601String.'
                elif key == 'version':
                    field['interpretation'] = 'Getter value is the receiver of an indirect call; its result is later unboxed as double and stored at field_37. The x4=0 call-site metadata is not a null fallback; target, null handling, and accepted input classes remain unconfirmed.'
                elif not field['observed_input_type_tests']:
                    field['interpretation'] = 'No local type-test stub observed in this getter block; preserve dynamic value, do not infer strict type from key name.'
            if cls == 'ViewSetting':
                defaults = {'orientationMjHeight':3.0,'orientationMjWidth':1.9,'orientationHeight':640.0,
                            'validMjWidth':34.0,'validMjHeight':70.0,'editMjWidth':60.0,'editMjHeight':64.0,
                            'orientationAiVis':True}
                field['interpretation'] = 'Getter result is discarded; factory writes fixed constructor value.'
                field['factory_value'] = defaults[key]
                # orientationHeight lives at +0x17; serializer uses ArrayLoad IR at this offset.
                if key == 'orientationHeight': field['model_slot'] = '0x17'
            if cls == 'MjConfig':
                field['interpretation'] = 'Serializer setter verified; no standalone fromJson method emitted in this model file.'
            model['fields'].append(field)
        if not directions:
            model['limits'].append('No standalone JSON converter emitted; constructors/field consumers may be inlined elsewhere. Not an assertion that JSON is unsupported.')
        model['limits'].append('Field names/types do not establish backend requirements, enum meanings, or all business validation.')
        models.append(model)
    return {'scope': 'All 16 emitted business model files; exact JSON-key inventory and bounded local contracts.',
            'model_file_count': len(models), 'model_method_count': len(methods),
            'json_method_count': sum('direction' in m for m in methods),
            'distinct_class_key_contracts': sum(len(m['fields']) for m in models),
            'json_key_occurrences': sum(len(m['keys']) for m in methods),
            'models': models, 'methods': methods, 'inputs': inputs}

def public(data):
    data = json.loads(json.dumps(data))
    for method in data['methods']: method.pop('_body', None)
    return data

def verify():
    stored = json.loads((OUT / 'model_field_contracts.json').read_text())
    current = collect()
    errors = []
    if stored != public(current): errors.append('Inventory differs from original model files / ELF / function index')
    for m in current['methods']:
        if '_body' in m:
            p = Path(m['complete_excerpt'])
            if not p.is_file() or p.read_text() != m['_body']: errors.append('Complete excerpt mismatch: '+str(p))
    result = {'status':'FAIL' if errors else 'PASS', 'model_files':current['model_file_count'],
              'model_methods':current['model_method_count'], 'json_methods':current['json_method_count'],
              'class_key_contracts':current['distinct_class_key_contracts'],
              'json_key_occurrences':current['json_key_occurrences'], 'errors':errors,
              'independently_decoded_serializer_slot_loads':sum(len(k.get('slot_instruction_evidence',[])) for m in current['methods'] for k in m['keys']),
              'scope':'Byte-backed inventory/local JSON contracts; not whole business semantics or server schema.',
              'script':str(Path(__file__).resolve()), 'script_sha256':sha(Path(__file__))}
    dump(OUT/'verification.json', result)
    print(json.dumps(result,ensure_ascii=False))
    return not errors

if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--verify',action='store_true')
    args = parser.parse_args()
    OUT.mkdir(parents=True,exist_ok=True)
    if not args.verify:
        data=collect()
        (OUT/'complete_methods').mkdir(exist_ok=True)
        for m in data['methods']:
            if '_body' in m: Path(m['complete_excerpt']).write_text(m['_body'])
        dump(OUT/'model_field_contracts.json',public(data))
        report=['模型 JSON 字段完整性补齐（静态证据）',
                '库存覆盖全部16个模型文件，记录每个已输出转换器及全部字符串键；未输出转换器单独标注。',
                '类型只取显式类型测试，缺少测试保留未知；槽位来自序列化器真实字段读取，不由键顺序猜测。',
                '全部序列化字段ldur已由原ELF和Capstone独立核验地址/槽位；JSON键及类型名仍来自Blutter对象池解码，不等于后端Schema。',
                'Devices.create_time读取String后DateTime.parse，序列化为ISO8601；version走间接调用、结果按double拆箱，x4=0不是null回退证据。',
                'Devices的键 img_min_hreshold 为APK实际拼写，不能改成img_min_threshold。',
                'Message.msg_content构造时保留dynamic；toJson对null写null，非null走GDT[cid+0x6d49]间接调用，此库存不猜调用目标。',
                'ViewSetting.fromJson读取8个键但丢弃结果，返回固定值；不能当作恢复用户设置。',
                '本库存不能证明后端必填字段、枚举完整含义、所有业务校验或原始源码恢复。','']
        for model in data['models']:
            report.append(Path(model['file']).name+': '+str(model['emitted_method_count'])+' methods')
            for f in model['fields']:
                report.append('  '+f['class']+'.'+f['key']+' | '+str(f['model_slot'])+' | '+','.join(f['observed_input_type_tests'])+' | '+f['interpretation']+((' default='+str(f['factory_value'])) if 'factory_value' in f else ''))
            for limit in model['limits']: report.append('  边界: '+limit)
        (OUT/'模型字段补齐说明.txt').write_text('\n'.join(report)+'\n')
    raise SystemExit(0 if verify() else 1)
