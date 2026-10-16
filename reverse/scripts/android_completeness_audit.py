#!/usr/bin/env python3
"""APK/DEX/smali/Android completeness audit. Static parsing only; --verify is read-only."""

from _paths import app_root, workspace_root
import argparse
import collections
import hashlib
import json
import re
import shutil
import struct
import subprocess
import xml.etree.ElementTree as ET
import zipfile
import zlib
from pathlib import Path

ROOT = workspace_root()
APP = ROOT / 'APP'
OUT = APP / 'analysis/completeness_audit/android'
APK = ROOT / 'app_xcs(新).apk.1.1'
WORK = APP / 'input/app_xcs.apk'
DECODED = APP / 'apktool/decoded'
ANDROID = '{http://schemas.android.com/apk/res/android}'

def sha(data):
    return hashlib.sha256(data).hexdigest()

def file_record(p):
    b = p.read_bytes()
    return {'file': str(p), 'bytes': len(b), 'sha256': sha(b)}

def save(name, obj):
    p = OUT / name
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(json.dumps(obj, ensure_ascii=False, indent=2) + '\n')

def evidence(p, first, last):
    ls = p.read_text().splitlines()
    return {'file': str(p), 'sha256': sha(p.read_bytes()), 'start_line': first,
            'end_line': last, 'excerpt': '\n'.join(ls[first-1:last])}

def parse_dex(p):
    b = p.read_bytes()
    def u32(o): return struct.unpack_from('<I', b, o)[0]
    def uleb(o):
        n = 0
        for shift in range(0, 35, 7):
            v = b[o]; o += 1; n |= (v & 127) << shift
            if not v & 128: return n, o
        raise ValueError('invalid ULEB128')
    assert b[:4] == b'dex\n' and b[7] == 0
    assert u32(0x20) == len(b) and u32(0x24) == 0x70 and u32(0x28) == 0x12345678
    assert hashlib.sha1(b[32:]).digest() == b[12:32]
    assert zlib.adler32(b[12:]) & 0xffffffff == u32(8)
    sn, so = u32(0x38), u32(0x3c)
    tn, to = u32(0x40), u32(0x44)
    pn, po = u32(0x48), u32(0x4c)
    fn, fo = u32(0x50), u32(0x54)
    mn, mo = u32(0x58), u32(0x5c)
    cn, co = u32(0x60), u32(0x64)
    def string(i):
        _, o = uleb(u32(so + i*4))
        return b[o:b.index(0, o)].decode('utf8', 'replace')
    types = [string(u32(to + i*4)) for i in range(tn)]
    protos = []
    for i in range(pn):
        _, ret, param = struct.unpack_from('<III', b, po + i*12)
        params = [] if not param else [types[struct.unpack_from('<H', b, param+4+j*2)[0]] for j in range(u32(param))]
        protos.append('(' + ''.join(params) + ')' + types[ret])
    methods = []
    for i in range(mn):
        cls, proto, name = struct.unpack_from('<HHI', b, mo+i*8)
        methods.append((types[cls], string(name)+protos[proto]))
    fields = []
    for i in range(fn):
        cls, typ, name = struct.unpack_from('<HHI', b, fo+i*8)
        fields.append((types[cls], string(name)+':'+types[typ]))
    classes = []
    for i in range(cn):
        cls, access, superclass, interfaces, source, annotations, dataoff, statics = struct.unpack_from('<IIIIIIII', b, co+i*32)
        entries = []; defined_fields = []
        if dataoff:
            sf, q = uleb(dataoff); inf, q = uleb(q); dm, q = uleb(q); vm, q = uleb(q)
            for kind, count in [('static', sf), ('instance', inf)]:
                idx = 0
                for _ in range(count):
                    diff, q = uleb(q); flags, q = uleb(q); idx += diff
                    owner, signature = fields[idx]; assert owner == types[cls]
                    defined_fields.append({'signature':signature,'field_id':idx,'access_flags':flags,'kind':kind})
            for kind, count in [('direct', dm), ('virtual', vm)]:
                idx = 0
                for _ in range(count):
                    diff, q = uleb(q); flags, q = uleb(q); code, q = uleb(q); idx += diff
                    owner, signature = methods[idx]
                    assert owner == types[cls]
                    entry = {'signature': signature, 'method_id': idx, 'access_flags': flags, 'kind': kind, 'code_offset': code}
                    if code:
                        units = u32(code+12); raw = b[code+16:code+16+units*2]
                        assert len(raw) == units*2
                        entry.update({'instruction_code_units': units, 'instruction_bytes_sha256': sha(raw)})
                    entries.append(entry)
        classes.append({'descriptor': types[cls], 'access_flags': access, 'class_def_offset': co+i*32, 'class_data_offset': dataoff, 'methods': entries, 'fields':defined_fields})
    return {'source': file_record(p), 'dex_version': b[4:7].decode(), 'header_signature_and_checksum_valid': True,
            'class_defs': cn, 'method_ids': mn, 'field_ids':fn,'encoded_fields':sum(len(c['fields']) for c in classes),'encoded_methods': sum(len(c['methods']) for c in classes),
            'encoded_methods_with_code': sum(bool(m['code_offset']) for c in classes for m in c['methods']), 'classes': classes}

def smali_inventory():
    result = []
    for root in sorted(DECODED.glob('smali*')):
        if not root.is_dir(): continue
        for p in sorted(root.rglob('*.smali')):
            ls = p.read_text().splitlines()
            cls = next(re.search(r'(L[^\s]+;)$', l).group(1) for l in ls if l.startswith('.class '))
            methods = []
            fields = []
            for i, line in enumerate(ls):
                if line.startswith('.field '):
                    fields.append({'signature':line.split(' = ',1)[0].split()[-1],'line':i+1})
                if line.startswith('.method '):
                    sig = line.split()[-1]
                    end = next(j for j in range(i+1, len(ls)) if ls[j] == '.end method')
                    flags=line.split()[1:-1]
                    methods.append({'signature': sig, 'start_line': i+1, 'end_line': end+1,'has_code':not ('abstract' in flags or 'native' in flags),
                                    'excerpt_sha256': sha(('\n'.join(ls[i:end+1])+'\n').encode())})
            result.append({'source': file_record(p), 'smali_root': root.name, 'descriptor': cls, 'methods': methods, 'fields':fields})
    return result

def zip_audit(write=False):
    with zipfile.ZipFile(APK) as z:
        groups=collections.defaultdict(list)
        for i in z.infolist():
            if not i.is_dir():groups[i.filename.casefold()].append(i.filename)
        collisions=[v for v in groups.values() if len(v)>1]
        colliding={x for v in collisions for x in v}
        entries = []
        for i in z.infolist():
            if i.is_dir(): continue
            b = z.read(i); p = APP / 'unpacked' / i.filename
            record = {'entry': i.filename, 'zip_bytes': len(b), 'zip_sha256': sha(b), 'zip_crc32': f'{i.CRC:08x}',
                      'extracted_file': str(p), 'exists': p.is_file()}
            if p.is_file():
                raw = p.read_bytes(); record.update({'extracted_bytes': len(raw), 'extracted_sha256': sha(raw), 'matches': raw == b})
            else: record['matches'] = False
            if i.filename in colliding:
                target=OUT/'case_safe_entries'/(i.filename.encode().hex()+Path(i.filename).suffix)
                if write:target.parent.mkdir(parents=True,exist_ok=True);target.write_bytes(b)
                record.update({'audit_canonical_file':str(target),'audit_canonical_sha256':sha(target.read_bytes()) if target.exists() else None,
                               'effective_matches':target.exists() and target.read_bytes()==b})
            else:record.update({'audit_canonical_file':str(p),'audit_canonical_sha256':record.get('extracted_sha256'),'effective_matches':record['matches']})
            entries.append(record)
    names = [e['entry'] for e in entries]
    extracted = {str(p.relative_to(APP/'unpacked')) for p in (APP/'unpacked').rglob('*') if p.is_file()}
    return {'original_apk': file_record(APK), 'working_apk': file_record(WORK), 'working_copy_matches': APK.read_bytes()==WORK.read_bytes(),
            'non_directory_entries': len(entries), 'duplicate_zip_names': [n for n,c in collections.Counter(names).items() if c>1],
            'unpacked_extra_files': sorted(extracted-set(names)), 'mismatch_entries': [e['entry'] for e in entries if not e['matches']],
            'casefold_collisions':collisions,'casefold_collision_same_inode':[{'entries':v,'inodes':[str((APP/'unpacked'/n).stat().st_ino) for n in v]} for v in collisions],
            'effective_mismatch_entries':[e['entry'] for e in entries if not e['effective_matches']],
            'entry_path_index_boundary':'Case-colliding ZIP names are mapped to separate hex-encoded audit paths; APP/unpacked on this macOS filesystem cannot hold both byte-distinct entries under their original names.', 'entries': entries}

FAILED = [
    ('r2/a.java','Lr2/a$a;','m(Ljava/lang/Object;)Ljava/lang/Object;',r'public final (?:java\.lang\.)?Object m\('),
    ('q6/q.java','Lq6/q$a;','m(Ljava/lang/Object;)Ljava/lang/Object;',r'public final (?:java\.lang\.)?Object m\('),
    ('g2/b.java','Lg2/b$a;','b(Lz0/s;J)Z',r'public boolean b\(z0\.s'),
    ('x1/a.java','Lx1/a;','M(BB)V',r'(?:public|private|protected).* void M\('),
    ('p6/g.java','Lp6/g;','c(Lp6/d;Lo6/t;ZLv5/d;)Ljava/lang/Object;',r'(?:public|private|protected).* (?:java\.lang\.)?Object c\('),
    ('p6/n.java','Lp6/n;','c(Lp6/d;Lv5/d;)Ljava/lang/Object;',r'public (?:final )?(?:java\.lang\.)?Object c\('),
    ('c2/d.java','Lc2/d;','m(Lorg/xmlpull/v1/XmlPullParser;ILc2/d$b;)Lc2/e;',r'(?:public|private|protected).* (?:c2\.)?e m\('),
    ('b0/j1.java','Lb0/j1;','e0(JJ)V',r'(?:public|private|protected).* void e0\('),
]

def jadx_audit(smali, write):
    files = sorted((APP/'jadx/sources').rglob('*.java'))
    markers = []
    warnings = []
    for p in files:
        for i,l in enumerate(p.read_text().splitlines(),1):
            if 'JADX ERROR:' in l or 'Method not decompiled:' in l or 'Method dump skipped' in l:
                markers.append({'file': str(p), 'sha256': sha(p.read_bytes()), 'line': i, 'text': l.strip()})
            if 'JADX WARN:' in l:
                warnings.append({'file': str(p), 'line': i, 'text': l.split('JADX WARN:',1)[1].split('*/')[0].strip()})
    by_cls = {c['descriptor']:c for c in smali}
    failures = []
    for rel, cls, sig, rx in FAILED:
        primary = APP/'jadx/sources'/rel; fallback = APP/'jadx_fallback'/rel
        sc = by_cls[cls]; sm = next(m for m in sc['methods'] if m['signature']==sig)
        sp = Path(sc['source']['file'])
        fl = fallback.read_text().splitlines()
        matches = [i for i,l in enumerate(fl) if re.search(rx,l)]
        # g2.b contains a second nested implementation with the same method signature;
        # the failed owner is g2.b$a (first implementation), not g2.b$c (second).
        target_matches=matches[:1] if cls=='Lg2/b$a;' else matches
        # A complete fallback file and exact authoritative smali method are frozen separately.
        item = {'class_descriptor': cls, 'method_signature': sig, 'primary': file_record(primary), 'fallback': file_record(fallback),
                'fallback_method_declaration_lines': [i+1 for i in target_matches], 'fallback_same_signature_declaration_lines': [i+1 for i in matches],
                'fallback_method_declaration_match_count': len(target_matches),
                'fallback_has_error_or_not_decompiled_stub': bool(re.search(r'JADX ERROR|Method not decompiled|Method dump skipped',fallback.read_text())),
                'fallback_quality': 'simple register/goto pseudo-Java; not compilable Java and not a proof of semantic equivalence',
                'authoritative_smali_method': evidence(sp,sm['start_line'],sm['end_line']),
                'smali_snapshot': str(OUT/'failed_methods'/f'{cls[1:-1].replace("/","_")}_{sig.split("(")[0]}.smali'),
                'fallback_snapshot': str(OUT/'fallback_snapshot'/rel)}
        if write:
            dst=Path(item['smali_snapshot']);dst.parent.mkdir(parents=True,exist_ok=True);dst.write_text(item['authoritative_smali_method']['excerpt']+'\n')
            dst=Path(item['fallback_snapshot']);dst.parent.mkdir(parents=True,exist_ok=True);shutil.copyfile(fallback,dst)
        failures.append(item)
    log=OUT/'jadx_reaudit_debug.log'
    text=log.read_text() if log.exists() else ''
    nodes=re.findall(r'ERROR\s+-\s+Method: ([^\n\r]+)',text)
    unknown_refs=re.findall(r'DEBUG\s+-\s+(androidx\.window\.sidecar\.SidecarInterface\$SidecarCallback|org\.conscrypt\.ConscryptHostnameVerifier)',text)
    error_lines=[{'line':i,'text':l.strip()} for i,l in enumerate(text.splitlines(),1) if 'ERROR' in l and ('in method:' in l or 'Method:' in l or 'errors occurred' in l or 'finished with errors' in l)]
    return {'primary_java_files':len(files),'primary_marker_inventory':markers,'primary_error_marker_count':sum('JADX ERROR:' in x['text'] for x in markers),
            'primary_not_decompiled_stub_count':sum('Method not decompiled:' in x['text'] for x in markers),
            'initial_log':file_record(APP/'logs/jadx.log'),'initial_reported_errors':11,
            'reaudit_debug_log':file_record(log) if log.exists() else None,'reaudit_distinct_error_nodes':nodes,'reaudit_error_lines':error_lines,
            'reaudit_unknown_class_references':unknown_refs,
            'unknown_reference_boundary':'Two externally referenced class names reported by JADX; not absent DEX class_defs. Whether their optional runtime provider supplies them is not proven statically.',
            'error_accounting':'Reaudit reports 11 errors on 8 distinct Method nodes; x1.a.M, p6.n.c and g2.b.a.b each appear twice in pass errors. The original terse log did not name its nodes; the rerun reproduces the total and same 8 hard-failure methods.',
            'failed_methods':failures,'fallback_java_files':len(list((APP/'jadx_fallback').rglob('*.java'))),
            'primary_warning_count':len(warnings),'primary_warning_files':len({w['file'] for w in warnings}),
            'warnings':warnings,'warning_kind_counts':dict(collections.Counter(w['text'] for w in warnings)),
            'remaining_semantic_gap':'8 fallback files cover the 8 named hard failures, not all warning methods. 1299 primary warning markers include inference/control-flow/constructor reordering warnings. Smali/class/method presence does not prove each reconstructed Java method is semantically correct.',
            'source_inventory':[file_record(p) for p in files]}

def attrs(e): return {k.removeprefix(ANDROID):v for k,v in e.attrib.items()}

def manifest_audit():
    p=DECODED/'AndroidManifest.xml';root=ET.parse(p).getroot();app=root.find('application')
    perms=[attrs(e) for e in root.findall('uses-permission')]
    comps=[]
    for e in app:
        if e.tag in ['activity','activity-alias','service','receiver','provider']:
            item={'type':e.tag,**attrs(e),'intent_filters':[],'metadata':[attrs(m) for m in e.findall('meta-data')]}
            for f in e.findall('intent-filter'):
                item['intent_filters'].append({t:[attrs(x) for x in f.findall(t)] for t in ['action','category','data']})
            comps.append(item)
    oldp=APP/'analysis/deep_android/component_surface.json';old=json.loads(oldp.read_text())
    expected={(x['type'],x['name']) for x in comps};actual={(x['type'],x['name']) for x in old['components']}
    refs=[]
    for name in ['network_security_config','filepaths','image_share_filepaths']:
        f=DECODED/f'res/xml/{name}.xml'
        if f.exists(): refs.append(file_record(f))
    return {'source':file_record(p),'manifest_attributes':attrs(root),'application_attributes':attrs(app),
            'permissions':perms,'custom_permissions':[attrs(x) for x in root.findall('permission')],
            'components':comps,'queries':[ET.tostring(q,encoding='unicode') for q in root.findall('queries')],
            'application_metadata':[attrs(m) for m in app.findall('meta-data')],
            'optional_libraries':[attrs(m) for m in app.findall('uses-library')], 'referenced_security_and_provider_xml':refs,
            'existing_component_report':file_record(oldp),'existing_component_report_missing_components':sorted(expected-actual),
            'existing_component_report_extra_components':sorted(actual-expected),
            'existing_component_report_permissions_equal':perms==old['permissions'],
            'existing_component_report_component_attributes_equal':sorted(comps,key=lambda x:(x['type'],x['name']))==sorted(old['components'],key=lambda x:(x['type'],x['name']))}

PLUGIN_CLASSES={'audioplayers_android':'p7.d','device_info_plus':'s4.a','fast_rsa':'w4.a','integration_test':'r4.i',
                'ota_update':'o7.b','package_info_plus':'t4.c','path_provider_android':'n5.j','photo_manager':'a4.b',
                'shared_preferences_android':'o5.l','url_launcher_android':'p5.j','video_player_android':'q5.b0',
                'wakelock_plus':'u4.c','webview_flutter_android':'io.flutter.plugins.webviewflutter.t6','wifi_scan':'v4.d'}

def android_channels(smali,write):
    oldp=APP/'analysis/deep_android/android_channels.json';old=json.loads(oldp.read_text())
    oldnames={c['name'] for c in old['channels']}
    constructors=[];selected=[]
    for cls in smali:
        p=Path(cls['source']['file']);ls=p.read_text().splitlines()
        for method in cls['methods']:
            regs={};lastinvoke='';recent=[]
            for i in range(method['start_line']-1,method['end_line']):
                line=ls[i].strip()
                m=re.match(r'const-string(?:/jumbo)? (\w+), "(.*)"$',line)
                if m: regs[m[1]]=m[2];recent.append(m[2])
                m=re.match(r'move-object(?:/from16|/16)? (\w+), (\w+)',line)
                if m: regs[m[1]]=regs.get(m[2])
                m=re.match(r'move-result-object (\w+)',line)
                if m: regs[m[1]]=None
                # Other register writes must invalidate previous constants. The parser does
                # not model branches; registrations retain this lexical-analysis boundary.
                m=re.match(r'(?:iget\S*|sget\S*|aget\S*|new-instance|new-array|const(?:/\S+)?|check-cast) (\w+)[, ]',line)
                if m:regs[m[1]]=None
                if 'invoke-' in line: lastinvoke=line
                m=re.search(r'invoke-direct(?:/range)? \{([^}]+)\}, Lj5/([kad]);-><init>\(',line)
                if not m:continue
                args=[r.strip() for r in m[1].split(',')]
                kind={'k':'MethodChannel','a':'BasicMessageChannel','d':'EventChannel'}[m[2]]
                internal=cls['descriptor'] in ['Lj5/k;','Lj5/a;','Lj5/d;']
                literal=regs.get(args[2]) if len(args)>2 else None
                candidates=[s for s in recent[-12:] if '/' in s or s.startswith('dev.flutter.')]
                prefix=None if literal is not None else (candidates[-1] if candidates else None)
                name=literal or prefix
                record={'class_descriptor':cls['descriptor'],'method_signature':method['signature'],'kind':kind,
                        'constructor_signature':line.split('}, ',1)[1], 'name_literal':literal,'name_prefix_candidate':prefix,
                        'name_resolution':'direct const-string register, lexical within method' if literal is not None else 'unresolved; nearest channel-like literal is only a candidate prefix',
                        'internal_constructor_delegation':internal,'source':evidence(p,i+1,i+1),
                        'full_method_source':{'file':str(p),'sha256':cls['source']['sha256'],'start_line':method['start_line'],'end_line':method['end_line']},
                        'previous_selected_report_name_match':name in oldnames}
                constructors.append(record)
                if not internal:selected.append((p,method))
    snap=[]
    for p,m in { (str(p),m['signature']):(p,m) for p,m in selected}.values():
        target=OUT/'channel_smali_methods'/str(p.relative_to(DECODED/'smali')).replace('/','_').replace('.smali','')
        target=target.with_name(target.name+'_'+re.sub(r'[^A-Za-z0-9_]','_',m['signature'])+'.smali')
        ev=evidence(p,m['start_line'],m['end_line'])
        if write: target.parent.mkdir(parents=True,exist_ok=True);target.write_text(ev['excerpt']+'\n')
        snap.append({'source':ev,'snapshot':str(target)})
    regp=APP/'jadx/sources/io/flutter/plugins/GeneratedPluginRegistrant.java';reg=regp.read_text();imports={s.rsplit('.',1)[-1]:s for s in re.findall(r'import ([\w.]+);',reg)}
    oldregp=APP/'analysis/deep_android/registered_plugins.json';oldreg=json.loads(oldregp.read_text());plugins=[]
    for x in oldreg['plugins']:
        resolved=imports.get(x['obfuscated_class'],x['obfuscated_class'])
        assert resolved==PLUGIN_CLASSES[x['plugin']]
        plugins.append({**x,'resolved_dex_class':resolved,'dex_descriptor':'L'+resolved.replace('.','/')+';',
                        'source_class_present':any(c['descriptor']=='L'+resolved.replace('.','/')+';' for c in smali),
                        'selected_previous_channel_analysis':x['plugin'] in ['ota_update','path_provider_android','photo_manager','shared_preferences_android','wifi_scan']})
    return {'registrant':file_record(regp),'old_plugin_inventory':file_record(oldregp),'plugins':plugins,
            'previous_selected_channel_report':file_record(oldp),'previous_selected_channel_names':sorted(oldnames),
            'constructor_calls_total':len(constructors),'internal_constructor_delegations':sum(c['internal_constructor_delegation'] for c in constructors),
            'callsite_inventory':constructors,'full_registration_method_snapshots':snap,
            'scope':'All 5133 smali classes scanned for direct invokes of j5.k/d/a constructors. Exact direct constants and unresolved names are recorded; this is registration inventory, not all protocol arguments/results or evidence of Dart business calls. No reflection/dynamic-code proof.',
            'remaining_analysis_gap':'Previous deep_android covers 5 of 14 plugins plus MainActivity backDesktop. Audio/device-info/fast-rsa/integration-test/package-info/url-launcher/video/wakelock/webview interface semantics not exhaustively restored there. This audit freezes their constructor-containing methods but does not claim whole plugin behavior completion.'}

def resources(ziprecord):
    exe=shutil.which('aapt');assert exe,'existing aapt required for reproducible resource mapping'
    raw=subprocess.check_output([exe,'dump','--values','resources',str(APK)],text=True)
    mappings=[];config='';res=None
    for line in raw.splitlines():
        m=re.match(r'\s+config ([^:]+):',line)
        if m:config=m[1]
        m=re.match(r'\s+resource (0x[\da-f]+) [^:]+:(\w+)/([^:]+):',line)
        if m:res=(m[1],m[2],m[3])
        m=re.match(r'\s+\(string\d+\) "(res/[^\"]+)"',line)
        if m and res:
            path=m[1];suffix=Path(path).suffix
            directory=res[1]+('' if config=='(default)' else '-'+config)
            decoded=DECODED/'res'/directory/(res[2]+suffix)
            # aapt strips .9 from some resource paths; choose exact existing .9.png if necessary.
            if not decoded.exists() and suffix=='.png':
                alt=decoded.with_name(res[2]+'.9.png')
                if alt.exists():decoded=alt
            mappings.append({'zip_entry':path,'resource_id':res[0],'resource_type':res[1],'resource_name':res[2],'config':config,
                             'decoded_file':str(decoded),'decoded_exists':decoded.is_file(),
                             'decoded_sha256':sha(decoded.read_bytes()) if decoded.is_file() else None})
    rawres={e['entry'] for e in ziprecord['entries'] if e['entry'].startswith('res/')}
    mapped={r['zip_entry'] for r in mappings}
    return {'aapt_tool':exe,'aapt_version':subprocess.check_output([exe,'version'],text=True).strip(),
            'original_resource_table':file_record(APP/'unpacked/resources.arsc'),'raw_res_zip_entries':len(rawres),
            'resource_file_mappings':mappings,'unmapped_raw_res_entries':sorted(rawres-mapped),
            'mappings_to_missing_decoded_files':[r for r in mappings if not r['decoded_exists']],
            'comparison_boundary':'APK/unpacked resources are byte compared; apktool XML/png are transformed outputs, checked by ARSC resource name/config inventory and file presence, not asserted byte/semantic equality.'}

def build(write):
    z=zip_audit(write);dex=[parse_dex(p) for p in sorted((APP/'unpacked').glob('classes*.dex'))];sm=smali_inventory()
    comparisons=[]
    for d in dex:
        name=Path(d['source']['file']).stem;sr='smali' if name=='classes' else 'smali_'+name
        canonical={c['descriptor']:c for c in d['classes']};dec=[c for c in sm if c['smali_root']==sr];parsed={c['descriptor']:c for c in dec}
        diffs=[]; fielddiffs=[]; codemismatch=[]
        for cls in canonical.keys()&parsed.keys():
            a=[m['signature'] for m in canonical[cls]['methods']];b=[m['signature'] for m in parsed[cls]['methods']]
            if collections.Counter(a)!=collections.Counter(b):diffs.append({'class':cls,'dex_only':list((collections.Counter(a)-collections.Counter(b)).elements()),'smali_only':list((collections.Counter(b)-collections.Counter(a)).elements())})
            a=[f['signature'] for f in canonical[cls]['fields']];b=[f['signature'] for f in parsed[cls]['fields']]
            if collections.Counter(a)!=collections.Counter(b):fielddiffs.append({'class':cls,'dex_only':list((collections.Counter(a)-collections.Counter(b)).elements()),'smali_only':list((collections.Counter(b)-collections.Counter(a)).elements())})
            dm={m['signature']:bool(m['code_offset']) for m in canonical[cls]['methods']};smcode={m['signature']:m['has_code'] for m in parsed[cls]['methods']}
            if dm!=smcode:codemismatch.append({'class':cls,'different_signatures':[s for s in dm.keys()&smcode.keys() if dm[s]!=smcode[s]]})
        comparisons.append({'dex_file':d['source']['file'],'expected_smali_root':sr,'dex_class_defs':len(canonical),'smali_files':len(dec),
                            'missing_classes':sorted(canonical.keys()-parsed.keys()),'extra_classes':sorted(parsed.keys()-canonical.keys()),'method_inventory_mismatches':diffs,'field_inventory_mismatches':fielddiffs,'method_code_presence_mismatches':codemismatch,
                            'duplicate_smali_classes':[k for k,v in collections.Counter(c['descriptor'] for c in dec).items() if v>1]})
    counts={'zip_entries':z['non_directory_entries'],'dex_files':len(dex),'dex_class_defs':sum(d['class_defs'] for d in dex),'dex_encoded_methods':sum(d['encoded_methods'] for d in dex),
            'dex_methods_with_code':sum(d['encoded_methods_with_code'] for d in dex),'dex_encoded_fields':sum(d['encoded_fields'] for d in dex),
            'smali_files':len(sm),'smali_methods':sum(len(c['methods']) for c in sm),'smali_fields':sum(len(c['fields']) for c in sm),'smali_methods_with_code':sum(m['has_code'] for c in sm for m in c['methods'])}
    crossduplicates=[k for k,v in collections.Counter(c['descriptor'] for d in dex for c in d['classes']).items() if v>1]
    j=jadx_audit(sm,write);m=manifest_audit();c=android_channels(sm,write);r=resources(z)
    result={'schema':'android_completeness_audit.v1','static_only':True,'counts':counts,'zip':z,
            'dex_to_smali_comparison':comparisons,'cross_dex_duplicate_class_descriptors':crossduplicates,
            'jadx':{k:v for k,v in j.items() if k not in ['source_inventory','warnings']},'manifest':m,
            'platform_channels':{k:v for k,v in c.items() if k not in ['callsite_inventory','full_registration_method_snapshots']},
            'resources':r,'detail_files':{'dex':'dex_inventory.json','smali':'smali_inventory.json','jadx':'jadx_inventory.json','channels':'platform_channel_inventory.json','zip':'zip_inventory.json'},
            'corrective_action_artifacts':[file_record(p) for directory in ['corrected_inputs','corrections'] for p in sorted((OUT/directory).rglob('*')) if p.is_file()],
            'decoder_semantic_boundaries':['DEX annotations, encoded static values, debug_info and try/catch semantics retained in original DEX and smali but not exhaustively compared at the instruction/semantic level','JADX alias/nested-class file layout is not a canonical class inventory; DEX→smali comparison is canonical','Channel lexical constant resolution is not control-flow symbolic evaluation; full smali methods are frozen for unresolved names'],
            'confirmed':['Original APK and work copy byte equality','Every raw ZIP non-directory entry checked by size, SHA256 and content via case-safe path index','All DEX class_defs and encoded method/field signatures and code presence compared one-to-one with smali','Manifest entry/permission inventory compared against previous report'],
            'not_claimed':['100% restored original Java/Kotlin/Dart source','Semantic correctness of warning-bearing JADX methods','All 14 plugins arguments/results and actual Dart usage','Byte equivalence of transformed apktool resources','Runtime execution behavior or server interoperability']}
    if write:
        save('zip_inventory.json',z);save('dex_inventory.json',dex);save('smali_inventory.json',sm);save('jadx_inventory.json',j);save('platform_channel_inventory.json',c);save('android_completeness.json',result)
        text=f'''Android / APK / DEX 完整性审计

本次只做静态校验，未安装或执行 APK/目标库、未访问业务服务器。输入限定原APK、work copy、unpacked、apktool/smali/res、JADX源与8个fallback、deep_android既有报告。

APK：原件与APP/input/app_xcs.apk逐字节一致，SHA256={z['original_apk']['sha256']}。{counts['zip_entries']}个非目录条目当前全部逐字节比对。旧unpacked原路径不匹配={len(z['mismatch_entries'])}（大小写别名冲突）；经case_safe_entries索引不匹配={len(z['effective_mismatch_entries'])}。额外unpacked文件={len(z['unpacked_extra_files'])}，完全同名重复ZIP条目={len(z['duplicate_zip_names'])}。
原因已闭合：原APK同时含res/4C.xml（112字节、根<x>合法最小AXML）与res/4c.xml（layout/notification_template_media_custom，2756字节）。当前macOS大小写不敏感，两路径同inode；解包时小写原件被大写合法条目覆盖，不是可证人为篡改或工具语义解码。已保留前件与小写原件到corrected_inputs；按root授权恢复唯一旧小写文件后，大写别名转为不匹配。这种文件系统不能原名同时保存两者，现把两个原件分别以hex文件名保存case_safe_entries，zip_inventory.json为每个ZIP条目指定audit_canonical_file，可对全部427条核验。apktool按原ARSC资源名分开解码，两文件均存在，未改apktool。APK与work copy始终完整。

DEX：{counts['dex_files']}个DEX；class_defs={counts['dex_class_defs']}；encoded_methods={counts['dex_encoded_methods']}，其中code_item>0={counts['dex_methods_with_code']}；encoded_fields={counts['dex_encoded_fields']}。smali={counts['smali_files']}类、{counts['smali_methods']}方法、{counts['smali_fields']}字段，排除abstract/native的代码方法={counts['smali_methods_with_code']}。解析class_data_item静态/实例field index delta、direct/virtual method index delta的ULEB128，并按类核验完整签名Counter与code_off存在性。不以method_ids外部引用充当定义数。字节码指令区保存SHA256及code_units。此处证明库存覆盖，不能证明每条反编译语句语义正确。

JADX：原Java文件={j['primary_java_files']}；硬错误标记={j['primary_error_marker_count']}；Method not decompiled={j['primary_not_decompiled_stub_count']}。新独立重跑--no-res --log-level debug仍报11 errors、最终列8个不同Method nodes，恰与8个fallback对应；3个方法重复报pass错误。因此11不是漏了另外3个方法。原日志未列nodes，重跑是复现证据，不倒填原运行详情。8个fallback无ERROR/未反编译stub，但为register/goto伪Java，非可编译原源码。8个精确smali方法已复制failed_methods，完整fallback已复制fallback_snapshot。\nWARN={j['primary_warning_count']}，分布{j['primary_warning_files']}文件；8个fallback未解决所有类型推断、构造顺序、switch/控制流警告。完整警告库存见jadx_inventory.json，不能声称Java语义100%恢复。JADX文件数与DEX类数不能直接比较：内类合并/改名与自动生成R类均改变文件布局。

Manifest：{len(m['components'])}组件、{len(m['permissions'])}uses-permission，组件/属性/权限与deep_android逐项比较。registerWith注册14插件，已把7个短导入类名修正为完整DEX名（仅新审计文件）；14个类均有smali。静态注册不等于运行成功或业务调用。\n平台通道：全{counts['smali_files']}个smali扫描直接j5.k(MethodChannel)/j5.d(EventChannel)/j5.a(BasicMessageChannel)构造调用，共{c['constructor_calls_total']}，其中内部委托{c['internal_constructor_delegations']}。登记全部调用位置并冻结完整方法；常量寄存器按方法内词法追踪，动态名仅记候选前缀，不当作确定值。原deep_android仅详细分析5插件加MainActivity，共{len(c['previous_selected_channel_names'])}个名字。其余9插件未完整恢复参数/结果语义；本轮补库存、源码证据，未声称业务通道语义已全闭合。

资源：原ZIP res文件={r['raw_res_zip_entries']}；按aapt原ARSC类型/名称/config映射apktool解码文件。未映射原文件={len(r['unmapped_raw_res_entries'])}，映射后缺解码文件={len(r['mappings_to_missing_decoded_files'])}。XML与PNG可能是工具转换产物，存在性/名称库存验证不等于逐字段语义验证。原resources.arsc与所有原资源字节已逐条保存和核对。

复现：python3 APP/scripts/android_completeness_audit.py
若需重跑JADX错误复现：python3 APP/scripts/android_completeness_audit.py --reaudit-jadx（运行本机静态解码器，预期JADX exit3且11错误，日志保留本审计目录）
独立只读验证：python3 APP/scripts/android_completeness_audit.py --verify
验证PASS表示本审计记录的字节、库存、证据未变，并不表示上列语义缺口消失。
'''
        (OUT/'Android完整性审计说明.txt').write_text(text)
    return result,dex,sm,j,c

def verify():
    expected=json.loads((OUT/'android_completeness.json').read_text())
    actual,dex,sm,j,c=build(False)
    checks=[]
    def check(name,good):checks.append({'check':name,'passed':bool(good)})
    check('summary_recomputed_exactly',actual==expected)
    for name,obj in [('zip_inventory.json',actual['zip']),('dex_inventory.json',dex),('smali_inventory.json',sm),('jadx_inventory.json',j),('platform_channel_inventory.json',c)]:
        check(name+' recomputed',json.loads((OUT/name).read_text())==obj)
    check('zip_all_entries_match_via_case_safe_path_index',not actual['zip']['effective_mismatch_entries'] and not actual['zip']['unpacked_extra_files'] and not actual['zip']['duplicate_zip_names'] and actual['zip']['working_copy_matches'])
    check('dex_smali_exact_classes_methods_fields_and_code_presence',all(not d['missing_classes'] and not d['extra_classes'] and not d['method_inventory_mismatches'] and not d['field_inventory_mismatches'] and not d['method_code_presence_mismatches'] and not d['duplicate_smali_classes'] for d in actual['dex_to_smali_comparison']))
    check('eight_fallbacks_cover_eight_hard_failures',len(j['failed_methods'])==8 and len(j['reaudit_distinct_error_nodes'])==8 and all(x['fallback_method_declaration_match_count']==1 and not x['fallback_has_error_or_not_decompiled_stub'] for x in j['failed_methods']))
    check('manifest_components_attributes_permissions_existing_report_exact',actual['manifest']['existing_component_report_component_attributes_equal'] and actual['manifest']['existing_component_report_permissions_equal'])
    check('all_resource_file_mappings_present',not actual['resources']['unmapped_raw_res_entries'] and not actual['resources']['mappings_to_missing_decoded_files'])
    check('all_fourteen_registered_plugin_classes_present',len(c['plugins'])==14 and all(p['source_class_present'] for p in c['plugins']))
    for x in j['failed_methods']:
        check(x['method_signature']+' smali_snapshot',Path(x['smali_snapshot']).read_text()==x['authoritative_smali_method']['excerpt']+'\n')
        check(x['method_signature']+' fallback_snapshot',sha(Path(x['fallback_snapshot']).read_bytes())==x['fallback']['sha256'])
    for x in c['full_registration_method_snapshots']:
        check('channel method snapshot '+Path(x['snapshot']).name,Path(x['snapshot']).read_text()==x['source']['excerpt']+'\n')
    restoration=OUT/'corrected_inputs/restoration_record.json'
    if restoration.exists():
        rr=json.loads(restoration.read_text());check('original_restored_resource',sha((OUT/'corrected_inputs/res_4c_original.axml').read_bytes())==rr['original_sha256'] and sha((APP/'unpacked/res/4c.xml').read_bytes())==rr['original_sha256'])
        check('before_restore_resource_preserved',sha((OUT/'corrected_inputs/res_4c_before_restore.axml').read_bytes())==rr['before_sha256'])
    status='PASS' if all(x['passed'] for x in checks) else 'FAIL'
    return {'status':status,'checks':checks,'check_count':len(checks),'script':file_record(Path(__file__)),
            'scope':'Read-only recomputation of all inventories and exact evidence snapshots; does not assert semantic restoration.'}

if __name__=='__main__':
    parser=argparse.ArgumentParser();parser.add_argument('--verify',action='store_true');parser.add_argument('--reaudit-jadx',action='store_true');args=parser.parse_args()
    if args.verify and args.reaudit_jadx:parser.error('--verify is read-only; cannot combine with --reaudit-jadx')
    if args.verify:
        v=verify();print(json.dumps(v,ensure_ascii=False,indent=2));raise SystemExit(v['status']!='PASS')
    OUT.mkdir(parents=True,exist_ok=True)
    if args.reaudit_jadx:
        with (OUT/'jadx_reaudit_debug.log').open('w') as log:
            completed=subprocess.run(['jadx','--no-res','--log-level','debug','-d',str(OUT/'jadx_reaudit'),str(WORK)],stdout=log,stderr=subprocess.STDOUT)
        if completed.returncode not in [0,3]:raise RuntimeError('JADX static reaudit failed unexpectedly')
    build(True);v=verify();save('verification.json',v)
    print(json.dumps({'status':v['status'],'checks':v['check_count'],'output':str(OUT),'script_sha256':v['script']['sha256']},ensure_ascii=False));raise SystemExit(v['status']!='PASS')
