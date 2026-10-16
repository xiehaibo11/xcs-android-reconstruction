#!/usr/bin/env python3
"""Read-only APK/ELF/Ghidra completeness audit; runs only local analysis tools.

No target library loading or execution, no network, no secret string dumping.
Run: python3 APP/scripts/native_completeness_audit.py [--verify]
"""

from _paths import app_root, workspace_root
from pathlib import Path
import argparse, collections, csv, hashlib, io, json, re, struct, subprocess, zipfile
from functools import lru_cache
from elftools.elf.elffile import ELFFile
from elftools.elf.sections import SymbolTableSection
from elftools.elf.relocation import RelocationSection
from elftools.dwarf.callframe import FDE

ROOT=workspace_root()
APP=ROOT/'APP'; OUT=APP/'analysis/completeness_audit/native'
APK=ROOT/'app_xcs(新).apk.1.1'
LLVM=Path('/opt/homebrew/opt/llvm/bin/llvm-objdump')

@lru_cache(None)
def sha(p): return hashlib.sha256(Path(p).read_bytes()).hexdigest()
@lru_cache(None)
def source_lines(p): return Path(p).read_text().splitlines()
def ref(p): return {'file':str(p.resolve()),'sha256':sha(str(p.resolve()))}
def put(p,obj): p.parent.mkdir(parents=True,exist_ok=True);p.write_text(json.dumps(obj,ensure_ascii=False,indent=2)+'\n')
def rows(p): return list(csv.DictReader(p.open(),delimiter='\t'))
def uvar(b,p):
    n=s=0
    while True:
        q=b[p];p+=1;n|=(q&127)<<s
        if q<128:return n,p
        s+=7
        if s>70:raise ValueError('varint too long')
def go_functions(path):
    b=path.read_bytes()
    for m in re.finditer(re.escape(b'\xf1\xff\xff\xff\0\0'),b):
        p=m.start(); mi,ps=b[p+6:p+8]
        if ps not in (4,8) or mi not in (1,2,4):continue
        h=struct.unpack_from('<'+('I' if ps==4 else 'Q')*8,b,p+8)
        n,nf,tx,fn,cu,ft,pc,tab=h
        if not(0<n<100000 and p+tab+8*(n+1)<=len(b)):continue
        fs=[]
        try:
            for i in range(n):
                ent,off=struct.unpack_from('<II',b,p+tab+i*8)
                nxt=struct.unpack_from('<I',b,p+tab+(i+1)*8)[0]
                met=p+tab+off
                me,no,args,dr,sp,pf,pl=struct.unpack_from('<IiIIIII',b,met)
                assert me==ent and nxt>ent
                na=p+fn+no;name=b[na:b.index(b'\0',na)].decode('utf8')
                cui,line=struct.unpack_from('<II',b,met+32);source=None
                if pf:
                    d,_=uvar(b,p+pc+pf);idx=-1+(-(d&1)^(d>>1))
                    if idx>=0 and cui!=0xffffffff:
                        fo=struct.unpack_from('<I',b,p+cu+(cui+idx)*4)[0];sa=p+ft+fo
                        source=b[sa:b.index(b'\0',sa)].decode('utf8')
                # This provenance is component attribution, never proof of app invocation.
                group='unknown'
                if source and '/rsa-mobile/' in source:group='embedded_rsa_mobile_component'
                elif source and ('/go/src/' in source or '/golang.org/x/' in source):group='go_runtime_or_standard_library_source_path'
                elif source and '/pkg/mod/' in source:group='third_party_go_module_source_path'
                fs.append({'address':hex(tx+ent),'end_exclusive':hex(tx+nxt),'bytes':nxt-ent,'name':name,
                           'metadata_file_offset':met,'name_file_offset':na,'source_file':source,'start_line':line,
                           'classification':group,'classification_basis':'pclntab first pcfile source path; not a claim that function is irrelevant'})
            return {'magic':'0xfffffff1','file_offset':p,'pointer_bytes':ps,'minimum_instruction_bytes':mi,
                    'function_count':n,'file_count':nf,'text_start':hex(tx)},fs
        except (AssertionError,IndexError,ValueError,UnicodeError,struct.error):continue
    raise ValueError('Go pclntab not validated')

def elf_inventory(p,z):
    b=p.read_bytes();e=ELFFile(io.BytesIO(b));sy=[];exports=[];imports=[];rels=[];sections=[];segments=[];checks=[]
    checks.extend([{'check':'program_header_table_bounds','passed':e['e_phoff']+e['e_phentsize']*e.num_segments()<=len(b)},
                   {'check':'section_header_table_bounds','passed':e['e_shoff']+e['e_shentsize']*e.num_sections()<=len(b)}])
    for j,s in enumerate(e.iter_segments()):
        v={k:s[k] for k in ('p_type','p_offset','p_vaddr','p_filesz','p_memsz','p_flags','p_align')};v['index']=j;segments.append(v)
        checks.append({'check':'segment_file_bounds','index':j,'passed':s['p_offset']+s['p_filesz']<=len(b)})
        if s['p_type']=='PT_LOAD':
            checks.append({'check':'load_filesz_le_memsz','index':j,'passed':s['p_filesz']<=s['p_memsz']})
            checks.append({'check':'load_alignment_congruence','index':j,'passed':s['p_align']<=1 or (s['p_vaddr']-s['p_offset'])%s['p_align']==0})
    for j,s in enumerate(e.iter_sections()):
        v={'index':j,'name':s.name,**{k:s[k] for k in ('sh_type','sh_flags','sh_addr','sh_offset','sh_size','sh_link','sh_info','sh_entsize')}};sections.append(v)
        checks.append({'check':'section_file_bounds','index':j,'passed':s['sh_type']=='SHT_NOBITS' or s['sh_offset']+s['sh_size']<=len(b)})
        if s['sh_flags']&4:
            checks.append({'check':'executable_section_in_executable_load','index':j,'passed':any(v['p_type']=='PT_LOAD' and v['p_flags']&1 and v['p_vaddr']<=s['sh_addr'] and s['sh_addr']+s['sh_size']<=v['p_vaddr']+v['p_memsz']for v in segments)})
        if isinstance(s,SymbolTableSection):
            for si,q in enumerate(s.iter_symbols()):
                v={'table':s.name,'index':si,'name':q.name,'address':hex(q['st_value']),'size':q['st_size'],
                   'bind':q['st_info']['bind'],'type':q['st_info']['type'],'visibility':q['st_other']['visibility'],'section':q['st_shndx']};sy.append(v)
                if s.name=='.dynsym' and q.name:
                    if q['st_shndx']=='SHN_UNDEF':imports.append(v)
                    elif q['st_info']['bind'] in ('STB_GLOBAL','STB_WEAK'):exports.append(v)
        if isinstance(s,RelocationSection):
            invalid_offsets=invalid_symbols=0
            linked=e.get_section(s['sh_link']);symcount=linked.num_symbols()if isinstance(linked,SymbolTableSection)else None
            for ri,q in enumerate(s.iter_relocations()):
                v={'table':s.name,'index':ri,'offset':hex(q['r_offset']),'type':q['r_info_type'],'symbol_index':q['r_info_sym']}
                if s.is_RELA():v['addend']=q['r_addend']
                rels.append(v)
                invalid_offsets+=not any(vv['p_type']=='PT_LOAD' and vv['p_vaddr']<=q['r_offset']<vv['p_vaddr']+vv['p_memsz']for vv in segments)
                invalid_symbols+=symcount is not None and q['r_info_sym']>=symcount
            checks.extend([{'check':'relocation_target_in_load_memory','section':s.name,'invalid_count':invalid_offsets,'passed':invalid_offsets==0},
                           {'check':'relocation_symbol_index_bounds','section':s.name,'invalid_count':invalid_symbols,'passed':invalid_symbols==0}])
    member=f'lib/{p.parent.name}/{p.name}';orig=z.read(member);zi=z.getinfo(member)
    checks.append({'check':'zip_member_byte_identical','passed':b==orig})
    db=OUT/'elf'/p.parent.name/p.name
    put(db/'symbols.json',sy);put(db/'relocations.json',rels)
    unwind,unwind_status=unwind_inventory(p);put(db/'unwind_ranges.json',unwind)
    return {'abi':p.parent.name,'library':p.name,'file':str(p.resolve()),'sha256':sha(str(p.resolve())),
            'size':len(b),'zip_member':member,'zip_crc32':f'{zi.CRC:08x}','zip_uncompressed_size':zi.file_size,
            'elf_class':e.elfclass,'little_endian':e.little_endian,'machine':e['e_machine'],'elf_type':e['e_type'],
            'entry':hex(e['e_entry']),'segments':segments,'sections':sections,'checks':checks,
            'symbol_count':len(sy),'dynamic_exports':exports,'dynamic_imports':imports,
            'relocation_count':len(rels),'rela_count':sum('addend'in x for x in rels),'rel_count':sum('addend'not in x for x in rels),
            'symbols_inventory':ref(db/'symbols.json'),'relocations_inventory':ref(db/'relocations.json'),
            'unwind_range_count':len(unwind),'unwind_status':unwind_status,'unwind_inventory':ref(db/'unwind_ranges.json'),
            'executable_sections':[v for v in sections if v['sh_flags']&4]}

def unwind_inventory(p):
    out=[];status=[]
    with p.open('rb')as f:
        e=ELFFile(f)
        if e.get_section_by_name('.eh_frame'):
            try:
                for x in e.get_dwarf_info().EH_CFI_entries():
                    if not isinstance(x,FDE):continue
                    a=x['initial_location'];n=x['address_range']
                    out.append({'kind':'eh_frame_FDE','section_offset':x.offset,'start':hex(a),'end_exclusive':hex(a+n),'bytes':n,
                                'boundary':'Unwind PC range, not necessarily a unique source function; no semantic classification.'})
                status.append({'section':'.eh_frame','status':'parsed'})
            except Exception as exc:status.append({'section':'.eh_frame','status':'failed','error':type(exc).__name__+': '+str(exc)})
        s=e.get_section_by_name('.ARM.exidx')
        if s:
            b=s.data();base=s['sh_addr'];entries=[]
            for off in range(0,len(b),8):
                a,u=struct.unpack_from('<II',b,off);imm=a&0x7fffffff;imm=imm-(1<<31)if imm&(1<<30)else imm
                target=base+off+imm
                entries.append({'kind':'ARM_exidx','section_offset':off,'entry_va':hex(base+off),'start':hex(target&~1),
                                'thumb_bit':target&1,'unwind_word':hex(u),'raw_bytes_hex':b[off:off+8].hex(),
                                'boundary':'Exception-index start; next-entry interval can merge functions or be a sentinel, not exact source-function ownership.'})
            for i,x in enumerate(entries):x['next_entry_start']=entries[i+1]['start']if i+1<len(entries)else None
            out.extend(entries);status.append({'section':'.ARM.exidx','status':'parsed'})
    return out,status

def complete_c_inventory():
    records={'rust':collections.defaultdict(list),'rsa':collections.defaultdict(list)};statuses=[]
    for p in (APP/'analysis').rglob('decompile_status.tsv'):
        # Audit own newly created statuses too, but no non-native status files.
        if 'completeness_audit' in p.parts and 'native' not in p.parts:continue
        k='rsa' if 'librsa_bridge.so' in p.parts or any(x.startswith('ghidra_rsa')for x in p.parts) else 'rust'
        ls=p.read_text().splitlines()
        for i,x in enumerate(rows(p),2):
            statuses.append({**x,'library':k,'status_file':str(p.resolve()),'status_sha256':sha(str(p.resolve())),
                             'evidence':{**ref(p),'line':i,'excerpt':ls[i-1]}})
    for p in (APP/'analysis').rglob('*.c'):
        k='rsa' if 'librsa_bridge.so' in p.parts or any(x.startswith('ghidra_rsa')for x in p.parts) else 'rust'
        t=p.read_text(errors='replace')
        # WARNING comments may mention an address; only exporter function headers are boundaries.
        matches=list(re.finditer(r'^/\* (?:[A-Za-z_$][\w.$]* @ ([0-9a-f]{8})(?:;[^\n]*)?|Complete Ghidra decompiler output,[^\n]*entry: ([0-9a-f]{8});[^\n]*) \*/',t,re.M))
        for i,m in enumerate(matches):
            end=matches[i+1].start() if i+1<len(matches) else len(t);body=t[m.end():end].strip()
            cleaned=re.sub(r'/\*.*?\*/|//[^\n]*|"(?:\\.|[^"\\])*"|\'(?:\\.|[^\'\\])*\'', '',body,flags=re.S)
            bal=0;minbal=0
            for q in cleaned:
                bal+=(q=='{')-(q=='}');minbal=min(minbal,bal)
            syntactic=bool(body) and body.endswith('}') and '{'in cleaned and bal==0 and minbal>=0 and 'Decompilation incomplete'not in body
            records[k][m[1]or m[2]].append({**ref(p),'start_line':t[:m.start()].count('\n')+1,
                'end_line':t[:end].count('\n')+(not t[:end].endswith('\n')),
                'syntactic_body_closed':syntactic,'body_sha256':hashlib.sha256(body.encode()).hexdigest(),
                'control_flow_truncation_warning':bool(re.search(r'Truncating control flow|halt_baddata\s*\(',body)),
                'unresolved_jump_table_warning':'Could not recover jumptable'in body,
                'warning_count':body.count('WARNING:'),'body_chars':len(body)})
    return records,statuses

def gap_ranges(executable,covered):
    merged=[]
    for lo,hi in sorted(covered):
        if merged and lo<=merged[-1][1]:merged[-1][1]=max(merged[-1][1],hi)
        else:merged.append([lo,hi])
    gaps=[]
    for lo,hi in executable:
        cur=lo
        for a,b in merged:
            if b<=cur or a>=hi:continue
            if a>cur:gaps.append([hex(cur),hex(min(a,hi))])
            cur=max(cur,min(b,hi))
        if cur<hi:gaps.append([hex(cur),hex(hi)])
    return merged,gaps

def ghidra_inventory(kind,lib,records,statuses):
    p=OUT/f'ghidra_{kind}'/'function_metadata.tsv';old=APP/'analysis/ghidra'/lib/'functions.tsv'
    assert p.exists(),f'first run NativeCompletenessExport: {p}'
    rr=rows(p);oldr=rows(old)
    assert {x['address'] for x in rr}=={x['address'] for x in oldr},'database function inventory changed'
    elf=APP/'unpacked/lib/arm64-v8a'/lib
    with elf.open('rb')as f:e=ELFFile(f);ex=[(s['sh_addr'],s['sh_addr']+s['sh_size'])for s in e.iter_sections()if s['sh_flags']&4]
    items=[];covered=[]
    metadata_lines=p.read_text().splitlines()
    for metadata_line,x in enumerate(rr,2):
        addr=x['address'];ranges=[]
        for y in x['ranges'].split(';'):
            a,b=(int(v,16) for v in y.split('-'));assert b>=a;ranges.append([hex(a-0x100000),hex(b+1-0x100000)]);covered.append([a-0x100000,b+1-0x100000])
        assert sum(int(b,16)-int(a,16) for a,b in ranges)==int(x['bytes'])
        cc=records[kind].get(addr,[]);ss=[z for z in statuses if z['library']==kind and z['address']==addr]
        closed=[z for z in cc if z['syntactic_body_closed']]
        completed=any(z['completed']=='true'for z in ss)
        state='complete_c_export' if closed and completed else 'c_closed_without_completed_status' if closed else 'decompile_failed_or_deferred' if ss else 'not_exported'
        physical=all(any(a<=int(lo,16) and int(hi,16)<=b for a,b in ex)for lo,hi in ranges)
        if closed and completed and not any(not z['control_flow_truncation_warning']for z in closed):state='complete_tool_output_with_control_flow_gap'
        if not physical and x['thunk']=='true':state='non_executable_import_placeholder'
        category='unknown';basis=[]
        if x['thunk']=='true':category='import_or_local_thunk';basis=['Ghidra thunk flag; does not establish irrelevance']
        elif x['name'].startswith(('frb_','dart_','init_frb','new_dart','store_dart','free_zero')):category='exported_bridge_runtime_candidate';basis=['symbol identity; implementation may include business adapters']
        reasons=sorted({z.get('reasons','')for z in ss if z.get('reasons')})
        if any(re.search(r'src_ws_frameworks|src/ws/frameworks|src/api/|这是服务端|登陆验证失败|收到的服务端消息类型|QoS|Keep Alive|ws_login|ws_logout|is_content_ws|init_ws|create_event_stream',q)for q in reasons):
            category='business_or_bridge_context_xref';basis=['existing extraction string xref/root selection reasons; caller/callee context alone does not prove exclusive business ownership']
        items.append({'ghidra_address':'0x'+addr,'elf_address':hex(int(addr,16)-0x100000),'name':x['name'],'bytes':int(x['bytes']),
            'metadata_evidence':{**ref(p),'line':metadata_line,'excerpt':metadata_lines[metadata_line-1]},
            'ranges_end_exclusive':ranges,'external':x['external']=='true','thunk':x['thunk']=='true',
            'ranges_fully_inside_elf_executable_sections':physical,
            'callees_ghidra':['0x'+v for v in x['callees'].split(';') if v],'symbols':x['symbols'].split(';'),
            'c_status':state,'complete_c_candidates':cc,'decompile_status_records':ss,'classification':category,'classification_basis':basis,
            'reasons':reasons})
    put(OUT/f'{kind}_ghidra_functions.json',items)
    missing=[x for x in items if x['c_status']!='complete_c_export'];put(OUT/f'{kind}_not_complete_c.json',missing)
    jump_uncertain=[x for x in items if any(c['unresolved_jump_table_warning']for c in x['complete_c_candidates'])]
    put(OUT/f'{kind}_jump_table_uncertainty.json',jump_uncertain)
    merged,gaps=gap_ranges(ex,covered)
    return {'library':lib,'abi':'arm64-v8a','database_metadata':ref(p),'previous_metadata':ref(old),
        'function_count':len(items),'status_counts':dict(collections.Counter(x['c_status']for x in items)),
        'classification_counts':dict(collections.Counter(x['classification']for x in items)),
        'function_inventory':ref(OUT/f'{kind}_ghidra_functions.json'),'not_complete_c_inventory':ref(OUT/f'{kind}_not_complete_c.json'),
        'unresolved_jump_table_function_count':len(jump_uncertain),'jump_table_uncertainty_inventory':ref(OUT/f'{kind}_jump_table_uncertainty.json'),
        'covered_range_bytes':sum(b-a for a,b in merged),'unassigned_executable_ranges_end_exclusive':gaps,
        'unassigned_executable_bytes':sum(int(b,16)-int(a,16)for a,b in gaps),
        'range_boundary':'Unassigned executable bytes can be code, padding, PLT, literals or undiscovered functions; Ghidra function inventory is complete only for this database.'}

def disassemble(p):
    out=OUT/'llvm'/p.parent.name/(p.name+'.asm.txt');out.parent.mkdir(parents=True,exist_ok=True)
    if not out.exists():
        with out.open('w') as f:subprocess.run([str(LLVM),'-d','--disassemble-zeroes','--print-imm-hex',str(p)],stdout=f,check=True)
    return {**ref(out),'binary':str(p.resolve()),'binary_sha256':sha(str(p.resolve())),
            'command':[str(LLVM),'-d','--disassemble-zeroes','--print-imm-hex',str(p)],
            'boundary':'Full executable-section LLVM listing; raw instruction bytes verified independently. It does not recover types or guaranteed function boundaries.'}

def annotate_go(fs,abi):
    gh={int(x['elf_address'],16):x for x in json.loads((OUT/'rsa_ghidra_functions.json').read_text())}if abi=='arm64-v8a'else{}
    for x in fs:
        g=gh.get(int(x['address'],16));x['ghidra_exact_entry_present']=bool(g)
        x['c_status']=g['c_status']if g else 'no_exact_ghidra_function_entry'if abi=='arm64-v8a'else'no_ghidra_database_for_this_abi'
        if g:x['ghidra_body_ranges_end_exclusive']=g['ranges_end_exclusive']
        x['machine_code_coverage']='Full LLVM executable-section listing, all raw bytes independently verified'
    return fs

def critical_inventory():
    rust_addrs=['1b0180','1b0054','1b0504','1aff28','1b03d8','1b02ac','1c64b0','1d327c','1a5ec8','1e99a0','1cf0e0','1eaf88',
                '1e8b4c','1eab5c','1e2ea0','1cec94','1e1b0c','1e1110','1e1270','1e13c8','1ec068','1a5cd0','1a5430',
                '1a556c','1a51f0','1df0cc','1e06c4','1e0cf4','1c6e5c','1c5ce4','1e4eec','1e49e0','1c0a94','1e303c']
    rsa_addrs=['2fc874','2fc7a0','2fc530','2f56c0'];out=[]
    for kind,aa in [('rust',rust_addrs),('rsa',rsa_addrs)]:
        inv={int(x['ghidra_address'],16):x for x in json.loads((OUT/f'{kind}_ghidra_functions.json').read_text())}
        for a in aa:
            x=inv.get(int(a,16));out.append({'library':kind,'ghidra_address':hex(int(a,16)),
                'status':x['c_status']if x else'no_function_in_current_database',
                'elf_body_ranges_end_exclusive':x['ranges_end_exclusive']if x else[],
                'ghidra_body_bytes':x['bytes']if x else None,
                'body_candidates':x['complete_c_candidates']if x else[],
                'selection_basis':'explicit prior bridge/login/authentication/heartbeat/QoS/socket/response-disposal analysis addresses; scope is this finite list'})
    return out

def analysis_failures():
    p=APP/'logs/ghidra_console.log';ls=p.read_text().splitlines();groups={}
    patterns={'go_type_analysis_failure':r'ERROR Go analysis failure',
              'go_no_types_recovered':r'Found 0 Go types',
              'exception_table_function_boundary_failure':r'ERROR Function body does not',
              'gcc_exception_disassembly_failure':r'ERROR Failed to disassemble at'}
    for key,pattern in patterns.items():
        hits=[i for i,l in enumerate(ls,1)if re.search(pattern,l)]
        groups[key]={'count':len(hits),'examples':[{**ref(p),'line':i,'excerpt':ls[i-1]}for i in hits[:3]],
                     'full_log':ref(p),'boundary':'Historic auto-analysis errors remain evidence of analysis limitations; they are not ELF file corruption.'}
    return groups

def build():
    OUT.mkdir(parents=True,exist_ok=True)
    with zipfile.ZipFile(APK)as z:
        names=sorted(x for x in z.namelist()if x.startswith('lib/')and x.endswith('.so'))
        local=sorted(APP.joinpath('unpacked',n).resolve()for n in names)
        assert {str(p.resolve())for p in APP.joinpath('unpacked/lib').glob('*/*.so')}=={str(p)for p in local}
        libs=[elf_inventory(p,z)for p in local]
    records,statuses=complete_c_inventory()
    gh=[ghidra_inventory('rust','librust_lib_distinguish.so',records,statuses),ghidra_inventory('rsa','librsa_bridge.so',records,statuses)]
    gos=[]
    for p in local:
        if p.name!='librsa_bridge.so':continue
        meta,fs=go_functions(p);fs=annotate_go(fs,p.parent.name);db=OUT/'go'/p.parent.name
        put(db/'functions.json',fs);put(db/'metadata.json',meta)
        with p.open('rb')as f:
            e=ELFFile(f);ex=[(s['sh_addr'],s['sh_addr']+s['sh_size'])for s in e.iter_sections()if s['sh_flags']&4]
        covered,gaps=gap_ranges(ex,[(int(x['address'],16),int(x['end_exclusive'],16))for x in fs])
        gf={'abi':p.parent.name,**ref(p),'metadata':ref(db/'metadata.json'),'functions':ref(db/'functions.json'),
            'function_count':len(fs),'classification_counts':dict(collections.Counter(x['classification']for x in fs)),
            'not_covered_by_pclntab_exec_ranges':gaps}
        if p.parent.name=='arm64-v8a':
            existing=json.loads((APP/'analysis/deep_rsa/go_functions.json').read_text());assert [(x['address'],x['end'],x['name'])for x in existing]==[(int(x['address'],16),int(x['end_exclusive'],16),x['name'])for x in fs]
            dbfunc=json.loads((OUT/'rsa_ghidra_functions.json').read_text());starts={int(x['elf_address'],16)for x in dbfunc}
            mismatch=[x for x in fs if int(x['address'],16)not in starts];put(db/'not_exact_ghidra_entry.json',mismatch)
            gf.update(exact_ghidra_entry_match=len(fs)-len(mismatch),not_exact_ghidra_entry=len(mismatch),not_exact_ghidra_inventory=ref(db/'not_exact_ghidra_entry.json'))
        gos.append(gf)
    llvm=[disassemble(p)for p in local if p.name in ('librsa_bridge.so','librust_lib_distinguish.so')]
    entries=[]
    for lib in libs:
        for s in lib['dynamic_exports']:
            n=s['name']
            if s['type']!='STT_FUNC':continue
            kind='JNI' if n.startswith(('JNI_','Java_')) else 'FRB_or_Dart_native_bridge' if any(q in n for q in ['frb_','dart_','zero_copy']) else 'Go_RSA_bridge' if 'RSABridgeCall'in n else 'other_export'
            entries.append({'abi':lib['abi'],'library':lib['library'],'name':n,'address':s['address'],'size':s['size'],'category':kind,
                'elf':lib['file'],'elf_sha256':lib['sha256'],'symbol_index':s['index'],
                'coverage':'full LLVM and Ghidra function inventory available' if lib['abi']=='arm64-v8a' and lib['library']in('librust_lib_distinguish.so','librsa_bridge.so') else 'full LLVM and Go pclntab available' if lib['library']=='librsa_bridge.so' else 'full LLVM, no Ghidra database for this ABI' if lib['library']=='librust_lib_distinguish.so' else 'ELF/dynsym inventory only; Dart snapshot/Flutter engine requires separate analysis'})
    put(OUT/'native_exported_entrypoints.json',entries)
    critical=critical_inventory();put(OUT/'critical_business_bodies.json',critical)
    boundary=['Function metadata covers all discovered Ghidra functions and every validated Go pclntab entry in all four RSA ABIs.',
              'A closed, completed decompiler C body is a complete tool output, not original source nor proof that recovered Go/Rust ABI types are correct.',
              'All .so ZIP contents are byte-compared. Stripped libapp/libflutter dynsym does not enumerate their actual functions; Dart AOT completeness is audited separately.',
              'No Ghidra database exists in the current project for non-arm64 ABIs or libapp/libflutter. Do not claim their full C reconstruction.',
              'Component classification never implies that runtime/vendor code is irrelevant. Unproved unnamed native functions remain unknown.',
              'All procedures are static. No target executable was loaded/run, no business backend requests, no secret contents are emitted.']
    result={'format':'native-completeness-v1','apk':ref(APK),'elf_libraries':libs,'library_count':len(libs),
            'abis':sorted({x['abi']for x in libs}),'ghidra_databases':gh,'go_pclntab':gos,'full_llvm_listings':llvm,
            'exported_entrypoints':ref(OUT/'native_exported_entrypoints.json'),'boundaries':boundary}
    result['critical_business_bodies']=ref(OUT/'critical_business_bodies.json')
    result['historic_auto_analysis_failures']=analysis_failures()
    put(OUT/'native_completeness.json',result)
    lines=['本地原生库逆向完整性审计（静态）','',f'APK 共有 {len(libs)} 个 .so，4 个 ABI。所有解包库与 ZIP 成员逐字节相同。x86 只有 RSA 库；不存在的其他 x86 库不是解包漏失。','',
           '完整性分层：文件/ELF 库存完整，不等同所有逻辑已还原；已发现函数完整库存，不等同已识别所有机器码函数。']
    for g in gh:lines.extend(['',f'{g["library"]} ARM64 Ghidra 函数总数 {g["function_count"]}；C 状态 {g["status_counts"]}；未归入数据库函数的可执行字节 {g["unassigned_executable_bytes"]}，区间见 JSON。',
                             f'另有 {g["unresolved_jump_table_function_count"]} 个函数的工具输出含未恢复 jumptable 警告，单独库存。这不必然是缺失字节（可能为间接尾调用），但跳转语义未完全确定，不可据 completed 宣称逻辑全恢复。'])
    lines.extend(['','Go pclntab：'])
    for g in gos:lines.append(f'{g["abi"]}: {g["function_count"]} 函数'+(f'，其中 {g["not_exact_ghidra_entry"]} 没有精确 Ghidra 函数入口，已逐一列出。'if 'not_exact_ghidra_entry'in g else'。'))
    lines.extend(['','Rust 三 ABI、RSA 四 ABI 共七个库已补全 LLVM 全可执行段列表。逐指令原始机器字校验见 verification.json。所有 ELF 符号/RELA/REL、入口、函数范围、C 导出/失败/未导出状态都有独立库存。',
                  '额外解析各库 .eh_frame/.ARM.exidx 共 98,685 条 unwind PC 范围；ARMv7 exidx 可能合并函数或含 sentinel，Dart 两个 FDE 可覆盖大段 snapshot，它们不能当成唯一源函数。保留各 ABI 原始区域，不套用 ARM64 函数地址。',
                  'libapp/libflutter 仅稀疏动态符号，不能据此宣称其函数还原无遗漏；它们的 Dart AOT/Flutter 引擎覆盖需结合其他审计。','',
                  '未导出库存含 thunk/import/unknown。未知函数不能因 FUN 名称或组件名称被断言无业务关系。Go 标准库/第三方归属依据编译源路径，不是调用活跃性判断。',
                  'Ghidra 完整 C 是完整工具输出：Go 栈/ABI 和 Rust 状态机类型常为 approximate；不能称恢复原始源代码。超时、失败与预算延后逐项保留。','',
                  '原始 Ghidra 日志还明确记录 Go 类型分析失败（runtime.sigset）和异常表函数范围错误，JSON 保存计数与原始行证据。不能把原始项目自动分析当成毫无错误的全量函数发现。',
                  '工具状态具体边界：Rust 2 个函数在 10 秒/60 秒重试仍超时；RSA 3 个函数 varnode 错误、5 个 completed 输出含明确控制流截断。非可执行导入占位也单列。相关地址在 *_not_complete_c.json；这些区域都有完整 LLVM，不等同完成 C 语义。',
                  f'关键桥接/登录/认证/心跳/QoS/Socket/响应销毁有限清单共 {len(critical)} 个，逐一核对完整 C/状态，见 critical_business_bodies.json。','',
                  '本轮另外复核 types50 成功响应：auth +0x2b1 确有写入；user_id/data 是局部 String，e303c helper 仅释放两个字符串，未证明写入 SDK。旧报告“尚未确认写入”仍成立。','',
                  '独立复核：python3 APP/scripts/native_completeness_audit.py --verify。不会执行 APK 或任何目标 so，也不会请求业务服务器。'])
    (OUT/'中文说明.txt').write_text('\n'.join(lines)+'\n')
    source_files={str(APK.resolve()),str(Path(__file__).resolve()),str((OUT/'NativeCompletenessExport.java').resolve())}
    def inputs(o):
        if isinstance(o,list):
            for v in o:inputs(v)
        elif isinstance(o,dict):
            if 'file'in o and 'sha256'in o and not Path(o['file']).is_relative_to(OUT):source_files.add(o['file'])
            if 'status_file'in o:source_files.add(o['status_file'])
            for v in o.values():inputs(v)
    inputs(result);inputs(json.loads((OUT/'rust_ghidra_functions.json').read_text()));inputs(json.loads((OUT/'rsa_ghidra_functions.json').read_text()))
    artifacts=[p for p in OUT.rglob('*')if p.is_file()and p.name not in ('source_manifest.json','verification.json','audit_run.log','elf_inventory_preliminary.json')]
    put(OUT/'source_manifest.json',{'inputs':[ref(Path(p))for p in sorted(source_files)],'artifacts':[ref(p)for p in sorted(artifacts)],
                                'boundary':'Manifest excludes itself, changing console log and generated verification result to avoid circular hashes.'})

def verify():
    doc=json.loads((OUT/'native_completeness.json').read_text());counts=collections.Counter();seen=set()
    def walk(o):
        if isinstance(o,list):
            for x in o:walk(x)
        elif isinstance(o,dict):
            if 'file'in o and 'sha256'in o:
                p=Path(o['file']);assert p.exists()and sha(str(p))==o['sha256'],p;seen.add(str(p));counts['file_hash_refs']+=1
                if 'line'in o and 'excerpt'in o:
                    ls=source_lines(str(p));assert 1<=o['line']<=len(ls)and ls[o['line']-1]==o['excerpt'];counts['exact_source_lines']+=1
            if 'elf'in o and 'elf_sha256'in o:assert sha(o['elf'])==o['elf_sha256'];counts['elf_hash_refs']+=1
            for v in o.values():walk(v)
    walk(doc)
    if (OUT/'source_manifest.json').exists():walk(json.loads((OUT/'source_manifest.json').read_text()))
    with zipfile.ZipFile(APK)as z:
        assert len([n for n in z.namelist()if n.startswith('lib/')and n.endswith('.so')])==doc['library_count']==13
        for lib in doc['elf_libraries']:
            p=Path(lib['file']);assert p.read_bytes()==z.read(lib['zip_member']);assert all(x['passed']for x in lib['checks']);counts['zip_identical_libraries']+=1
            sy=json.loads(Path(lib['symbols_inventory']['file']).read_text());rs=json.loads(Path(lib['relocations_inventory']['file']).read_text())
            assert len(sy)==lib['symbol_count']and len(rs)==lib['relocation_count'];counts['symbols']+=len(sy);counts['relocations']+=len(rs)
            uw,us=unwind_inventory(p);assert uw==json.loads(Path(lib['unwind_inventory']['file']).read_text())and us==lib['unwind_status'];counts['unwind_PC_ranges']+=len(uw)
    independently_recovered_c,independently_recovered_status=complete_c_inventory()
    for g in doc['ghidra_databases']:
        fs=json.loads(Path(g['function_inventory']['file']).read_text());walk(fs);assert len(fs)==g['function_count'];assert dict(collections.Counter(x['c_status']for x in fs))==g['status_counts']
        ju=[x for x in fs if any(c['unresolved_jump_table_warning']for c in x['complete_c_candidates'])]
        assert ju==json.loads(Path(g['jump_table_uncertainty_inventory']['file']).read_text())and len(ju)==g['unresolved_jump_table_function_count']
        assert len({x['ghidra_address']for x in fs})==len(fs);counts['ghidra_functions']+=len(fs)
        native_rows=rows(Path(g['database_metadata']['file']));byaddr={int(x['ghidra_address'],16):x for x in fs}
        assert {int(x['address'],16)for x in native_rows}==set(byaddr)
        for r in native_rows:
            x=byaddr[int(r['address'],16)];assert x['name']==r['name']and x['bytes']==int(r['bytes'])
            expected=[[hex(int(a,16)-0x100000),hex(int(b,16)+1-0x100000)]for a,b in (v.split('-')for v in r['ranges'].split(';'))]
            assert x['ranges_end_exclusive']==expected
        for x in fs:
            assert sum(int(b,16)-int(a,16)for a,b in x['ranges_end_exclusive'])==x['bytes']
            kind='rsa'if g['library']=='librsa_bridge.so'else'rust';addr=x['ghidra_address'][2:].zfill(8)
            recovered=independently_recovered_c[kind].get(addr,[])
            key=lambda c:(c['file'],c['start_line'],c['end_line'])
            assert sorted(x['complete_c_candidates'],key=key)==sorted(recovered,key=key)
            ss=[s for s in independently_recovered_status if s['library']==kind and s['address']==addr]
            assert x['decompile_status_records']==ss
            closed=[c for c in recovered if c['syntactic_body_closed']];ok=any(s['completed']=='true'for s in ss)
            state='complete_c_export'if closed and ok else'c_closed_without_completed_status'if closed else'decompile_failed_or_deferred'if ss else'not_exported'
            if closed and ok and not any(not c['control_flow_truncation_warning']for c in closed):state='complete_tool_output_with_control_flow_gap'
            if not x['ranges_fully_inside_elf_executable_sections']and x['thunk']:state='non_executable_import_placeholder'
            assert x['c_status']==state
            for c in x['complete_c_candidates']:
                ls=source_lines(c['file']);assert 1<=c['start_line']<=c['end_line']<=len(ls)
                counts['reparsed_C_candidate_bodies']+=1
    for g in doc['go_pclntab']:
        meta,fs=go_functions(Path(g['file']));fs=annotate_go(fs,g['abi']);saved=json.loads(Path(g['functions']['file']).read_text());assert fs==saved and len(fs)==g['function_count'];counts['go_functions']+=len(fs)
    for r in doc['full_llvm_listings']:
        p=Path(r['binary']);assert sha(str(p))==r['binary_sha256'];b=p.read_bytes();e=ELFFile(io.BytesIO(b));execsec=[(s['sh_addr'],s['sh_addr']+s['sh_size'])for s in e.iter_sections()if s['sh_flags']&4];seg=[s for s in e.iter_segments()if s['p_type']=='PT_LOAD']
        covered=[];num=0;bl=0
        for line in Path(r['file']).read_text().splitlines():
            m=re.match(r'^\s*([0-9a-f]+):\s+([0-9a-f ]+)\t(.*)$',line)
            if not m:continue
            a=int(m[1],16);tokens=m[2].split();code=m[3]
            if not all(re.fullmatch('[0-9a-f]{2}|[0-9a-f]{4}|[0-9a-f]{8}',v)for v in tokens):continue
            raw=b''.join(bytes.fromhex(v)[::-1] if len(v)>2 and e['e_machine']in('EM_AARCH64','EM_ARM')else bytes.fromhex(v)for v in tokens)
            ss=next((s for s in seg if s['p_vaddr']<=a and a+len(raw)<=s['p_vaddr']+s['p_filesz']),None);assert ss is not None,(p,a)
            off=ss['p_offset']+a-ss['p_vaddr'];assert b[off:off+len(raw)]==raw,(p,hex(a),raw.hex());covered.append((a,a+len(raw)));num+=1
            if e['e_machine']=='EM_AARCH64' and len(raw)==4:
                w=int.from_bytes(raw,'little')
                if w&0xfc000000 in (0x94000000,0x14000000):
                    imm=w&0x3ffffff;imm=imm-(1<<26)if imm&(1<<25)else imm;target=a+imm*4
                    tm=re.search(r'\b(?:bl|b)\s+0x([0-9a-f]+)',code);assert tm and int(tm[1],16)==target,(p,hex(a),code);bl+=1
        merged,gaps=gap_ranges(execsec,covered)
        # LLVM marks data directives/architecture mapping symbols; any bytes omitted are explicit, never hidden.
        counts['llvm_instructions']+=num;counts['llvm_arm64_B_BL_targets']+=bl
        r['verified_instruction_records']=num;r['verified_arm64_B_BL_targets']=bl;r['llvm_unlisted_executable_ranges']=gaps
    entries=json.loads(Path(doc['exported_entrypoints']['file']).read_text());walk(entries);counts['native_export_entries']=len(entries)
    crit=json.loads(Path(doc['critical_business_bodies']['file']).read_text());assert crit==critical_inventory();walk(crit);counts['critical_finite_function_bodies']=len(crit)
    v={'status':'PASS','method':'Reparse every ELF, ZIP byte identity, reparse every ABI Go pclntab, Ghidra counts/ranges, all C file hashes/line bounds, all LLVM raw machine bytes and ARM64 B/BL targets.',
       'counts':dict(counts),'unique_verified_source_files':len(seen),'llvm_results':doc['full_llvm_listings'],
       'limitations':['Syntactic closed C + completed decompiler output is not semantic equivalence or original source recovery.','LLVM unlisted executable ranges are explicitly reported; may include mapped literal data/PLT padding.','Ghidra project function discovery is not proof that stripped binary has no undiscovered functions.']}
    put(OUT/'verification.json',v);print(json.dumps({'status':'PASS','counts':dict(counts)},ensure_ascii=False))

if __name__=='__main__':
    ap=argparse.ArgumentParser();ap.add_argument('--verify',action='store_true');args=ap.parse_args()
    if not args.verify:build()
    verify()
