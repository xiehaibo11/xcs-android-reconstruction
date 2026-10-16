#!/usr/bin/env python3
"""Assemble evidence without promoting diagnostic C to original source."""

from pathlib import Path as _PublicPath
import sys as _public_sys
_public_sys.path.insert(0, str(_PublicPath(__file__).resolve().parents[3] / "scripts"))
from _paths import app_root as _public_app_root, java_home as _public_java_home
import csv,hashlib,json,shutil,io
from pathlib import Path
from elftools.elf.elffile import ELFFile

OUT=Path(__file__).resolve().parent
APP=_public_app_root()
DEST=APP/'reconstruction/evidence/round2/native'
def load(name):return json.loads((OUT/name).read_text())
def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()
def span(start,end,fact):return {'start':hex(start),'end_exclusive':hex(end),'fact':fact}

def main():
    bodies=load('native_gap_bodies.json');tests=load('emulation_verification.json')
    assert tests['status']=='PASS'
    meta=bodies['abis']['arm64-v8a']['functions']
    targets=[('internal/bytealg.CountString',0x5af40),('internal/bytealg.IndexByte',0x5b400),
      ('internal/bytealg.IndexByteString',0x5b420),('runtime.rt0_go',0xbd980),('runtime.systemstack',0xbdb30),
      ('runtime.morestack',0xbdbe0),('runtime.morestack_noctxt',0xbdc60),('runtime.abort',0xc00f0)]
    facts={
      0x5af40:dict(
        semantics='Count occurrences of an unsigned byte in a Go string; byte-oriented, not Unicode/rune-oriented. Empty input returns 0 without dereferencing the data pointer.',
        abi={'data':'SP+8','length':'SP+16','target_byte':'SP+24','result_int64':'SP+32','shared_body_registers':'x0=data, x1=byte, x2=length, x8=result address'},
        machine_code=[span(0x5af40,0x5af54,'ABI0 stack loads and tail branch to countbytebody'),span(0x5ae90,0x5aea0,'zero length and short-input branches'),span(0x5aea0,0x5aec8,'scalar prefix to 32-byte alignment'),span(0x5aec8,0x5af20,'32-byte NEON chunks; compare, mask to ones, pairwise/reduction count, 64-bit accumulation'),span(0x5af20,0x5af3c,'scalar remainder; store count and return')],
        tests='3809 cases per ABI, ARM64 and ARM32; total 7618',
        remaining=['SIMD helper still triggers Ghidra unique-varnode-hash failure after boundary repair. Executed machine code establishes tested behavior; diagnostic C is incomplete.']),
      0x5b400:dict(
        semantics='Return first byte index in a Go []byte, or -1 if absent. Capacity is not consulted. Empty input returns -1 without dereferencing its pointer.',
        abi={'data':'SP+8','length':'SP+16','capacity':'SP+24 (unused)','target_byte':'SP+32','result_int64':'SP+40','shared_body_registers':'x0=data, x1=byte, x2=length, x8=result address'},
        machine_code=[span(0x5b400,0x5b414,'ABI0 slice wrapper; tail branch to indexbytebody'),span(0x5b310,0x5b338,'zero length, saved original pointer, 32-byte alignment and weighted byte mask initialization'),span(0x5b338,0x5b374,'first unaligned 32-byte load; discard bits before the logical start'),span(0x5b374,0x5b3c8,'vector scan and final-block mask after the logical end'),span(0x5b3c8,0x5b3f4,'RBIT+CLZ selects earliest matching byte; compute original-relative index or -1')],
        tests='3809 cases per ABI, ARM64 and ARM32; total 7618',
        remaining=['SIMD loads may read outside the logical slice within aligned 32-byte blocks. Bit masks exclude those bytes; callers still need valid Go memory/page invariants.','SIMD helper C decompilation remains a Ghidra failure.']),
      0x5b420:dict(
        semantics='Return first byte index in a Go string, or -1 if absent; same shared machine code as IndexByte with different ABI0 stack layout.',
        abi={'data':'SP+8','length':'SP+16','target_byte':'SP+24','result_int64':'SP+32','shared_body_registers':'x0=data, x1=byte, x2=length, x8=result address'},
        machine_code=[span(0x5b420,0x5b434,'ABI0 string wrapper; tail branch to the same indexbytebody at 0x5b310'),span(0x5b310,0x5b3f4,'identical shared implementation described for IndexByte')],
        tests='3809 cases per ABI, ARM64 and ARM32; total 7618',
        remaining=['Same bounded vector over-read and Ghidra helper limitation as IndexByte.']),
      0xbd980:dict(
        semantics='Go runtime bootstrap: initialize g0 stack and guards, optionally call cgo_init with Android TLS arguments, publish g/TLS, link g0 and m0, initialize runtime, schedule runtime.main and enter mstart. It is a runtime entry, not an RSA operation.',
        machine_code=[span(0xbd980,0xbd9b8,'save argc/argv; g0=0x410f60; stack low=SP-65536, stack high=SP, initial guards=low'),span(0xbd9b8,0xbd9ec,'optional indirect cgo_init; x0=g0, x1=setg_gcc 0xbd350, x2=tls_g storage 0x3e7ee0, x3=TPIDR_EL0'),span(0xbd9ec,0xbda10,'save_g; guard0=guard1=stack.lo+0x3a0; m0 at 0x4113c0 links g0'),span(0xbda10,0xbda50,'check -> args -> osinit -> schedinit -> newproc -> mstart; newproc argument funcval at 0x2bf730 points to runtime.main at 0x90080'),span(0xbda50,0xbda64,'unexpected mstart return: null store at 0xbda5c, followed by invalid word 0xbea71700 at 0xbda60')],
        tests='Two startup branches with modeled callees; unexpected mstart return faults at the original null store.',
        remaining=['cgo_init, check, args, osinit, schedinit and newproc internals are explicitly modeled; mstart boundary is stopped. This does not establish complete Go initialization or OS interaction.','ELF loader relocation behavior and full runtime startup are outside this isolated-fragment test.']),
      0xbdb30:dict(
        semantics='Run a function value on the system stack: direct tail call on g0/gsignal, save curg and switch to g0 otherwise, then restore current g/SP/BP/TLS and clear saved SP/BP. An unexpected g calls badsystemstack then abort.',
        machine_code=[span(0xbdb30,0xbdb6c,'function value from caller SP+8; compare g against m.gsignal, m.g0, then m.curg'),span(0xbdb6c,0xbdb7c,'unexpected g: badsystemstack ABI0 wrapper 0xc1f30, then abort'),span(0xbdb7c,0xbdb9c,'gosave_systemstack_switch; switch g to g0, save_g, restore g0 SP/BP, call closure code pointer'),span(0xbdb9c,0xbdbc8,'restore m.curg/TLS and saved SP/BP; clear g.sched.sp at +0x38 and bp at +0x68'),span(0xbdbc8,0xbdbd8,'g0/gsignal path restores caller LR/SP and tail-branches to closure code pointer; not a jump table'),span(0xbd310,0xbd344,'save helper stores resume PC/SP/BP, zeroes sched.lr/ret, aborts if sched.ctxt is nonzero'),span(0xc17f0,0xc1810,'save_g writes g to TPIDR_EL0 + tls_g only if iscgo is nonzero')],
        tests='g0 direct; gsignal direct; curg switch and restore; invalid g; invalid saved context; iscgo TLS restore.',
        remaining=['Callback is a synthetic immediate return; this does not model arbitrary callback execution, panic/unwind, scheduler concurrency or OS signals.','badsystemstack is modeled as returning solely to reach the original fallback abort.']),
      0xbdbe0:dict(
        semantics='Save an ordinary goroutine caller state, save m.morebuf, switch to g0 and transfer to newstack. Growing g0 or gsignal is prohibited. newstack is expected not to return.',
        machine_code=[span(0xbdbe0,0xbdc0c,'reject g0/gsignal via badmorestack helpers and abort'),span(0xbdc0c,0xbdc34,'save g.sched SP/BP/PC/LR/context and m.morebuf SP/PC/g'),span(0xbdc34,0xbdc50,'switch to g0 and publish TLS; use g0 SP/BP; create dummy frame; call newstack ABI0 0xc1f10'),span(0xbdc50,0xbdc54,'invalid word 0xbea71700 is a non-return sentinel, not missing business instructions')],
        state_offsets={'g.sched.sp':'+0x38','g.sched.pc':'+0x40','g.sched.ctxt':'+0x50','g.sched.lr':'+0x60','g.sched.bp':'+0x68','m.morebuf.sp':'+0x08','m.morebuf.pc':'+0x10','m.morebuf.g':'+0x18'},
        tests='normal handoff; rejects g0 and gsignal; modeled newstack return traps at 0xbdc50; iscgo TLS publication.',
        remaining=['newstack allocator/copy/unwind/scheduler implementation is stopped at its ABI0 entry; only handoff state is verified.']),
      0xbdc60:dict(
        semantics='Context-free stack-growth entry: MOV SP,SP keeps the unwinder stack-write marker, clear closure context x26, then tail branch to morestack.',
        machine_code=[span(0xbdc60,0xbdc6c,'MOV SP,SP; zero x26; B 0xbdbe0'),span(0xbdc6c,0xbdc70,'alignment padding word 0; not required executable behavior')],
        tests='Actual tail transfer verifies saved context becomes 0 and all morestack handoff fields are populated.',
        remaining=['Inherits morestack runtime-callee boundary; no standalone missing algorithm.']),
      0xc00f0:dict(
        semantics='Deliberately terminate execution: set x0=0, load from null, then an invalid-instruction fallback word. No return value or RSA logic.',
        machine_code=[span(0xc00f0,0xc00f8,'zero x0 then load at address 0; emulator faults at 0xc00f4'),span(0xc00f8,0xc00fc,'0xbea71700 invalid-instruction fallback'),span(0xc00fc,0xc0100,'alignment padding')],
        tests='Direct invocation and all tested abort paths stop on the same original null read.',
        remaining=['Actual Android signal/abort handling after the hardware fault is not executed.'])
    }
    rows=[]
    for name,address in targets:
        f=next(f for f in meta if f['entry']==hex(address))
        row={'name':name,'elf_entry':hex(address),'ghidra_entry':hex(address+0x100000),
          'status':'bounded_function_semantics_established','original_source_recovered':False,
          'baseline_tool_status':f['metadata_record']['c_status'],'metadata_record':f['metadata_record'],
          'machine_code_file':f['raw_file'],'machine_code_sha256':f['raw_sha256'],
          'assembly_file':f['llvm_file'],'cross_abi_entries':{},**facts[address]}
        for abi,ar in bodies['abis'].items():
            row['cross_abi_entries'][abi]=[{'entry':g['entry'],'end_exclusive':g['end_exclusive'],'raw_file':g['raw_file'],'raw_sha256':g['raw_sha256']} for g in ar['functions'] if g['name']==name]
        rows.append(row)
    diagnostic=list(csv.DictReader((OUT/'ghidra_diagnosis/status.tsv').open(),delimiter='\t'))
    lib=(APP/'unpacked/lib/arm64-v8a/librsa_bridge.so').read_bytes();elf=ELFFile(io.BytesIO(lib))
    address=0x2bf730;seg=next(s for s in elf.iter_segments() if s['p_type']=='PT_LOAD' and s['p_vaddr']<=address<s['p_vaddr']+s['p_filesz'])
    off=seg['p_offset']+address-seg['p_vaddr'];value=int.from_bytes(lib[off:off+8],'little')
    assert value==0x90080
    data_evidence={'virtual_address':hex(address),'elf_file_offset':off,'raw_bytes':lib[off:off+8].hex(),'value':hex(value),
      'target_go_name':'runtime.main','rela_dyn_records':[dict(r.entry) for sec in elf.iter_sections() if sec['sh_type']=='SHT_RELA' for r in sec.iter_relocations() if r['r_offset']==address]}
    report={'scope':'Eight previously failed/truncated Go functions in the original librsa_bridge.so. Semantics and tooling causes, not original-source restoration.',
      'requested_gap_count':8,'bounded_semantics_established':8,'original_source_recovered_count':0,
      'application_source_changes':[],'jca_replacement_defect_established':False,
      'apk_sha256':sha(APP/'input/app_xcs.apk'),
      'go_build_info':{'file':'analysis/deep_rsa/go_build_info.txt','sha256':sha(APP/'analysis/deep_rsa/go_build_info.txt')},
      'startup_main_function_value':data_evidence,
      'business_relevance':'The eight entries are Go byte primitives and runtime assembly. They neither establish RSA padding/key-format behavior nor prove the fast_rsa bridge is invoked by login. No LoginFlow/JCA modification is justified by these eight functions alone.',
      'emulation':{'report':'emulation_verification.json','status':tests['status'],'bytealg_cases':sum(r['cases'] for r in tests['bytealg'].values()),'runtime_boundary_cases':len(tests['runtime']),'original_binary_execution':'Unicorn isolated fragments only','full_go_runtime_execution':False,'server_contacted':False},
      'decompiler_diagnosis':{'experiment':'DiagnoseBytealg.java','results':'ghidra_diagnosis/status.tsv','original_database_modified':False,
        'observed':['Baseline three wrappers fail with Unable to find unique hash for varnode.','Pclntab boundary repair and separate shared-body functions alone do not fix the error.','Adding explicit CALL_RETURN flow annotation at the wrapper tail branches produces diagnostic C for all three wrappers.','Both isolated SIMD shared bodies still fail. This localizes the remaining defect to decompilation inside those bodies; it does not prove the exact Ghidra internal bug.','Five runtime truncations point to intentional invalid instructions and/or an indirect function-value tail call. The original bytes are present and isolated execution reaches the expected boundaries.'],
        'remaining_helper_decompiler_errors':['countbytebody at 0x5ae90','indexbytebody at 0x5b310'],
        'wrapper_c_is_complete_algorithm':False,'diagnostic_rows':diagnostic},
      'upstream_corroboration':[{'url':'https://raw.githubusercontent.com/golang/go/go1.21.0/src/runtime/asm_arm64.s','use':'Corroborates runtime function names and intentional non-return boundaries; local machine-code and emulator evidence are primary.'}],
      'rows':rows,
      'global_limits':['No original Dart/Go/Rust authoring source recovered by this round.','A bounded emulator fixture cannot prove full application, runtime, scheduler, signal or concurrency equivalence.','Ghidra-generated C is diagnostic output with manually supplied flow annotations; it is not buildable recovered original source.','Public upstream source was read for corroboration; no business server, credential or external account was used.']}
    (OUT/'go_gap_resolution.json').write_text(json.dumps(report,ensure_ascii=False,indent=2)+'\n')
    DEST.mkdir(parents=True,exist_ok=True)
    for path in OUT.rglob('*'):
        if path.is_file() and '__pycache__' not in path.parts and path.name not in ('evidence_manifest.json',):
            dest=DEST/path.relative_to(OUT);dest.parent.mkdir(parents=True,exist_ok=True)
            if dest.resolve()!=path.resolve():shutil.copyfile(path,dest)
    manifest={'files':[{'file':str(p.relative_to(DEST)),'bytes':p.stat().st_size,'sha256':sha(p)} for p in sorted(DEST.rglob('*')) if p.is_file() and p.name!='evidence_manifest.json'],
      'source_analysis_directory':str(OUT),'original_source_recovered':False}
    (DEST/'evidence_manifest.json').write_text(json.dumps(manifest,ensure_ascii=False,indent=2)+'\n')
    print(json.dumps({'bytealg_cases':report['emulation']['bytealg_cases'],'runtime_cases':len(tests['runtime']),'target_count':len(rows),'evidence_files':len(manifest['files'])}))

if __name__=='__main__':main()
