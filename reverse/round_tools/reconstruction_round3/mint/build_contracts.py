#!/usr/bin/env python3
"""Hash original instruction evidence and local VM-reference evidence; not APK execution."""

from pathlib import Path as _PublicPath
import sys as _public_sys
_public_sys.path.insert(0, str(_PublicPath(__file__).resolve().parents[3] / "scripts"))
from _paths import app_root as _public_app_root, java_home as _public_java_home
from pathlib import Path
import hashlib,io,json,re
from elftools.elf.elffile import ELFFile
from capstone import Cs,CS_ARCH_ARM64,CS_MODE_LITTLE_ENDIAN
ROOT=_public_app_root()
HERE=Path(__file__).resolve().parent
OUT=ROOT/'reconstruction/evidence/round3/mint'
ELF=ROOT/'unpacked/lib/arm64-v8a/libapp.so'
VM=ROOT/'tools/blutter/dartsdk/v3.5.2'
def sha(data):return hashlib.sha256(data).hexdigest()
def fileinfo(p):return {'path':str(p.relative_to(ROOT)),'sha256':sha(p.read_bytes())}
def main():
    data=ELF.read_bytes();elf=ELFFile(io.BytesIO(data));md=Cs(CS_ARCH_ARM64,CS_MODE_LITTLE_ENDIAN)
    proofs=[]
    for addr,size,name in [(0x52a2a4,0xe8,'Message.toJson'),(0x580b30,0x84,'Object.toString'),(0x6f791c,0x38,'_IntegerImplementation.toDouble'),(0x2ebc94,0xb8,'_Double.fromInteger')]:
        segment=next(s for s in elf.iter_segments() if s['p_type']=='PT_LOAD' and s['p_vaddr']<=addr<s['p_vaddr']+s['p_filesz'])
        off=segment['p_offset']+addr-segment['p_vaddr'];raw=data[off:off+size];ins=list(md.disasm(raw,addr));assert len(ins)*4==size
        text='\n'.join(f'0x{i.address:x}: {i.bytes.hex()} {i.mnemonic} {i.op_str}' for i in ins)+'\n'
        (OUT/f'{addr:x}.raw.txt').write_text(text)
        proofs.append({'entry':hex(addr),'name':name,'size':size,'elf_file_offset':off,'sha256':sha(raw),'instruction_words':len(ins),'whole_selected_body_disassembled':True,'original_runtime_execution':False})
    lines=(OUT/'reference.tsv').read_text().splitlines();metadata=[x for x in lines if not x.startswith('VALUE\t')]
    assert any('GDT\t60\t[dart:core] _Mint\t0x580b30' in x and 'native_name=Object_toString' in x for x in metadata)
    assert any('NATIVE_FACTORY\t0x2ebc94' in x and 'native_name=Double_doubleFromInteger' in x for x in metadata)
    assert any('GDT\t4688\t[dart:core] DateTime\t0x5715ac' in x for x in metadata)
    excerpts=[]
    for rel,first,last in [('runtime/lib/object.cc',61,74),('runtime/lib/double.cc',22,30),('runtime/vm/object.cc',23010,23023),('runtime/vm/object.cc',23257,23259),('runtime/vm/object.cc',23291,23293),('runtime/vm/object.cc',23331,23337),('runtime/vm/object.cc',23361,23363),('runtime/platform/globals.h',413,418)]:
        p=VM/rel;alllines=p.read_text().splitlines();text='\n'.join(f'{n}: {alllines[n-1]}' for n in range(first,last+1))+'\n'
        dest=OUT/(Path(rel).name+f'.L{first}-{last}.txt');dest.write_text(text)
        excerpts.append({'source':str(p.relative_to(ROOT)),'source_sha256':sha(p.read_bytes()),'first_line':first,'last_line':last,'captured_excerpt':str(dest.relative_to(ROOT)),'excerpt_sha256':sha(dest.read_bytes())})
    test=json.loads((OUT/'verification.json').read_text());assert test['status']=='PASS' and test['differential_cases']==20856 and test['differences']==0
    code=ROOT/'reconstruction/app/src/main/java/com/re/xcs/rebuild/core/DartIntegers.java'
    files=[ELF,HERE/'mint_oracle.cpp',HERE/'build_commands.json',HERE/'verify_mint.py',HERE/'build_contracts.py',HERE/'cases.txt',OUT/'reference.tsv',OUT/'MintConversionTest.java',OUT/'run_tests.sh',code,ROOT/'tools/blutter/packages/lib/libdartvm3.5.2_android_arm64.a']
    report={
      'scope':'Signed 64-bit native Dart int toString/toDouble reconstruction; not full original-source recovery',
      'status':'PASS',
      'resolved_claims':[
       {'id':'Mint.msg_content.toString','dispatch':'Message.toJson 0x52a330 GDT[cid+0x6d49], CID60 ->0x580b30','native_binding':'Object_toString (read from original snapshot Function.native_name)','native_body_reference':'Object_toString creates Instance::CheckedHandle, then calls instance.ToCString(). The handle preserves concrete runtime type; Mint::ToCString uses signed Pd64 decimal. This is not the generic Instance::ToCString text.','implementation':'DartIntegers.toDartString accepts Java Byte/Short/Integer/Long, formats all signed64 values including Long.MIN_VALUE; Java wrappers are adapters for native Dart int and do not define its Smi/Mint allocation.'},
       {'id':'Integer.toDouble','dispatch':'_IntegerImplementation.toDouble 0x6f791c -> _Double.fromInteger 0x2ebc94; snapshot native_name Double_doubleFromInteger','original_body':'Smi fast path sign-extracts 31-bit compressed value and SCVTFs it. Mint takes native fallback.','native_body_reference':'Double_doubleFromInteger calls Integer::AsDoubleValue. Smi and Mint each static_cast<double> their signed payload.','implementation':'DartIntegers.toDouble casts checked signed64 long to double; binary64 rounding is preserved, with 2^53 and signed64 boundaries tested.'},
       {'id':'Smi.Mint.representation','observed_snapshot':'compressed pointers enabled, CID59 Smi valid [-1073741824,1073741823], CID60 Mint holds remaining signed64 values','limitation':'This is the inspected ARM64 compressed snapshot, not a claim that every 64-bit Dart build has 31-bit Smis. Mint is signed64 despite compressed references.'}
      ],
      'snapshot_metadata':metadata,
      'method_proofs':proofs,
      'original_instruction_words_reviewed':sum(p['instruction_words'] for p in proofs),
      'reference_excerpts':excerpts,
      'verification':dict(test,reference='Local Dart VM3.5.2 linked C++ implementation, loaded with original APK snapshot; Integer::New, Instance::ToCString and Integer::AsDoubleValue executed directly. Original APK target entrypoints and libflutter native methods were not invoked.',seed=35260,random_samples_requested=20000,boundary_cases_added=856),
      'remaining':['BigInt, numeric parsing, arithmetic overflow, custom Number subclasses, and arbitrary Dart dynamic receivers are outside this helper.','DateTime has its own CID4688 GDT toString override at0x5715ac; it must use the separately reconstructed DateTime implementation.','Entire Object_toString behavior for non-int instances, full noSuchMethod/error identity, and original engine native runtime execution are not claimed.','Method-level original source and whole-application equivalence remain unrecovered.'],
      'source_manifest':[fileinfo(p) for p in files],
      'business_server_contacted':False,'original_apk_runtime_executed':False,'original_source_recovered':False,'frozen_audit_modified':False
    }
    (OUT/'contracts.json').write_text(json.dumps(report,ensure_ascii=False,indent=2)+'\n')
    verification=dict(test,reference=report['verification']['reference'],source_manifest=[fileinfo(p) for p in [code,OUT/'MintConversionTest.java',OUT/'run_tests.sh',OUT/'reference.tsv']],original_apk_runtime_executed=False,business_server_contacted=False,original_source_recovered=False)
    (OUT/'verification.json').write_text(json.dumps(verification,ensure_ascii=False,indent=2)+'\n')
    print(json.dumps({'status':'PASS','instruction_words':report['original_instruction_words_reviewed'],'snapshot_native_names_verified':2,'differential_cases':test['differential_cases']}))
if __name__=='__main__':main()
