#!/usr/bin/env python3
"""Publish stable round-3 SIMD sources, fixtures and explicit limitations."""

from pathlib import Path as _PublicPath
import sys as _public_sys
_public_sys.path.insert(0, str(_PublicPath(__file__).resolve().parents[3] / "scripts"))
from _paths import app_root as _public_app_root, java_home as _public_java_home
import csv,hashlib,json,shutil
from pathlib import Path
HERE=Path(__file__).resolve().parent
APP=_public_app_root()
DEST=APP/'reconstruction/evidence/round3/simd'
def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()
def main():
    j=json.loads((HERE/'differential_verification.json').read_text())
    java=APP/'reconstruction/app/src/main/java/com/re/xcs/rebuild/core/GoBytePrimitives.java'
    assert j['status']=='PASS' and j['c_source_sha256']==sha(HERE/'go_byte_primitives.c') and j['java_class_sha256']==sha(java)
    assert j['original_fixture_sha256']==sha(HERE/'original_arm64_cases.bin.gz')
    expected=set(range(0x5ae90,0x5af3c,4))|set(range(0x5b310,0x5b3f4,4))
    assert expected<=set(int(x,16) for x in j['original_executed_instructions'])
    old=APP/'analysis/reconstruction_round2/native'
    bodydir=HERE/'original_bodies';bodydir.mkdir(exist_ok=True)
    meta=json.loads((old/'native_gap_bodies.json').read_text())['abis']['arm64-v8a']
    selected=[]
    for address in ('0005ae90','0005b310'):
        for suffix in ('.bin','.asm.txt'):
            shutil.copyfile(old/'bodies/arm64-v8a'/(address+suffix),bodydir/(address+suffix))
        selected.append(next(x for x in meta['functions'] if int(x['entry'],16)==int(address,16)))
    (bodydir/'metadata.json').write_text(json.dumps({'library_sha256':meta['library_sha256'],'functions':selected},ensure_ascii=False,indent=2)+'\n')
    diag=list(csv.DictReader((HERE/'ghidra/status.tsv').open(),delimiter='\t'))
    baseline=[x for x in diag if x['experiment'].startswith('baseline')]
    assert len(baseline)==2 and all(x['completed']=='false' for x in baseline)
    verification={'status':'PASS','scope':'Two SIMD shared bodies, genuine compiled reconstructions and original-instruction differential tests',
      'original_source_recovered':False,'original_source_recovered_count':0,'remaining_original_body_decompiler_errors':2,
      'compiled_semantic_implementations':['go_byte_primitives.c','app/src/main/java/com/re/xcs/rebuild/core/GoBytePrimitives.java'],
      'new_business_call_sites':0,'business_server_contacted':False,
      'dataset_inputs':j['dataset_inputs'],'original_arm64_function_executions':j['original_arm64_function_executions'],
      'compiled_c_result_checks':j['compiled_c_result_checks'],'java_result_checks':j['java_result_checks'],
      'java_boundary_checks':j['java_boundary_checks'],'c_sanitizer_checks':sum(x['checks'] for x in j['sanitizer_runs']),
      'original_memory_boundary_checks':j['memory_boundaries']['checks'],'original_instruction_coverage':{'executed':100,'total':100},
      'fixture_file':j['original_fixture_file'],'fixture_sha256':j['original_fixture_sha256'],
      'java_source_sha256':sha(java),'c_source_sha256':sha(HERE/'go_byte_primitives.c'),
      'portable_test_command':'sh evidence/round3/simd/run_tests.sh',
      'portable_test_type':'Replay recorded original ARM64 results; does not emulate original machine code without the APK',
      'detailed_original_execution_report':'differential_verification.json',
      'ghidra_diagnosis':{'original_bodies_still_fail':True,'temporary_nop_ablations':True,'temporary_ld1_to_ldp_analysis_outputs':2,
        'all_elf_and_database_changes_rolled_back':True,'diagnostic_c_used_as_implementation':False,
        'internal_hash_collision_count_measured':False,'results':'ghidra/status.tsv'},
      'limitations':['Original Go authoring source is not recovered.','Original ARM64 index reads whole aligned blocks; safe Java/C index uses bounded reads.','Caller must supply valid readable/writable objects; C range checks cannot prove arbitrary pointer validity.','Original tested ISA is little-endian ARM64; C tested on macOS arm64 with NEON and scalar backends.','Checked argument failures are reconstruction API behavior, not original Go assembly exceptions.','No concurrent runtime, JNI or business invocation equivalence is claimed.']}
    (HERE/'verification.json').write_text(json.dumps(verification,ensure_ascii=False,indent=2)+'\n')
    DEST.mkdir(parents=True,exist_ok=True)
    for p in HERE.rglob('*'):
        if p.is_file() and 'build' not in p.relative_to(HERE).parts and '__pycache__' not in p.parts and p.name!='manifest.json':
            target=DEST/p.relative_to(HERE);target.parent.mkdir(parents=True,exist_ok=True);shutil.copyfile(p,target)
    (DEST/'run_tests.sh').chmod(0o755)
    manifest={'original_source_recovered':False,'files':[{'file':str(p.relative_to(DEST)),'bytes':p.stat().st_size,'sha256':sha(p)} for p in sorted(DEST.rglob('*')) if p.is_file() and p.name!='manifest.json']}
    (DEST/'manifest.json').write_text(json.dumps(manifest,ensure_ascii=False,indent=2)+'\n')
    print(json.dumps({'status':'PASS','evidence_files':len(manifest['files']),'destination':str(DEST)}))
if __name__=='__main__':main()
