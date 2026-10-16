#!/usr/bin/env python3
"""Verify original-binary ranges and audit claims independently of extraction."""

from pathlib import Path as _PublicPath
import sys as _public_sys
_public_sys.path.insert(0, str(_PublicPath(__file__).resolve().parents[3] / "scripts"))
from _paths import app_root as _public_app_root, java_home as _public_java_home
import csv,hashlib,io,json
from pathlib import Path
from elftools.elf.elffile import ELFFile
HERE=Path(__file__).resolve().parent
APP=_public_app_root()
def read(name):return json.loads((HERE/name).read_text())
def sha(b):return hashlib.sha256(b).hexdigest()

def main():
    j=read('native_gap_bodies.json');r=read('go_gap_resolution.json');e=read('emulation_verification.json')
    counts={};intervals=0
    for abi,a in j['abis'].items():
        blob=(APP/a['library']).read_bytes();elf=ELFFile(io.BytesIO(blob))
        assert sha(blob)==a['library_sha256']
        meta=(APP/a['metadata_file']).read_bytes();assert sha(meta)==a['metadata_sha256']
        records=json.loads(meta)
        for f in a['functions']:
            start,end=int(f['entry'],16),int(f['end_exclusive'],16)
            assert f['metadata_record'] in records
            segment=next(s for s in elf.iter_segments() if s['p_type']=='PT_LOAD' and s['p_vaddr']<=start and end<=s['p_vaddr']+s['p_filesz'])
            offset=segment['p_offset']+start-segment['p_vaddr']
            raw=(HERE/f['raw_file']).read_bytes()
            assert offset==f['elf_file_offset'] and raw==blob[offset:offset+end-start]
            assert sha(raw)==f['raw_sha256'] and len(raw)==f['bytes']
            assert sha((HERE/f['llvm_file']).read_bytes())==f['llvm_sha256']
            intervals+=1
        counts[abi]=a['target_count']
    assert counts=={'arm64-v8a':8,'armeabi-v7a':8,'x86':7,'x86_64':8}
    assert j['abis']['x86']['targets_not_emitted_under_exact_name']==['internal/bytealg.CountString']
    assert len(r['rows'])==8 and len({x['elf_entry'] for x in r['rows']})==8
    assert r['original_source_recovered_count']==0 and all(not x['original_source_recovered'] for x in r['rows'])
    assert e['status']=='PASS' and e['error'] is None and e['syscalls_executed'] is False and e['business_server_contacted'] is False
    assert e['script_sha256']==sha((HERE/'emulate_native_gaps.py').read_bytes())
    assert all(x['status']=='PASS' and x['cases']==11427 for x in e['bytealg'].values())
    assert len(e['runtime'])==16 and all(x['status']=='PASS' for x in e['runtime'])
    assert e['bytealg']['arm64-v8a']['result_fingerprint_sha256']==e['bytealg']['armeabi-v7a']['result_fingerprint_sha256']
    d=list(csv.DictReader((HERE/'ghidra_diagnosis/status.tsv').open(),delimiter='\t'))
    wrappers={'15af40','15b400','15b420'}
    for phase in ('baseline','metadata_boundaries'):
        records=[x for x in d if x['phase']==phase and x['address'] in wrappers]
        assert len(records)==3 and all(x['complete']=='false' and 'unique hash' in x['error'] for x in records)
    records=[x for x in d if x['phase']=='explicit_tail_calls' and x['address'] in wrappers]
    assert len(records)==3 and all(x['complete']=='true' for x in records)
    helpers=[x for x in d if x['phase']=='explicit_tail_calls' and x['address'] not in wrappers]
    assert len(helpers)==2 and all(x['complete']=='false' for x in helpers)
    for entry,word_at in [(0xbd980,0xbda60),(0xbdbe0,0xbdc50),(0xc00f0,0xc00f8)]:
        raw=(HERE/f'bodies/arm64-v8a/{entry:08x}.bin').read_bytes()
        assert raw[word_at-entry:word_at-entry+4]==bytes.fromhex('0017a7be')
    result={'status':'PASS','exact_original_binary_intervals_verified':intervals,'abi_target_counts':counts,
      'bytealg_cases_verified':22854,'runtime_cases_verified':16,'emulator_script_hash_matches_report':True,
      'wrapper_diagnostic_c_successes':3,'remaining_simd_decompiler_errors':2,'original_source_recovered_count':0}
    (HERE/'evidence_verification.json').write_text(json.dumps(result,ensure_ascii=False,indent=2)+'\n')
    print(json.dumps(result,ensure_ascii=False))

if __name__=='__main__':main()
