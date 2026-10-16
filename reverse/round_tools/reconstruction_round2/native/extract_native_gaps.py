#!/usr/bin/env python3
"""Extract exact Go metadata-delimited native bodies; no target execution."""

from pathlib import Path as _PublicPath
import sys as _public_sys
_public_sys.path.insert(0, str(_PublicPath(__file__).resolve().parents[3] / "scripts"))
from _paths import app_root as _public_app_root, java_home as _public_java_home
import hashlib, io, json, re, subprocess
from pathlib import Path
from elftools.elf.elffile import ELFFile

OUT=Path(__file__).resolve().parent
ROOT=_public_app_root()
BASE=ROOT/'analysis/completeness_audit/native'
LLVM='/opt/homebrew/opt/llvm/bin/llvm-objdump'
TARGETS=['internal/bytealg.CountString','internal/bytealg.IndexByte','internal/bytealg.IndexByteString',
         'runtime.rt0_go','runtime.systemstack','runtime.morestack','runtime.morestack_noctxt','runtime.abort']
HELPERS=['countbytebody','countbody','internal/bytealg.countGenericString','indexbytebody','gosave_systemstack_switch',
         'runtime.save_g','runtime.mstart','runtime.badmorestackg0','runtime.badmorestackgsignal','runtime.badsystemstack',
         'runtime.check','runtime.args','runtime.osinit','runtime.schedinit','runtime.newproc','runtime.newstack']

def digest(b):return hashlib.sha256(b).hexdigest()

def main():
    result={'source_recovered':False,'scope':'Exact metadata interval extraction, including padding; independent from Ghidra body attribution','abis':{}}
    for abi in ['arm64-v8a','armeabi-v7a','x86','x86_64']:
        lib=ROOT/'unpacked/lib'/abi/'librsa_bridge.so';blob=lib.read_bytes();elf=ELFFile(io.BytesIO(blob))
        metadata=BASE/'go'/abi/'functions.json';all_functions=json.loads(metadata.read_text());selected=[]
        folder=OUT/'bodies'/abi;folder.mkdir(parents=True,exist_ok=True)
        for f in all_functions:
            if f['name'] not in TARGETS+HELPERS:continue
            start,end=int(f['address'],16),int(f['end_exclusive'],16)
            segment=next(s for s in elf.iter_segments() if s['p_type']=='PT_LOAD' and s['p_vaddr']<=start and end<=s['p_vaddr']+s['p_filesz'])
            offset=segment['p_offset']+start-segment['p_vaddr'];raw=blob[offset:offset+end-start]
            rawpath=folder/f'{start:08x}.bin';rawpath.write_bytes(raw)
            asm=subprocess.run([LLVM,'-d','--start-address='+hex(start),'--stop-address='+hex(end),str(lib)],check=True,stdout=subprocess.PIPE,text=True).stdout
            asmpath=folder/f'{start:08x}.asm.txt';asmpath.write_text(asm)
            refs=[]
            for line in asm.splitlines():
                match=re.search(r'^\s*([0-9a-f]+):.*\b(b|bl|callq?|jmp)\s+(0x[0-9a-f]+)',line)
                if match:
                    address=int(match.group(3),16);matches=[g['name'] for g in all_functions if int(g['address'],16)==address]
                    refs.append({'pc':'0x'+match.group(1),'operation':match.group(2),'target':hex(address),'go_exact_entry_names':matches})
            selected.append({'name':f['name'],'entry':hex(start),'end_exclusive':hex(end),'bytes':len(raw),
              'elf_file_offset':offset,'raw_sha256':digest(raw),'raw_file':str(rawpath.relative_to(OUT)),
              'llvm_file':str(asmpath.relative_to(OUT)),'llvm_sha256':digest(asmpath.read_bytes()),
              'metadata_record':f,'direct_control_transfers':refs})
        result['abis'][abi]={'library':str(lib.relative_to(ROOT)),'library_sha256':digest(blob),
          'metadata_file':str(metadata.relative_to(ROOT)),'metadata_sha256':digest(metadata.read_bytes()),
          'target_count':sum(f['name'] in TARGETS for f in selected),
          'targets_not_emitted_under_exact_name':[n for n in TARGETS if not any(f['name']==n for f in selected)],'functions':selected}
    (OUT/'native_gap_bodies.json').write_text(json.dumps(result,ensure_ascii=False,indent=2)+'\n')
    print({abi:row['target_count'] for abi,row in result['abis'].items()})

if __name__=='__main__':main()
