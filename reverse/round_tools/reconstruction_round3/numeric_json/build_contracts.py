#!/usr/bin/env python3

from pathlib import Path as _PublicPath
import sys as _public_sys
_public_sys.path.insert(0, str(_PublicPath(__file__).resolve().parents[3] / "scripts"))
from _paths import app_root as _public_app_root, java_home as _public_java_home
from pathlib import Path
import hashlib,io,json,subprocess,shutil
from elftools.elf.elffile import ELFFile
from capstone import Cs,CS_ARCH_ARM64,CS_MODE_LITTLE_ENDIAN
ROOT=_public_app_root()
HERE=Path(__file__).resolve().parent
OUT=ROOT/'reconstruction/evidence/round3/numeric_json'
SDK=ROOT/'analysis/reconstruction_round3/datetime/reference/dart-sdk'
def sha(data):return hashlib.sha256(data).hexdigest()
def info(p):return {'path':str(p.relative_to(ROOT)),'sha256':sha(p.read_bytes())}
def main():
    elfpath=ROOT/'unpacked/lib/arm64-v8a/libapp.so';data=elfpath.read_bytes();elf=ELFFile(io.BytesIO(data));md=Cs(CS_ARCH_ARM64,CS_MODE_LITTLE_ENDIAN)
    methods=[]
    for addr,size,name in [(0x2ed154,0xba8,'parseNumber'),(0x2eb3ac,0x174,'finishChunkNumber'),(0x2eb520,0x34,'NumberBuffer.parseDouble'),(0x2ebda4,0x34,'NumberBuffer.parseNum'),(0x2edd6c,0x80,'_parseDouble')]:
        seg=next(s for s in elf.iter_segments() if s['p_type']=='PT_LOAD' and s['p_vaddr']<=addr<s['p_vaddr']+s['p_filesz']);off=seg['p_offset']+addr-seg['p_vaddr'];raw=data[off:off+size]
        ins=list(md.disasm(raw,addr));assert len(ins)*4==size
        (OUT/f'{addr:x}.raw.txt').write_text('\n'.join(f'0x{i.address:x}: {i.bytes.hex()} {i.mnemonic} {i.op_str}' for i in ins)+'\n')
        methods.append({'entry':hex(addr),'name':name,'size':size,'elf_offset':off,'sha256':sha(raw),'instruction_words':len(ins),'scope':'Original body captured and byte-grounded; not original-runtime execution or exhaustive method proof.'})
    meta=(OUT/'snapshot_metadata.tsv').read_text().splitlines();assert any('native_name=Double_parse' in x for x in meta)
    for line in ['POOL\t0xbe8\t0x7ff0000000000000','POOL\t0xc90\t0x8000000000000000','POOL\t0xc98\t0xfff0000000000000']:
        assert line in meta,line
    ref=SDK/'lib/_internal/vm/lib/convert_patch.dart';lines=ref.read_text().splitlines();excerpts=[]
    for a,b in [(241,249),(1253,1299),(1303,1458),(1654,1656)]:
        p=OUT/f'convert_patch.dart.L{a}-{b}.txt';p.write_text('\n'.join(f'{n}: {lines[n-1]}' for n in range(a,b+1))+'\n');excerpts.append(dict(info(p),reference_start_line=a,reference_end_line=b))
    raw=subprocess.run([str(OUT/'run_tests.sh')],check=True,capture_output=True,text=True);test=json.loads(raw.stdout)
    assert test['status']=='PASS' and test['differential_cases']==52778
    code=ROOT/'reconstruction/app/src/main/java/com/re/xcs/rebuild/core/JsonCodec.java'
    source_files=[code,OUT/'NumericJsonTest.java',OUT/'run_tests.sh',OUT/'reference.tsv',OUT/'snapshot_metadata.tsv',OUT/'DART_LICENSE.txt',HERE/'reference.dart',HERE/'generate_cases.py',HERE/'cases.json',HERE/'snapshot_numeric_targets.cpp',HERE/'build_commands.json',HERE/'build_contracts.py',ref,SDK/'version',SDK/'bin/dart',elfpath]
    report={
      'status':'PASS','scope':'Bounded native Dart 3.5.2 JSON number decoding and non-finite encode rejection; no complete JSON codec equivalence claim',
      'claims':[
        {'id':'JSON.signed64','behavior':'Integer grammar without decimal/exponent remains native signed64 int, including -2^63,+2^63-1 and integers above2^53. -0 is int0.','implementation':'Java Long preserving all64bits; no intermediate double.'},
        {'id':'JSON.integer_overflow','behavior':'Larger integer literals become double, not BigInt and not immediate parse errors; infinities are valid decoder outcomes.','implementation':'Long overflow falls back to Double; native type distinction is retained.'},
        {'id':'JSON.decimal_exponent','behavior':'Decimal/exponent literals become double, including signedzero/subnormals/underflow/infinities.','implementation':'End-of-input follows parseDouble. A following delimiter/whitespace follows original numeric fast path, using binary64 mantissa/powers arithmetic and the exponent>400 shortcut.'},
        {'id':'JSON.context_boundary','examples':[{'input':'400 digits9 followed by e-401, no suffix','result':'double0.1'},{'input':'same token with trailing space or in array/object','result':'double0.0'},{'input':'0. plus401zeroes then1e401, no suffix','result':'double0.1'},{'input':'same token with trailing space or in array/object','result':'Infinity'}],'reason':'Dart3.5.2 finishChunkNumber reparses the full token, while parseNumber may take exponentOverflow before considering combined decimal scale.'},
        {'id':'JSON.encode_nonfinite','behavior':'NaN/positiveInfinity/negativeInfinity remain rejected by serializer at scalar and nested list/map positions.','implementation':'Existing writer finite check retained and explicitly tested.'}
      ],
      'snapshot_metadata':meta,'targeted_original_branches':[
        {'range':'0x2ed7e8..0x2ed858','meaning':'Signed exponent comparison against0x190(400), sticky overflow flag, end-of-chunk bypass at0x2ed804, and flag test before overflow result branches.'},
        {'range':'0x2ed85c..0x2ed938','meaning':'Zero-mantissa/negative-exponent branch emits signedzero; otherwise chooses -Infinity/+Infinity by sign. Actual snapshot immediate pool bits at0xc90/0xc98/0xbe8 were read again.'},
        {'range':'0x2ed970..0x2ed988','meaning':'Exponent ending exactly at chunk boundary calls beginChunkNumber with NUM_E_DIGIT0x1c.'},
        {'range':'0x2eb428..0x2eb494','meaning':'finishChunkNumber routes NUM_DIGIT to NumberBuffer.parseNum and NUM_DOT_DIGIT/NUM_E_DIGIT to NumberBuffer.parseDouble.'},
        {'range':'0x2eda04..0x2edb40','meaning':'Mantissa comparison against pooled2^53 and exponent limits±22 gate FDIV/FMUL fast paths.'}
      ],'original_methods':methods,'original_instruction_words_captured':sum(m['instruction_words'] for m in methods),
      'reference':{'kind':'Official Dart3.5.2 SDK macOSARM64 jsonDecode/jsonEncode execution','download_provenance':'Sibling round3/datetime reference SDK and its provenance','sdk_version':(SDK/'version').read_text().strip(),'vm_android_snapshot_distinction':'SDK execution is a version-matched native VM reference, not execution of original Android libflutter.'},
      'reference_excerpts':excerpts,'verification':dict(test,seed=3521303,random_tokens=13000,boundary_tokens=162,malformed_tokens=34,contexts=['top-level token ending at input boundary','top-level token followed by whitespace','single-array item','object n property']),
      'remaining':['Original full Dart source and whole JSON codec equivalence are not recovered.','Non-numeric JSON grammar, Unicode edge cases, recursion/resource limits, duplicate-key policy, arbitrary receivers/toJson, exact exception class/message/offset and streaming chunk APIs are not fully ported.','JsonCodec.stringify finite Double lexical formatting still uses Java Number.toString; semantically equal JSON numbers may have different decimal/exponent spellings than Dart jsonEncode.','This tests native Dart3.5.2 reference. Dart JavaScript numeric semantics and other VM versions/architectures are outside scope.'],
      'source_manifest':[info(p) for p in source_files],'business_server_contacted':False,'original_apk_runtime_executed':False,'original_source_recovered':False,'frozen_audit_modified':False
    }
    (OUT/'contracts.json').write_text(json.dumps(report,ensure_ascii=False,indent=2)+'\n')
    verification=dict(test,source_manifest=[info(p) for p in [code,OUT/'NumericJsonTest.java',OUT/'run_tests.sh',OUT/'reference.tsv']],reference=report['reference'],original_apk_runtime_executed=False,business_server_contacted=False,original_source_recovered=False)
    (OUT/'verification.json').write_text(json.dumps(verification,ensure_ascii=False,indent=2)+'\n')
    print(json.dumps({'status':'PASS','original_instruction_words_captured':report['original_instruction_words_captured'],'differential_cases':test['differential_cases']}))
if __name__=='__main__':main()
