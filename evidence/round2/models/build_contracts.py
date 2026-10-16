#!/usr/bin/env python3
"""Static evidence only. Does not modify Java sources or the parent's verification.json."""
from pathlib import Path
import hashlib, json, re, io, shutil
from elftools.elf.elffile import ELFFile
from capstone import Cs, CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN
ROOT=Path(__file__).resolve().parents[4]
OUT=Path(__file__).resolve().parent
ANALYSIS=ROOT/'analysis/reconstruction_round2/models'
AUDIT=ROOT/'analysis/completeness_audit/flutter'
ELF=ROOT/'unpacked/lib/arm64-v8a/libapp.so'
def sha(data):return hashlib.sha256(data).hexdigest()
def relative(path):return str(path.relative_to(ROOT))

def main():
 data=ELF.read_bytes();elf=ELFFile(io.BytesIO(data));loads=[s for s in elf.iter_segments() if s['p_type']=='PT_LOAD'];(OUT/'methods').mkdir(exist_ok=True)
 def offset(addr):
  for s in loads:
   if s['p_vaddr']<=addr<s['p_vaddr']+s['p_filesz']:return s['p_offset']+addr-s['p_vaddr']
  raise ValueError(hex(addr))
 methods={m['address'][2:]:m for m in json.loads((AUDIT/'method_coverage.json').read_text())['methods']}
 proofs=[];failures=[];words=0
 for a in ['4901f0','459f08','52a2a4']:
  m=methods[a];ap=ROOT/m['complete_excerpt'];rp=ROOT/m['raw_disassembly'];asm=ap.read_bytes();raw=rp.read_bytes();off=m['elf_file_offset'];size=m['exported_body_size'];machine=data[off:off+size];ins=re.findall(rb'^0x([0-9a-f]+): ([0-9a-f]{8})\s',raw,re.M)
  checks={'frozen_asm_hash':sha(asm)==m['complete_excerpt_sha256'],'frozen_raw_hash':sha(raw)==m['raw_disassembly_sha256'],'frozen_machine_hash':sha(machine)==m['exported_body_sha256'],'whole_body_raw_coverage':len(ins)*4==size,'every_raw_word_matches_elf':all(data[off+int(v,16)-int(a,16):off+int(v,16)-int(a,16)+4]==bytes.fromhex(b.decode()) for v,b in ins)}
  if not all(checks.values()):failures.append({'address':a,'checks':checks})
  words+=len(ins);shutil.copyfile(ap,OUT/'methods'/(a+'.asm.txt'));shutil.copyfile(rp,OUT/'methods'/(a+'.raw.txt'))
  proofs.append({'entry':'0x'+a,'size':size,'signature':m['signature'],'source':m['source'],'elf_file_offset':off,'body_sha256':sha(machine),'raw_instruction_count':len(ins),'checks':checks,'prior_semantic_coverage':m['semantic_coverage'],'whole_method_completed':False})
 rows=[line.split('\t') for line in (ANALYSIS/'snapshot_targets.tsv').read_text().splitlines()]
 call=next(r for r in rows if r[0]=='UNLINKED' and r[1]=='0x10840')
 assert call[2]=='dyn:toDouble',call
 wanted={59,60,61,62,85,86,89,90,91,93,94}
 dispatch=[{'cid':int(r[1]),'receiver':r[2],'entry':r[3],'canonical_function_label':r[4]} for r in rows if r[0]=='GDT' and int(r[1]) in wanted]
 assert len(dispatch)==len(wanted)
 numerical=[{'cid':int(r[1]),'receiver':r[2],'entry':r[3],'function':r[4]} for r in rows if r[0]=='NUMERIC']
 slices=[];md=Cs(CS_ARCH_ARM64,CS_MODE_LITTLE_ENDIAN)
 for addr,size in [(0x6f78fc,8),(0x6f79a8,8),(0x5800fc,24)]:
  off=offset(addr);machine=data[off:off+size];ins=list(md.disasm(machine,addr));text='\n'.join(f'0x{i.address:x}: {i.bytes.hex()} {i.mnemonic} {i.op_str}' for i in ins)+'\n';(OUT/'methods'/f'{addr:x}.raw.txt').write_text(text)
  checks={'raw_covers_selected_slice':sum(i.size for i in ins)==size}
  if size==8:checks['exact_receiver_identity_body']=machine.hex()=='e00140f9c0035fd6'
  if not all(checks.values()):failures.append({'address':hex(addr),'checks':checks})
  words+=len(ins);slices.append({'entry':hex(addr),'selected_size':size,'elf_file_offset':off,'bytes_le':machine.hex(),'sha256':sha(machine),'checks':checks,'scope':'Selected body slice; not a new full SDK coverage claim'})
 lines=(ROOT/'analysis/aot_dump/pp.txt').read_text().splitlines()
 pp_refs=[{'line':n,'text':line} for n,line in enumerate(lines,1) if line.startswith(('[pp+0xcc8]','[pp+0xcd8]','[pp+0x10840]','[pp+0x14fb0]'))]
 claims=[
  {'id':'Devices.version.dynamic_toDouble','status':'selector_closed_numeric_receiver_subset_reconstructed','entry':'0x4901f0','callsite':'0x490614..0x490620','object_pool_offset':'0x10840','selector':call[2],
   'original_dataflow':['0x4905f4..0x490604 reads JSON[version] through map index dispatch.','0x490608 puts that result in receiver slot; 0x490614..0x490620 uses PP0x10840 UnlinkedCall. Snapshot target_name is dyn:toDouble.','There is no null/type-to-string/default branch between this map read and the dynamic call. Missing/null is not mapped to a numeric default.','0x490624..0x49062c preserves returned value; 0x491128..0x491130 loads returned Double payload and stores unboxed Devices.field37.'],
   'bounded_implementation':{'accepted':'Java integral wrappers Byte/Short/Integer/Long and Double; returns doubleValue (rounding applies for large integers).','rejected':'null, String, Boolean and unsupported custom receivers; no numeric-string parser or silent zero default.','observed_snapshot_numeric_entry':numerical},
   'limits':['The IC selector is proven; every possible runtime receiver/noSuchMethod path is not enumerated.','The int-to-double Java conversion is a primitive numeric reconstruction supported by matching Dart runtime Double_doubleFromInteger/AsDoubleValue behavior. These tests are not exhaustive original-APK IC execution.','Devices model remains partial because create_time DateTime conversion is still unrecovered.']},
  {'id':'Message.toJson.msg_content','status':'null_branch_and_dispatch_selector_closed_supported_receivers_bounded','entry':'0x52a2a4','null_branch':'0x52a308..0x52a314','dispatch':'0x52a318..0x52a33c',
   'original_dataflow':['The two-entry result Map copies msg_type from field7 unchanged.','msg_content loads field_b. Null bypasses dispatch and writes actual null; it is not the four-character string null.','For non-null, compressed Smi receives CID59; heap receivers load CID. 0x52a330 uses GDT[cid+0x6d49] with a receiver-only argument descriptor.','The call result becomes Map[msg_content] before Map._fromLiteral. This is dynamic toString formatting, not JSON serialization of the content object.'],
   'snapshot_receiver_rows':dispatch,
   'supported_receiver_subset':{'String':'CID93/94 both select 0x6f79a8, exact ldr x0,[SP];ret; returns the receiver even though shared code has an unrelated canonical label.','bool':'CID62 ->0x5800fc; reads boolean bit and returns pooled true/false string.','Smi':'CID59 ->0x580434 _Smi::toString; compressed signed range [-2^30, 2^30).','Double':'CID61 ->0x580114 _Double::toString; Java shortest formatting checked against local Dart 3.5.2 reference implementation.','List':'CID89/90/91 ->0x57fb60 ListBase::toString; bounded acyclic list display syntax, comma+space, no JSON string quotes.','Map':'CID85/86 ->0x57fbfc MapMixin::toString; bounded acyclic insertion-order map display syntax key: value with comma+space.'},
   'unsupported_receivers':['Mint: CID60 dispatch is 0x580b30 Object::toString in this snapshot, not Smi::toString. Its observable text is deliberately not guessed from the label; large integer content is unresolved and rejected.','Custom receiver classes and DateTime as dynamic content are not reconstructed.','Cyclic lists/maps and their Dart recursion/truncation behavior are not reconstructed.'],
   'examples':[{'input':'null','output':'actual null'},{'input':'String 文本','output':'文本'},{'input':'List [String a, bool true, null, int2]','output':'[a, true, null, 2]'},{'input':'Map x -> [1,2]','output':'{x: [1, 2]}'}]},
  {'id':'Double.display_reference','status':'bounded_local_reference_differential_validation','original_target':'CID61 ->0x580114','reference_file':'tools/blutter/dartsdk/v3.5.2/runtime/vm/double_conversion.cc','reference_function':'dart::DoubleToCString','parameters':{'mode':'ToShortest','decimal_low':-6,'decimal_high':21,'exponent_char':'e','infinity':'Infinity','nan':'NaN','flags':['EMIT_POSITIVE_EXPONENT_SIGN','EMIT_TRAILING_DECIMAL_POINT','EMIT_TRAILING_ZERO_AFTER_POINT']},
   'observed_test_result':{'model_assertions':38,'double_cases':20100,'differences':0,'record':'reconstruction/evidence/round2/models/verification.json'},
   'sampling':'20,000 deterministic random uint64 bit patterns with seed352, plus100 curated IEEE754/boundary/adjacent bit cases, including signed zero, infinities, NaN, subnormal/minimum normal/maximum finite and exponent thresholds.',
   'limits':['This runs local C++ double-conversion code from matching Dart 3.5.2 source and the Java reconstruction. It does not execute the original APK or its native Double formatter.','20,100 cases are sampled differential evidence, not exhaustive proof for every double bit pattern.','toDouble numeric conversion and toString formatting are separate operations; this oracle checks formatting only.']},
  {'id':'Devices.create_time.remaining','status':'explicitly_unrecovered','original_calls':['0x490328 -> DateTime.parse 0x491264','0x459f80 -> DateTime.toIso8601String 0x45a9dc'],'implementation':'Requires/retains source String and exposes an unresolved item; Devices.Record.toJson refuses to claim completed serialization.','limits':['Parsing overflow, timezone/local offset, date range, fractional seconds and ISO formatting are not ported.','Rejecting malformed dates at the original parse point is not reproduced merely by retaining String.','Version improvement does not complete Devices.fromJson or Devices.toJson.']}
 ]
 source_files=[ELF,AUDIT/'method_coverage.json',ANALYSIS/'snapshot_model_targets.cpp',ANALYSIS/'snapshot_targets.tsv',ANALYSIS/'snapshot_tool_build_commands.json',ANALYSIS/'verify_model_conversions.py',ANALYSIS/'double_oracle.cpp',ROOT/'tools/blutter/dartsdk/v3.5.2/runtime/vm/double_conversion.cc',ROOT/'tools/blutter/dartsdk/v3.5.2/runtime/lib/double.cc',ROOT/'reconstruction/app/src/main/java/com/re/xcs/rebuild/core/Models.java',ROOT/'reconstruction/app/src/main/java/com/re/xcs/rebuild/core/DartConversions.java',OUT/'ModelConversionTest.java',OUT/'run_tests.sh']
 contract={'scope':'Round2 bounded model conversion contract; never complete original source recovery','claims':claims,'machine_code_review':{'status':'PASS' if not failures else 'FAIL','whole_business_method_bodies_checked':len(proofs),'selected_framework_slices_checked':len(slices),'instruction_words_checked':words,'failures':failures},'method_proofs':proofs,'framework_slices':slices,'pool_references':pp_refs,'metadata_reading':{'tool':'analysis/reconstruction_round2/models/snapshot_model_targets.cpp','reads':'Original libapp.so snapshot ObjectPool UnlinkedCall target_name and GDT ArrayOrigin()[0x6d49+cid]','target_Dart_method_invoked':False,'caution':'GDT canonical function names may label shared code. CID-specific targets are proven, while behavior requires body evidence/reference limits.'},'source_manifest':[{'path':relative(p),'sha256':sha(p.read_bytes())} for p in source_files],'coverage':{'new_bounded_association_addresses':['0x52a2a4'],'whole_methods_claimed_complete':0,'frozen_audit_modified':False},'original_source_recovered':False,'original_apk_executed_by_this_audit':False,'business_server_contacted':False}
 (OUT/'contracts.json').write_text(json.dumps(contract,ensure_ascii=False,indent=2)+'\n')
 print(json.dumps(contract['machine_code_review']))
 if failures:raise SystemExit(1)
if __name__=='__main__':main()
