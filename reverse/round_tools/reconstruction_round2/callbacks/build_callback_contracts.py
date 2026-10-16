#!/usr/bin/env python3
"""Recheck original machine bytes and materialize bounded callback claims.
Read-only original APK/ELF/snapshot inputs; no target Dart or server execution.
"""

from pathlib import Path as _PublicPath
import sys as _public_sys
_public_sys.path.insert(0, str(_PublicPath(__file__).resolve().parents[3] / "scripts"))
from _paths import app_root as _public_app_root, java_home as _public_java_home
from pathlib import Path
import json, hashlib, re, shutil, io
from elftools.elf.elffile import ELFFile
from capstone import Cs, CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN
ROOT=_public_app_root()
OUT=Path(__file__).resolve().parent
DEST=ROOT/'reconstruction/evidence/round2/callbacks'
AUDIT=ROOT/'analysis/completeness_audit/flutter'
ELF=ROOT/'unpacked/lib/arm64-v8a/libapp.so'
def sha(b):return hashlib.sha256(b).hexdigest()
def write(path,obj):path.write_text(json.dumps(obj,ensure_ascii=False,indent=2)+'\n')
claims=[
 {'id':'preview_state_ownership_and_async_values','business_methods':'457b58 457dc4 4580b4 45911c 459704 460ab4 460b60 461014 4ac0b8 51d844'.split(),
  'scope':'Previously established preview contract made executable; rereading is not new method completion.',
  'slots':{'PreviewService.field_b':'nullable Devices.id; default0; request/route ID','MainService.field_f':'unboxed int WS102 filter; default-1','MainService.field_b':'singleton RxString, initial empty'},
  'events':['startPreview writes service ID before HTTP GET. Its response callback reads captured Devices.id at callback time, null=>0, and sets filter regardless ok/business success.',
            'A rejected or still-pending Future never runs the onValue callback; do not synthesize its effect.',
            'savePreviewParams and endPreview clear service ID before POST. Failure does not roll it back.',
            'Save callback checks ok then strict bool success then captured close bool. Accepted close calls endPreview(captured Devices current id), attaches null callback, then Navigator.pop(true) without awaiting end.',
            'Route completion ignores pop result. If current service ID !=0, including null, issues endPreview(current ID); zero skips.',
            'FramePreview.initState clears RxString only; no startPreview/filter-reset call occurs in that method.',
            'end does not clear filter/frame. Reentry retains old filter until a normal start response overwrites it. Completion order wins; no epoch/generation check.',
            'Late save-close callback issues end before consulting State.element; if disposed, the later navigation can throw after end was dispatched.'],
  'limits':['No server acceptance inferred from HTTP completion. Android route guards intentionally differ and must be documented by its owner.']},
 {'id':'ws102_rx_string_receiver','business_methods':['527460','459704','51d844'],'framework_methods':['4597b0','459810','51d884','2db568','55e340','674170','673f8c'],
  'events':['WS102 content dynamic toString; optional prefix int.parse split[0] compared to MainService.field_f, takes split[1], ignores later parts; unprefixed text bypasses filter.',
            'decodeData runs before value=; parse/decode failure preserves previous frame. Rendering/base64 failure occurs outside this setter and cannot roll back its stored value.',
            'MainService._getInstance allocates StringExtension.obs => RxString<String>, initial empty and field_17=true.',
            'At 0x51d8e4..0x51d908 setter returns when GetStream.field_1b is null (close writes null at0x55e36c).',
            'At0x51d90c..0x51d968 current String == incoming String and first flag false returns without store or add. Initial flag true permits equal empty first event.',
            'Accepted update first sets flag=false, then stores _value, then GetStream.add. Original snapshot resolves direct GDT[cid] for CID93 to _OneByteString::==0x674170 and CID94 to _TwoByteString::==0x673f8c.',
            'No preview-page, serviceID, connection/auth, mounted or epoch test appears in WS102 receive branch. Duplicate suppression is Rx value equality, not a protocol-level duplicate check.'],
  'limits':['Framework observer scheduling/listener exceptions and repaint details are not reproduced by the synchronous Java Listener callback. Stream-close helper exposes framework semantics; route exit does not invoke it.']},
 {'id':'shared_end_completion','business_methods':['460b60','527460'],'framework_methods':['6f2a58'],
  'events':['PP0x1be10 and PP0x14ca0 refer to the same pooled code address0x6f2a58. Original 8-byte body e00316aac0035fd6 is mov x0,x22; ret; ignores response and returns null.',
            'The historical pretty-printer name Shader::Shader._ reflects shared code canonicalization, not a shader operation. sharedNullCompletion is an exact known no-op, not an unfinished implementation.'],
  'limits':['Future exception propagation is framework-owned; this onValue closure is not a catchError/retry/cleanup callback.']},
 {'id':'main_view_modes_and_palette','business_methods':'565264 4aa6b8 4aa71c 4a36c0 4a36f8 4a375c 4a37a0 4a37d8 4a383c 4a1f4c 4a1fac 4a1fd0 4a2030 4a566c 4a56d4 4a6b94 4a6c04 4a3390 4a33cc 4a344c'.split(),
  'slots':{'MainState.field_27':'pageMode, initial1','MainState.field_47':'displayType, initial2','MainState.field_4f':'paletteVisible initialfalse','MainState.field_2f':'selected ChannelResult initiallynull'},
  'events':['onOpenChangePage sets pageMode2. onCloseChangePage is pageMode==1?0:1; mode0 must not be erased by an assumed constant return-to-main.',
            'onViewShowType is displayType==2?1:2; does not clear palette or selected object.',
            'Palette open/close set only field4f. Result click captures actual ChannelResult into selected field2f and opens palette.',
            'Cancel/dialog closure clears selected before Navigator.pop, with no palette field write.',
            'Outer onSelectMj0x4a33cc checks selected null and returns. Inner0x4a344c requires nonnull, stores config.id.toString and config.url; hides palette only when displayType2, retaining selected object.'],
  'limits':['Analyst field aliases are not recovered original variable names. Java state methods do not replicate Flutter layout/widgets or setState after disposal.']},
 {'id':'recognition_and_upload_view_effects','business_methods':['527460','529164','529c50','4aa6b8','4aa71c','4a32b0'],
  'events':['WS113 at0x527db0..0x527db8 replaces each channel results with a new empty list; late saveImg completion iterates current channels/results and may append into the new round.',
            'Recognized-count equality cancels timer, sets countdown0/status, then onOpenChangePage before onValidDataAndSendData at0x529814/0x529824.',
            'Upload accepted callback executes for each live channel: pageMode1, replaces that channel results with a fresh empty list, hides visible palette only for displayType2.',
            'Zero channels means no loop iteration, hence no pageMode/palette change. SelectedResult and removedOffset are not cleared by this callback.'],
  'limits':['Java now replaces List references for WS113 and upload callbacks; renderer/widget subscriptions and other outstanding list aliases are not reconstructed. Validation/server correctness remain separate.']},
 {'id':'http401_numeric_equality','business_methods':['67f850'],'framework_methods':['6747cc','674930'],
  'events':['ResponseInterceptors requires status401 AND dynamic data.code==401. Snapshot GDT equality resolves _Double::==0x6747cc and _IntegerImplementation::==0x674930; numeric401.0 satisfies numeric equality while String401 does not.',
            'Matching branch clears Dart JWT and navigates offAll(LoginPage), without handler.next in that branch. It does not directly clear preview IDs/frame or native authentication.'],
  'limits':['SessionState.onHttpError implements numeric predicate/JWT mutation only; it does not model the original possibly pending completer or full navigation/native token lifetime.']},
]

def main():
 OUT.mkdir(parents=True,exist_ok=True);DEST.mkdir(parents=True,exist_ok=True);(OUT/'methods').mkdir(exist_ok=True)
 data=ELF.read_bytes();elf=ELFFile(io.BytesIO(data));loads=[s for s in elf.iter_segments() if s['p_type']=='PT_LOAD']
 def offset(addr):
  for s in loads:
   if s['p_vaddr']<=addr<s['p_vaddr']+s['p_filesz']:return s['p_offset']+addr-s['p_vaddr']
  raise ValueError(hex(addr))
 ledger=json.loads((AUDIT/'method_coverage.json').read_text());methods={m['address'][2:]:m for m in ledger['methods']}
 selected=sorted({a for c in claims for a in c['business_methods']});proofs=[];failures=[];words=0
 for a in selected:
  m=methods[a];asm_path=ROOT/m['complete_excerpt'];raw_path=ROOT/m['raw_disassembly'];asm=asm_path.read_bytes();raw=raw_path.read_bytes();off=m['elf_file_offset'];size=m['exported_body_size'];machine=data[off:off+size]
  raw_ins=re.findall(rb'^0x([0-9a-f]+): ([0-9a-f]{8})\s',raw,re.M)
  checks={'asm_matches_frozen':sha(asm)==m['complete_excerpt_sha256'],'raw_matches_frozen':sha(raw)==m['raw_disassembly_sha256'],'body_matches_frozen':sha(machine)==m['exported_body_sha256'],'raw_full_body':len(raw_ins)*4==size,'raw_words_match_elf':all(data[off+int(v,16)-int(a,16):off+int(v,16)-int(a,16)+4]==bytes.fromhex(b.decode()) for v,b in raw_ins)}
  if not all(checks.values()):failures.append({'address':a,'checks':checks})
  words+=len(raw_ins);shutil.copyfile(asm_path,OUT/'methods'/(a+'.asm.txt'));shutil.copyfile(raw_path,OUT/'methods'/(a+'.raw.txt'))
  proofs.append({'address':'0x'+a,'source':m['source'],'signature':m['signature'],'elf_offset':off,'size':size,'body_sha256':sha(machine),'prior_semantic_coverage':m['semantic_coverage'],'whole_method_completed':False,'checks':checks})
 framework=sorted({a for c in claims for a in c.get('framework_methods',[])})
 rx=ROOT/'analysis/aot_dump/asm/get/get_rx/src/rx_types/rx_types.dart';stream=ROOT/'analysis/aot_dump/asm/get/get_rx/src/rx_stream/rx_stream.dart'
 sources=[rx,stream];meta={}
 for l in (OUT/'snapshot_targets.tsv').read_text().splitlines():
  p=l.split('\t')
  if p[0]=='FUNCTION':meta[p[1][2:]]={'size':int(p[2]),'signature':p[3],'source':'Original snapshot metadata'}
 dis=Cs(CS_ARCH_ARM64,CS_MODE_LITTLE_ENDIAN);framework_proofs=[]
 for a in framework:
  item=meta.get(a)
  for source in sources:
   text=source.read_text();match=re.search(r'^    // \*\* addr: 0x'+a+r', size: 0x([0-9a-f]+)$',text,re.M)
   if match:
    begin=text.rfind('\n  ',0,match.start())+1;end=text.index('\n  }',match.end())+4;body=text[begin:end]+'\n';(OUT/'methods'/(a+'.asm.txt')).write_text(body)
    item={'size':int(match.group(1),16),'source':str(source.relative_to(ROOT)),'signature':body.splitlines()[0].strip(),'asm_sha256':sha(body.encode())};break
  if not item:raise ValueError('No method boundary '+a)
  off=offset(int(a,16));machine=data[off:off+item['size']];instructions=list(dis.disasm(machine,int(a,16)));raw='\n'.join(f'0x{i.address:x}: {i.bytes.hex()} {i.mnemonic} {i.op_str}' for i in instructions)+'\n';(OUT/'methods'/(a+'.raw.txt')).write_text(raw)
  check=sum(i.size for i in instructions)==item['size'];words+=len(instructions)
  if not check:failures.append({'address':a,'error':'incomplete raw disassembly'})
  framework_proofs.append({'address':'0x'+a,**item,'elf_offset':off,'body_sha256':sha(machine),'raw_instruction_count':len(instructions),'disassembly_covers_body':check})
  if a=='6f2a58' and machine.hex()!='e00316aac0035fd6':failures.append({'address':a,'error':'expected shared null body mismatch'})
 refs=[]
 for a in selected:
  for line in (OUT/'methods'/(a+'.asm.txt')).read_text().splitlines():
   if 'AnonymousClosure:' in line or 'Function: [dart:ui] Shader' in line:refs.append({'owner':'0x'+a,'reference':line.strip()})
 unknown=['No original source text/project files recovered; this is bounded functional reconstruction.',
          'No original Dart entrypoint or business server executed by this callback audit. Tests execute reconstructed Java only.',
          'Android mounted/generation protection suppresses some late UI effects that the original lacks. Core onValue methods deliberately have no route/epoch guard; engine.close blocks message receive and late image completion as a stated reconstruction lifecycle policy.',
          'Original GetStream listener ordering/scheduling and Flutter painting/navigation are not recreated; Rx value store/equality behavior is represented.',
          'HTTP special401 pending completer and native reconnect/authentication remain outside these Java callback methods.',
          'Dynamic content conversion delegates DartConversions supported receiver types; unsupported receiver/conversion cases throw, not synthesize success.']
 manifest=[]
 for path in [ELF,AUDIT/'method_coverage.json',rx,stream,OUT/'snapshot_callback_targets.cpp',OUT/'snapshot_tool_build_commands.json',OUT/'snapshot_targets.tsv']:
  manifest.append({'path':str(path.relative_to(ROOT)),'sha256':sha(path.read_bytes())})
 code=[]
 for f in ['SessionState.java','MessageEngine.java','ResultRules.java']:
  p=ROOT/'reconstruction/app/src/main/java/com/re/xcs/rebuild/core'/f;code.append({'path':str(p.relative_to(ROOT)),'sha256':sha(p.read_bytes())})
 finding={'scope':'Bounded callback/state reconstruction, never complete original source','claims':claims,'method_proofs':proofs,'framework_method_proofs':framework_proofs,'closure_references':refs,'dynamic_receiver_metadata':'snapshot_targets.tsv','source_manifest':manifest,'reconstructed_sources':code,'limitations':unknown}
 write(OUT/'callback_contracts.json',finding)
 new=[p['address'] for p in proofs if p['prior_semantic_coverage']=='no_explicit_semantic_association_found']
 summary={'status':'PASS' if not failures else 'FAIL','business_method_evidence_count':len(proofs),'framework_method_evidence_count':len(framework_proofs),'new_bounded_business_associations':len(new),'new_association_addresses':new,'verified_instruction_words':words,'failures':failures,'whole_methods_claimed_complete':0,'original_source_recovered':False,'frozen_audit_modified':False,'target_dart_invoked':False,'business_server_contacted':False}
 write(OUT/'verification.json',summary)
 for name in ['callback_contracts.json','verification.json','snapshot_targets.tsv']:shutil.copyfile(OUT/name,DEST/name)
 print(json.dumps(summary,ensure_ascii=False))
if __name__=='__main__':main()
