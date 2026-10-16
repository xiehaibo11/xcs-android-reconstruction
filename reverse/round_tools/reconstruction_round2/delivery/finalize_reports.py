#!/usr/bin/env python3
"""Refresh the mutable delivery ledger; never rewrite the frozen audit."""

from pathlib import Path as _PublicPath
import sys as _public_sys
_public_sys.path.insert(0, str(_PublicPath(__file__).resolve().parents[3] / "scripts"))
from _paths import app_root as _public_app_root, java_home as _public_java_home
from pathlib import Path
import copy, datetime, hashlib, json

APP=_public_app_root()
ROOT=APP/'reconstruction'
def read(p):return json.loads(p.read_text())
def write(p,x):p.write_text(json.dumps(x,ensure_ascii=False,indent=2)+'\n')
def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()
def ref(p):return {'file':str(p),'sha256':sha(p)}
def evidence(rel):return ref(ROOT/'evidence'/rel)

ledger=read(ROOT/'evidence/gap_progress.json')
baseline=read(APP/'analysis/completeness_audit/coverage_ledger.json')
original_baselines=[copy.deepcopy(x['baseline']) for x in ledger['remaining_gap_updates']]
updates={x['id']:x for x in ledger['remaining_gap_updates']}
build=read(ROOT/'dist/source-build.json')
runtime=read(ROOT/'evidence/runtime/verification.json')
live=read(ROOT/'evidence/round2/live/android-verification.json')
native=read(ROOT/'evidence/round2/native/go_gap_resolution.json')
models=read(ROOT/'evidence/round2/models/contracts.json')
assert runtime['status']=='PASS' and live['status']=='PASS_READ_ONLY_LIVE_LOGIN'
assert runtime['apk_sha256']==live['apk_sha256']==build['apk_sha256']
assert all(sha(ROOT/x['path'])==x['sha256'] for x in build['sources'])
ledger['recorded_at_utc']=datetime.datetime.now(datetime.timezone.utc).isoformat()
ledger['round']='second reconstruction integration and bounded real-login verification'

def supplement(id,summary,refs,remaining=None):
 u=updates[id]['update'];u['progress_kind']='bounded_round2_progress';u['summary']=summary
 u['evidence'] += [evidence(p) for p in refs if str(ROOT/'evidence'/p) not in [v['file'] for v in u['evidence']]]
 if remaining:u['remaining']=remaining
 return u

supplement('dart_method_semantics','上一轮33个局部方法关联保留。本轮新增14个回调及1个模型序列化有界关联；复核35业务/10框架回调证据体2895条指令，模型1811条指令。124回调与38模型断言通过并接入重建工程；均不计整方法完成，冻结612/225/387计数不改。',['round2/callbacks/callback_contracts.json','round2/callbacks/verification.json','round2/callbacks/test_results.json','round2/models/contracts.json','round2/models/verification.json'])
supplement('dart_dynamic_calls','已明确预览开始/保存/结束/路由返回、共享空回调、结果编辑/上传和新List替换；RxString相等比较和Models两个selector有原snapshot证据。Android页面已接入并覆盖失败、晚到消息和重入。',['round2/callbacks/callback_contracts.json','round2/models/contracts.json','runtime/verification.json'])
u=supplement('native_c_failures_or_truncations','原Go/RSA清单8项为3个字节算法wrapper及5个runtime入口，限定范围语义均确定。22854个原机器码字节算法用例、16个runtime边界、103个区间和223个证据文件核验通过；3个wrapper可生成诊断C，2个共享SIMD体仍有反编译器错误。Rust两项类型警告仍在；未恢复任何原Go/Rust源码。',['round2/native/go_gap_resolution.json','round2/native/emulation_verification.json','round2/native/evidence_verification.json','round2/native/evidence_manifest.json'],'8个Go入口的限定范围语义已建立，完整运行时/调度/信号/并发及原源码仍open；两个共享SIMD体C错误和两个Rust语义未闭合。')
u['metrics']={'baseline_items':10,'rust_new_c_outputs':2,'rust_type_warning_outputs':2,'go_rsa_bounded_semantics_established':8,'go_rsa_original_source_open':8,'remaining_shared_simd_decompiler_errors':2,'runtime_truncation_causes_identified':5,'original_source_gaps_closed':0,'full_program_equivalence_established':False}
for item in updates['native_c_failures_or_truncations']['item_updates']:
 if item['baseline']['library']!='rsa':continue
 row=next(r for r in native['rows'] if r['elf_entry']==item['baseline']['elf_address'])
 item.update(state='bounded_semantics_established_source_open',bounded_semantics_established=True,semantic_gap_closed=False,original_source_gap_closed=False,
             current_tool_output_status='wrapper_diagnostic_c_available' if row['name'].startswith('internal/bytealg.') else 'intentional_runtime_boundary_identified',
             new_c_output_available=row['name'].startswith('internal/bytealg.'),control_flow_truncation=False,
             output_evidence=evidence('round2/native/go_gap_resolution.json'),function_name=row['name'],scope='Isolated original fragments with explicit external-call models, not full Go execution')
supplement('native_jumptable_semantics','本轮 systemstack 的间接分支确定为Go函数值尾调用，5个runtime旧截断解释为有意非法指令/零地址终点。其他原生跳转表和完整调用图未因此闭合。',['round2/native/go_gap_resolution.json'])
supplement('native_function_discovery_and_other_abis','本轮8项目标及支持函数103个原始区间与4 ABI ELF/pclntab核对；ARM64/ARM32字节算法执行覆盖、ARM64 runtime隔离边界验证。全库未归属区域/其他函数/完整多ABI语义仍open。',['round2/native/evidence_verification.json'])
supplement('model_types_and_dynamic_conversion','Devices.version动态toDouble和Message.msg_content非空toString/null分支确认并实现。普通String/bool/Smi/Double/List/Map有界支持，38断言及20100个匹配Dart3.5.2参考浮点样本通过。新增1个有界方法关联，不计完整方法。',['round2/models/contracts.json','round2/models/verification.json'],'DateTime完整解析/ISO序列化、Mint内容格式、自定义动态接收类型、循环容器及其他未观察模型边界仍open。')
u=supplement('server_device_runtime_contract','64业务、102设置、124回调、38模型断言通过；14本机TCP场景通过。API35实际Activity通过22合成场景，包括失败end/晚到WS102/重新进入。相同APK通过6项真实只读Android检查：登录、JWT/RSA服务配置解密、设备version、牌配置、在线配置/设备状态、WS认证；读取4台设备和50项牌配置。未操作生产设备或上传结果，原程序完整端到端等价未证明。',['round2/live/android-verification.json','round2/callbacks/test_results.json','round2/models/verification.json'],'真实设备控制/上传、完整服务端schema及所有认证拒绝/重连/晚到WS102真实时序和原程序端到端等价仍open。')
android=u['android_runtime_validation'];android.update(assertions=len(runtime['assertions']),apk_sha256=build['apk_sha256'])
android['scope']='New Java Activity, API35, synthetic HTTP/RSA/WS/image/upload/failed-end/late-WS102/reentry/settings/WiFi; no production device acceptance'
u['live_read_only_validation']={'status':live['status'],'checks':len(live['checks']),'device_count':live['device_count'],'palette_count':live['palette_count'],'apk_sha256':build['apk_sha256'],'device_mutation_requests_allowed':False,'credentials_recorded':False,'evidence':evidence('round2/live/android-verification.json')}
supplement('original_source','新写17个Java编译输入（15主源码+2instrumentation）已通过SDK与Gradle编译，24项合成Android检查及6项真实只读登录检查。原Smali/资源重装包沿用原离线启动与往返证据。本轮8项Go限定语义、15个新增Dart局部关联不等于原始Dart/Rust/Go全源码恢复。',['round2/live/android-verification.json','round2/models/contracts.json','round2/native/go_gap_resolution.json'])
j=ledger['build_artifacts']['java_source_reconstruction'];j.update(apk_sha256=build['apk_sha256'],source_files=build['source_files'],runtime_validation='PASS_SYNTHETIC_ANDROID_24_AND_READ_ONLY_LIVE_6',report_source_files_changed_since_build=[])
j['live_read_only_validation']=copy.deepcopy(u['live_read_only_validation'])
for kind in ('callbacks','models'):
 command='sh evidence/round2/'+kind+'/run_tests.sh'
 if command not in j['standalone_test_commands']:j['standalone_test_commands'].append(command)
 path=ROOT/'evidence/round2'/kind/'run_tests.sh'
 if str(path) not in [x['file'] for x in j['standalone_test_scripts']]:j['standalone_test_scripts'].append(ref(path))
v=ledger['validation_snapshot'];v['android_runtime']=copy.deepcopy(android);v['live_read_only']=copy.deepcopy(u['live_read_only_validation'])
v['callbacks']={'status':'PASS','assertions':124,'evidence':evidence('round2/callbacks/test_results.json')}
v['models']={'status':'PASS','assertions':38,'double_reference_cases':20100,'evidence':evidence('round2/models/verification.json')}
v['native_go_eight']={'status':'PASS_BOUNDED','bytealg_cases':22854,'runtime_boundary_cases':16,'evidence':evidence('round2/native/evidence_verification.json')}

checked=[];missing=[]
def refresh(obj):
 if isinstance(obj,dict):
  if isinstance(obj.get('file'),str) and 'sha256' in obj:
   p=Path(obj['file'])
   if p.is_file():obj['sha256']=sha(p);checked.append(str(p))
   else:missing.append(str(p))
  for key,val in obj.items():
   if key!='baseline':refresh(val)
 elif isinstance(obj,list):
  for val in obj:refresh(val)
refresh(ledger)
assert not missing, missing
assert original_baselines==[x['baseline'] for x in ledger['remaining_gap_updates']]
for b in original_baselines:
 assert b in baseline['remaining_gaps']
def verify_frozen_refs(obj):
 if isinstance(obj,dict):
  if 'file' in obj and 'sha256' in obj:assert sha(Path(obj['file']))==obj['sha256'];checked.append(obj['file'])
  for val in obj.values():verify_frozen_refs(val)
 elif isinstance(obj,list):
  for val in obj:verify_frozen_refs(val)
for b in original_baselines:verify_frozen_refs(b)
ledger['reference_verification']={'status':'PASS','checked_reference_occurrences':len(checked),'unique_files':len(set(checked)),'missing_files':[],'sha256_mismatches':[],'baseline_objects_preserved_exactly':len(original_baselines),'note':'Frozen baselines unchanged; mutable current-evidence references refreshed after actual tests.'}

# Keep implementation mapping hashes current and add the new evidence without rewriting history.
p=ROOT/'evidence/business/source_map.json';mapping=read(p)
for row in mapping['files']:
 row['sha256']=sha(Path(row['implementation']))
 name=Path(row['implementation']).name
 additions=[]
 if name in ('MessageEngine.java','SessionState.java','ResultRules.java'):additions=['round2/callbacks/callback_contracts.json']
 if name=='Models.java':additions=['round2/models/contracts.json']
 for rel in additions:
  target=ROOT/'evidence'/rel
  if str(target) not in [x['file'] for x in row['evidence']]:row['evidence'].append(ref(target))
dart=ROOT/'app/src/main/java/com/re/xcs/rebuild/core/DartConversions.java'
if str(dart) not in [x['implementation'] for x in mapping['files']]:mapping['files'].append({'implementation':str(dart),'sha256':sha(dart),'kind':'new bounded executable reconstruction','evidence':[evidence('round2/models/contracts.json'),evidence('round2/models/verification.json')]})
refresh(mapping);write(p,mapping)
checked.clear()
refresh(ledger)
for b in original_baselines:verify_frozen_refs(b)
ledger['reference_verification'].update(checked_reference_occurrences=len(checked),unique_files=len(set(checked)))
write(ROOT/'evidence/gap_progress.json',ledger)
print(json.dumps({'status':'PASS','baseline_categories_unchanged':len(original_baselines),'reference_files':len(set(checked)),'compiled_java_files':build['source_files'],'apk_sha256':build['apk_sha256']},ensure_ascii=False))
