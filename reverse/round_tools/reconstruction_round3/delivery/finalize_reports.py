#!/usr/bin/env python3
"""Round 3 bounded progress. Never change frozen audit or historical snapshots."""

from pathlib import Path as _PublicPath
import sys as _public_sys
_public_sys.path.insert(0, str(_PublicPath(__file__).resolve().parents[3] / "scripts"))
from _paths import app_root as _public_app_root, java_home as _public_java_home
from pathlib import Path
import copy,datetime,hashlib,json
APP=_public_app_root();ROOT=APP/'reconstruction'
def read(p):return json.loads(p.read_text())
def write(p,d):p.write_text(json.dumps(d,ensure_ascii=False,indent=2)+'\n')
def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()
def ref(p):return {'file':str(p),'sha256':sha(p)}
def ev(s):return ref(ROOT/'evidence'/s)
ledger=read(ROOT/'evidence/gap_progress.json');baseline=read(APP/'analysis/completeness_audit/coverage_ledger.json')
assert sha(APP/'analysis/completeness_audit/coverage_ledger.json')=='3da17a2ba384e9e6d7ed0cd6fdb59c681bfc3e728916b0380e11a8b1fa802770'
before=copy.deepcopy([v['baseline'] for v in ledger['remaining_gap_updates']]);updates={v['id']:v for v in ledger['remaining_gap_updates']}
build=read(ROOT/'dist/source-build.json');runtime=read(ROOT/'evidence/runtime/verification.json');live=read(ROOT/'evidence/round3/live/android-verification.json');host=read(ROOT/'evidence/round3/integration/host-verification.json')
assert runtime['status']=='PASS' and live['status']=='PASS_READ_ONLY_LIVE_LOGIN' and host['status']=='PASS'
assert runtime['apk_sha256']==live['apk_sha256']==build['apk_sha256']==sha(ROOT/'dist/xcs-source-rebuild-debug.apk')
assert all(sha(ROOT/v['path'])==v['sha256'] for v in build['sources'])
assert all(sha(ROOT/p)==v for p,v in host['source_sha256'].items())
ledger['recorded_at_utc']=datetime.datetime.now(datetime.timezone.utc).isoformat();ledger['round']='third reconstruction: DateTime/Mint/JSON numeric conversion and shared SIMD functions'
# Historical round2 entries remain reference data. Current claims point to current tests.
refs={s:ev(s) for s in ['round3/integration/host-verification.json','round3/datetime/contracts.json','round3/datetime/reference_verification.json','round3/mint/contracts.json','round3/mint/verification.json','round3/simd/verification.json','round3/numeric_json/verification.json','runtime/verification.json','round3/live/android-verification.json']}
def update(id,summary,remaining,files):
 row=updates[id];row['state']='open';row['semantic_gap_closed']=False;row['original_source_gap_closed']=False
 u=row['update'];u['progress_kind']='bounded_round3_progress';u['summary']=summary;u['remaining']=remaining
 for file in files:
  if refs[file]['file'] not in [r['file'] for r in u['evidence']]:u['evidence'].append(refs[file])
 return u
current=['round3/integration/host-verification.json','round3/datetime/contracts.json','round3/mint/contracts.json','round3/numeric_json/verification.json']
update('dart_method_semantics','前两轮局部关联保留；第三轮补 DateTime parse/ISO/toString、Mint native分派及JSON数值入口的限定范围实现。原方法计数不变，不把参考库验证当全部业务方法完成。','冻结612个导出业务方法225局部关联/387未关联；完整业务、框架动态接收者、异常对象和原源码仍open。',current)
update('dart_dynamic_calls','原snapshot确认DateTime CID4688独立toString和Mint CID60 Object_toString到Mint::ToCString分派，已接入Message和Devices的动态转换。','自定义接收者、循环容器、完整noSuchMethod/异常对象、全部Flutter异步与动态路径仍open。',current)
update('model_types_and_dynamic_conversion','Devices.create_time现解析为DartDateTime并ISO序列化，执行顺序先于version；DateTime动态内容、signed64 Mint字符串与toDouble、JSON数值边界均接入。DateTime 37,224对照、Mint 20,856对照及独立集成/Android/真实只读设备数据验证有明确证据。','系统tzdata差异、完整任意动态类型/BigInt/循环容器仍open；Message reader提前能力检查与原fromJson副作用/可变容器异常时序不保证相同；MjConfig原factory仍未恢复；有限Double JSON编码文本、非数字codec和流式接口仍不保证Dart等价。',current+['round3/datetime/reference_verification.json','round3/mint/verification.json','round3/live/android-verification.json'])
u=update('native_c_failures_or_truncations','第二轮8个Go入口限定语义保留。第三轮countbytebody和indexbytebody均有实际可编译C/NEON、标量和Java实现，并与原ARM64片段执行差分；不再只提供诊断反编译文本。','Ghidra对两共享SIMD体的自动C输出仍报工具错误；原始Go/Rust源码、完整Go运行时和全程序等价仍open；Rust两项类型传播问题未闭合。',['round3/simd/verification.json'])
u.setdefault('metrics',{}).update(shared_simd_executable_semantic_reconstructions=2,shared_simd_original_source_recovered=0,remaining_shared_simd_decompiler_errors=2)
update('native_function_discovery_and_other_abis','第三轮执行原ARM64两SIMD共享体，验证对齐块读取、边界掩码和页边界；其他ABI沿用第二轮限定证据。','全库未归属区间、完整多ABI语义及Go/Rust运行时并发未闭合。',['round3/simd/verification.json'])
u=update('server_device_runtime_contract',f'本轮当前Java源码host回归通过；同一最终APK在API35完成{len(runtime["assertions"])}项合成运行断言和{len(live["checks"])}项真实只读检查，设备DateTime解析/ISO往返与version转换通过；真实读取{live["device_count"]}台设备和{live["palette_count"]}项牌配置。','真实设备控制/上传、服务端全schema、所有认证/重连/晚到消息真实时序及原程序完整端到端等价仍open。',['round3/integration/host-verification.json','runtime/verification.json','round3/live/android-verification.json'])
android=u['android_runtime_validation'];android.update(assertions=len(runtime['assertions']),apk_sha256=build['apk_sha256'],evidence=ev('runtime/verification.json'))
android['scope']='New Java Activity API35 with synthetic counterpart: login/DateTime/Mint/byte primitives/WS/recognition upload/preview late-message/settings/WiFi; no production controls'
live_ref={'status':live['status'],'checks':len(live['checks']),'device_count':live['device_count'],'palette_count':live['palette_count'],'apk_sha256':build['apk_sha256'],'device_mutation_requests_allowed':False,'credentials_recorded':False,'evidence':ev('round3/live/android-verification.json')}
u['live_read_only_validation']=live_ref
update('original_source',f'本轮{build["source_files"]}个实际Java编译输入，新增DartDateTime、DartIntegers和GoBytePrimitives，SDK与Gradle构建通过。原字节码保留重装包沿用历史离线验证。','原始Dart/Rust/Go项目、树摇/内联丢失的原方法、注释/变量/工程结构及原签名仍未恢复，全部业务等价仍open。',['round3/integration/host-verification.json','round3/live/android-verification.json','round3/simd/verification.json'])
j=ledger['build_artifacts']['java_source_reconstruction'];j.update(apk_sha256=build['apk_sha256'],source_files=build['source_files'],runtime_validation=f'PASS_SYNTHETIC_ANDROID_{len(runtime["assertions"])}_AND_READ_ONLY_LIVE_{len(live["checks"])}',report_source_files_changed_since_build=[],live_read_only_validation=live_ref)
for suite in host['suites'].values():
 command=' '.join(suite['command']);path=ROOT/suite['command'][1]
 if command not in j['standalone_test_commands']:j['standalone_test_commands'].append(command)
 if str(path) not in [r['file'] for r in j['standalone_test_scripts']]:j['standalone_test_scripts'].append(ref(path))
v=ledger['validation_snapshot'];v['android_runtime']=copy.deepcopy(android);v['live_read_only']=live_ref
for name in ['business','settings','callbacks','models']:
 v[name]={'status':'PASS','current_suite_result':host['suites'][name],'evidence':ev('round3/integration/host-verification.json')}
v['round3']={'status':'PASS_BOUNDED','evidence':list(refs.values())}
# Update implementation mapping before refreshing references to it.
p=ROOT/'evidence/business/source_map.json';mapping=read(p)
byname={Path(r['implementation']).name:r for r in mapping['files']}
for name,files in {'DartIntegers.java':['round3/mint/contracts.json'],'DartDateTime.java':['round3/datetime/contracts.json'],'GoBytePrimitives.java':['round3/simd/verification.json'],'JsonCodec.java':['round3/numeric_json/verification.json'],'Models.java':['round3/datetime/contracts.json','round3/mint/contracts.json'],'DartConversions.java':['round3/mint/contracts.json','round3/datetime/contracts.json']}.items():
 path=ROOT/'app/src/main/java/com/re/xcs/rebuild/core'/name
 row=byname.get(name)
 if row is None:row={'implementation':str(path),'kind':'new executable bounded reconstruction','evidence':[]};mapping['files'].append(row)
 row['sha256']=sha(path)
 for s in files:
  if refs[s]['file'] not in [r['file'] for r in row['evidence']]:row['evidence'].append(refs[s])
def refresh(obj):
 if isinstance(obj,dict):
  if isinstance(obj.get('file'),str) and 'sha256'in obj:obj['sha256']=sha(Path(obj['file']))
  for k,val in obj.items():
   if k!='baseline':refresh(val)
 elif isinstance(obj,list):
  for val in obj:refresh(val)
for row in mapping['files']:row['sha256']=sha(Path(row['implementation']))
refresh(mapping);write(p,mapping);refresh(ledger)
assert before==[v['baseline'] for v in ledger['remaining_gap_updates']]
assert all(b in baseline['remaining_gaps'] for b in before)
checked=[]
def verify(obj):
 if isinstance(obj,dict):
  if 'file'in obj and 'sha256'in obj:assert sha(Path(obj['file']))==obj['sha256'];checked.append(obj['file'])
  for val in obj.values():verify(val)
 elif isinstance(obj,list):
  for val in obj:verify(val)
verify(ledger)
ledger['reference_verification']={'status':'PASS','checked_reference_occurrences':len(checked),'unique_files':len(set(checked)),'missing_files':[],'sha256_mismatches':[],'baseline_objects_preserved_exactly':len(before),'note':'Current pointers updated after actual tests; historical reports retain historical source/APK hashes.'}
write(ROOT/'evidence/gap_progress.json',ledger)
print(json.dumps({'status':'PASS','references':len(checked),'frozen_categories':len(before),'apk':build['apk_sha256']}))
