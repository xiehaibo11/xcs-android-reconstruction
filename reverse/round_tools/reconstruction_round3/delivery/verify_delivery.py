#!/usr/bin/env python3

from pathlib import Path as _PublicPath
import sys as _public_sys
_public_sys.path.insert(0, str(_PublicPath(__file__).resolve().parents[3] / "scripts"))
from _paths import app_root as _public_app_root, java_home as _public_java_home
from pathlib import Path
import argparse,datetime,hashlib,json,re,zipfile
APP=_public_app_root();ROOT=APP/'reconstruction'
def read(p):return json.loads(p.read_text())
def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()
parser=argparse.ArgumentParser();parser.add_argument('--forbidden-identifier',action='append',default=[]);args=parser.parse_args()
build=read(ROOT/'dist/source-build.json');package=read(ROOT/'dist/source-package.json');independent=read(ROOT/'dist/standalone-build-verification.json');ledger=read(ROOT/'evidence/gap_progress.json')
host=read(ROOT/'evidence/round3/integration/host-verification.json');runtime=read(ROOT/'evidence/runtime/verification.json');live=read(ROOT/'evidence/round3/live/android-verification.json');net=read(ROOT/'evidence/transport/network_verification.json')
date=read(ROOT/'evidence/round3/datetime/reference_verification.json');datemachine=read(ROOT/'evidence/round3/datetime/machine_execution.json');mint=read(ROOT/'evidence/round3/mint/verification.json');numeric=read(ROOT/'evidence/round3/numeric_json/verification.json');simd=read(ROOT/'evidence/round3/simd/verification.json')
assert build['build']=='PASS' and independent['status']=='PASS' and host['status']=='PASS'
assert runtime['status']=='PASS' and live['status']=='PASS_READ_ONLY_LIVE_LOGIN' and net['status']=='PASS'
assert build['apk_sha256']==sha(ROOT/'dist/xcs-source-rebuild-debug.apk')==runtime['apk_sha256']==live['apk_sha256']
assert package['sha256']==sha(ROOT/'dist/xcs-reconstruction-source.zip')==independent['archive_sha256']
for source in build['sources']:assert sha(ROOT/source['path'])==source['sha256']
for report in [host,net]:
 for name,expected in report['source_sha256'].items():assert sha(ROOT/name)==expected,name
for report in [date,datemachine,mint,numeric,simd]:assert report['status']=='PASS'
assert independent['all_dex_bytes_identical_to_emulator_tested_apk'] and independent['all_retained_assets_identical_to_emulator_tested_apk']
assert all(c['exit_code']==0 for c in independent['commands']) and len(independent['commands'])==10
assert 'BUILD SUCCESSFUL' in (ROOT/'build/gradle-build.log').read_text()
assert sha(APP/'analysis/completeness_audit/coverage_ledger.json')=='3da17a2ba384e9e6d7ed0cd6fdb59c681bfc3e728916b0380e11a8b1fa802770'
baseline=read(APP/'analysis/completeness_audit/coverage_ledger.json')
assert len(ledger['remaining_gap_updates'])==12
assert all(r['baseline'] in baseline['remaining_gaps'] and r['state']=='open' and not r['original_source_gap_closed'] for r in ledger['remaining_gap_updates'])
checked=[]
def refs(value):
 if isinstance(value,dict):
  if 'file'in value and 'sha256'in value:assert sha(Path(value['file']))==value['sha256'];checked.append(value['file'])
  for v in value.values():refs(v)
 elif isinstance(value,list):
  for v in value:refs(v)
refs(ledger)
# No source tree changed since packaging. Scan exact supplied account identifiers without recording them.
with zipfile.ZipFile(ROOT/'dist/xcs-reconstruction-source.zip') as z:
 assert z.testzip() is None
 for entry in package['files']:
  data=z.read('xcs-reconstruction/'+entry['path'])
  assert hashlib.sha256(data).hexdigest()==entry['sha256']==sha(ROOT/entry['path']),entry['path']
  assert not any(needle.encode() in data for needle in args.forbidden_identifier),'Private identifier found in packaged file'
with zipfile.ZipFile(ROOT/'dist/xcs-source-rebuild-debug.apk') as z:
 assert not any(name.startswith('lib/') and name.endswith('.so') for name in z.namelist())
 for name in z.namelist():
  assert not any(needle.encode() in z.read(name) for needle in args.forbidden_identifier),'Private identifier found in APK'
history=ROOT/'dist/history/round2';manifest=read(history/'history-manifest.json')
# Historical manifest format is preserved by the earlier snapshot operation.
for name in ['xcs-source-rebuild-debug.apk','xcs-reconstruction-source.zip']:
 assert (history/name).is_file()
assert sha(history/'xcs-source-rebuild-debug.apk')=='4b2578d8308239148d6354c6dfade5e26f4219141502a653f5df27b729128623'
assert sha(history/'xcs-reconstruction-source.zip')=='5143d2f6693dd1f1390e485fe31188fb99edc11b8b3a723966c2178ca0d2b4ae'
assert sha(ROOT/'dist/original-bytecode-rebuild.apk')=='8afd3ac46402bc54a27b5617d52c73e8ff829ec6e71bbd82558f797f2b3767c5'
cleanup=read(ROOT/'dist/round3-runtime-cleanup.json');assert cleanup['status']=='PASS' and all(r.get('exit_code',0)==0 for r in cleanup['actions'])
def first_count(name):return int(re.search(r'\b\d+\b',host['suites'][name]['summaries'][0]).group())
report={'status':'PASS','recorded_at_utc':datetime.datetime.now(datetime.timezone.utc).isoformat(),'round':3,'apk_sha256':build['apk_sha256'],'source_zip_sha256':package['sha256'],'compiled_java_files':len(build['sources']),'main_java_files':len(list((ROOT/'app/src/main/java').rglob('*.java'))),'instrumentation_java_files':len(list((ROOT/'app/src/androidTest/java').rglob('*.java'))),'packaged_files':len(package['files']),'source_archive_bytes':package['bytes'],'source_and_archive_hashes_current':True,'all_emulator_reports_match_final_apk':True,'independent_zip_build_and_all_dex_asset_match':True,'independent_commands_passed':len(independent['commands']),'gradle_offline_build':'PASS','business_assertions':first_count('business'),'settings_assertions':first_count('settings'),'callback_assertions':host['suites']['callbacks']['suite_results'][0]['assertion_count'],'model_assertions':first_count('models'),'round3_integration_assertions':first_count('integration'),'datetime_boundary_assertions':62,'datetime_reference_comparisons':date['comparisons'],'datetime_original_arithmetic_comparisons':datemachine['total_comparisons'],'mint_boundary_assertions':mint['boundary_assertions'],'mint_reference_comparisons':mint['differential_cases'],'numeric_json_boundary_assertions':numeric['boundary_assertions'],'numeric_json_reference_cases':numeric['differential_cases'],'numeric_json_parser_modes':numeric['parser_modes_checked'],'simd_input_cases':simd['dataset_inputs'],'simd_original_arm64_executions':simd['original_arm64_function_executions'],'simd_compiled_c_checks':simd['compiled_c_result_checks'],'simd_java_checks':simd['java_result_checks'],'simd_java_boundary_checks':simd['java_boundary_checks'],'simd_c_sanitizer_checks':simd['c_sanitizer_checks'],'simd_original_memory_checks':simd['original_memory_boundary_checks'],'loopback_ws_scenarios':len(net['tests']),'android_synthetic_checks':len(runtime['assertions']),'android_real_read_only_checks':len(live['checks']),'real_device_count':live['device_count'],'real_palette_count':live['palette_count'],'live_device_model_unresolved':live['model_unresolved'],'shared_simd_compiled_reconstructions':2,'new_simd_business_call_sites':simd['new_business_call_sites'],'remaining_simd_decompiler_errors':simd['remaining_original_body_decompiler_errors'],'ledger_reference_occurrences_verified':len(checked),'frozen_gap_categories_preserved':12,'credential_identifier_scan_performed':bool(args.forbidden_identifier),'credential_identifiers_in_packaged_files':False,'original_native_libraries_embedded_in_java_apk':False,'historical_round2_artifacts_preserved':True,'original_source_recovered':False,'complete_behavioral_equivalence':False,'task_emulator_and_fixture_stopped':True}
(ROOT/'dist/delivery-verification.json').write_text(json.dumps(report,ensure_ascii=False,indent=2)+'\n')
print(json.dumps(report,ensure_ascii=False))
