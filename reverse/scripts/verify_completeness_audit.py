#!/usr/bin/env python3
"""Recheck audit inventories and frozen artifacts; never runs target code."""

from _paths import app_root, workspace_root
import argparse
import hashlib
import json
import subprocess
import sys
from pathlib import Path

APP = app_root()
OUT = APP / 'analysis/completeness_audit'
MANIFEST = OUT / 'audit_artifact_manifest.json'
RESULT = OUT / 'verification.json'
CHECKERS = ['android_completeness_audit.py', 'flutter_completeness_audit.py',
            'native_completeness_audit.py', 'model_completeness_audit.py']
EXTRA_CHECKERS = ['verify_reconnect_preview_failure.py']

def sha(p): return hashlib.sha256(p.read_bytes()).hexdigest()
def write(p, x): p.write_text(json.dumps(x, ensure_ascii=False, indent=2)+'\n')

def run():
    checks, errors = [], []
    for name in CHECKERS + EXTRA_CHECKERS:
        command = [sys.executable, str(APP/'scripts'/name)] + (['--verify'] if name in CHECKERS else [])
        process = subprocess.run(command, cwd=APP.parent, text=True, capture_output=True)
        record = {'script':str(APP/'scripts'/name), 'script_sha256':sha(APP/'scripts'/name),
                  'exit_code':process.returncode, 'stdout':process.stdout.strip(),
                  'stderr':process.stderr.strip()}
        checks.append(record)
        print(json.dumps({'check':name,'exit_code':process.returncode},ensure_ascii=False),flush=True)
        if process.returncode: errors.append('Independent inventory verification failed: '+name)
    # Refresh existing active proof references after status/index corrections.
    process = subprocess.run([sys.executable,str(APP/'scripts/completeness_evidence_audit.py')],
                             cwd=APP.parent,capture_output=True,text=True)
    reference = json.loads((OUT/'evidence/existing_reference_audit.json').read_text())
    if process.returncode or reference['missing_references'] or reference['mismatched_references']:
        errors.append('Existing active proof reference audit failed')
    previous = json.loads((OUT/'evidence/verifier_rerun.json').read_text())
    if not previous['all_verifiers_passed']: errors.append('One of six previous proof verifiers failed')
    for v in previous['verifiers']:
        if sha(Path(v['script'])) != v['script_sha256']: errors.append('Previously rerun checker changed: '+v['script'])
    android = json.loads((OUT/'android/android_completeness.json').read_text())
    flutter = json.loads((OUT/'flutter/method_coverage.json').read_text())
    native = json.loads((OUT/'native/native_completeness.json').read_text())
    models = json.loads((OUT/'models/model_field_contracts.json').read_text())
    ledger = json.loads((OUT/'coverage_ledger.json').read_text())
    def ledger_refs(node):
        if isinstance(node,list):
            for value in node: ledger_refs(value)
        elif isinstance(node,dict):
            if isinstance(node.get('file'),str) and isinstance(node.get('sha256'),str):
                p=Path(node['file'])
                if not p.is_file() or sha(p)!=node['sha256']: errors.append('Coverage ledger evidence changed: '+str(p))
            for value in node.values(): ledger_refs(value)
    ledger_refs(ledger)
    expected_counts = {'apk_zip_entries':android['counts']['zip_entries'],
        'dex_classes':android['counts']['dex_class_defs'],
        'dex_defined_methods':android['counts']['dex_encoded_methods'],
        'dex_defined_fields':android['counts']['dex_encoded_fields'],
        'dart_business_files':flutter['counts']['business_files'],
        'dart_exported_business_methods':flutter['counts']['business_methods'],
        'dart_partial_claim_associations':flutter['counts']['methods_supporting_explicit_partial_claims'],
        'dart_without_explicit_claim_associations':flutter['counts']['methods_without_explicit_semantic_association'],
        'model_files':models['model_file_count'],
        'model_class_key_contracts':models['distinct_class_key_contracts'],
        'native_libraries':native['library_count'],'native_abis':len(native['abis']),
        'go_functions_all_abis':sum(g['function_count'] for g in native['go_pclntab'])}
    native_failures = []
    for library in ['rust','rsa']:
        items = json.loads((OUT/'native'/(library+'_not_complete_c.json')).read_text())
        native_failures += [x for x in items if x['c_status'] != 'non_executable_import_placeholder']
    expected_counts['native_explicit_c_failures_or_truncations'] = len(native_failures)
    if expected_counts != ledger['scope_counts']: errors.append('Coverage ledger counts differ from full inventories')
    if ledger['semantic_reconstruction_complete'] or ledger['source_reconstruction_complete']:
        errors.append('Coverage ledger incorrectly claims complete semantics/source')
    native_check = json.loads((OUT/'native/verification.json').read_text())
    if any(r['llvm_unlisted_executable_ranges'] for r in native_check['llvm_results']):
        errors.append('LLVM complete executable listings omit byte ranges')
    if android['zip']['effective_mismatch_entries']: errors.append('Unresolved indexed ZIP byte mismatch')
    if android['counts']['dex_class_defs'] != android['counts']['smali_files']: errors.append('DEX class omission')
    if flutter['counts']['business_methods'] != 612 or flutter['counts']['raw_direct_bl_failures']:
        errors.append('Business method/BL mismatch')
    if native['library_count'] != 13: errors.append('APK library omission')
    if models['model_file_count'] != 16 or models['distinct_class_key_contracts'] != 94:
        errors.append('Model file/JSON key inventory changed')
    return {'status':'FAIL' if errors else 'PASS', 'all_checks_passed':not errors,
            'scope':'Package byte identity, full inventoried definitions, all exported business AOT bodies, bounded local contracts, proof integrity. Not complete behavioral/source reconstruction.',
            'original_apk_unchanged':android['zip']['working_copy_matches'],
            'zip_entries':android['counts']['zip_entries'], 'dex':android['counts'],
            'dart_aot':flutter['counts'], 'model_contracts':{
                k:models[k] for k in ['model_file_count','model_method_count','json_method_count',
                                     'distinct_class_key_contracts','json_key_occurrences']},
            'native_libraries':native['library_count'], 'native_abis':native['abis'],
            'existing_proof_references':{'json_documents':reference['existing_json_documents'],
                'hash_checks':reference['hash_reference_checks'],'unique_files':reference['unique_files_hashed'],
                'missing':len(reference['missing_references']),'mismatches':len(reference['mismatched_references'])},
            'independent_checkers':checks, 'previous_verifiers_passed':previous['all_verifiers_passed'],
            'semantic_reconstruction_complete':False, 'original_dart_source_recovered':False,
            'target_code_executed':False,'business_server_contacted':False,'errors':errors}

if __name__ == '__main__':
    parser=argparse.ArgumentParser()
    parser.add_argument('--freeze-manifest',action='store_true',
                        help='Freeze current completed audit files after all sub-audits pass.')
    args=parser.parse_args()
    result=run()
    excluded={MANIFEST,RESULT,OUT/'evidence/existing_reference_audit.json'}
    # Reference-audit input lists include evolving status/verification files; verify them live,
    # do not turn that refreshable observation into a frozen source artifact.
    files=[p for p in sorted(OUT.rglob('*')) if p.is_file() and p not in excluded]
    files += [APP/'scripts'/n for n in CHECKERS+EXTRA_CHECKERS+['completeness_evidence_audit.py','verify_completeness_audit.py']]
    files += [APP/'逆向完整性审计与补齐报告.txt',APP/'README.txt']
    if args.freeze_manifest and not result['errors']:
        missing=[str(p) for p in files if not p.is_file()]
        if missing: result['errors'].append('Cannot freeze missing artifacts: '+str(missing))
        else: write(MANIFEST,{'scope':'Current static audit artifact snapshot; intentional historical correction records included as bytes.',
                              'files':[{'file':str(p),'sha256':sha(p),'bytes':p.stat().st_size} for p in files]})
    if not MANIFEST.is_file(): result['errors'].append('Frozen audit artifact manifest is missing')
    else:
        manifest=json.loads(MANIFEST.read_text())
        expected={Path(x['file']) for x in manifest['files']}
        current={p for p in files if p.is_file()}
        if expected != current: result['errors'].append('Audit artifact file set changed')
        for item in manifest['files']:
            p=Path(item['file'])
            if not p.is_file() or sha(p)!=item['sha256']: result['errors'].append('Frozen artifact changed: '+str(p))
        result['frozen_artifact_count']=len(manifest['files'])
    result['status']='FAIL' if result['errors'] else 'PASS'
    result['all_checks_passed']=not result['errors']
    write(RESULT,result)
    print(json.dumps({k:result[k] for k in ['status','all_checks_passed','semantic_reconstruction_complete','errors']},ensure_ascii=False))
    raise SystemExit(0 if result['all_checks_passed'] else 1)
