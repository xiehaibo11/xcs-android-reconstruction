#!/usr/bin/env python3
"""Run packaged, offline reconstruction tests and bind observations to current sources."""
from pathlib import Path
import hashlib,json,subprocess
ROOT=Path(__file__).resolve().parents[1]
OUT=ROOT/'dist/public-validation'
SUITES={
 'business':'evidence/business/run_tests.sh',
 'settings':'evidence/logic/run_tests.sh',
 'callbacks':'evidence/round2/callbacks/run_tests.sh',
 'models':'evidence/round2/models/run_tests.sh',
 'integration':'evidence/round3/integration/run_tests.sh',
 'mint':'evidence/round3/mint/run_tests.sh',
 'datetime':'evidence/round3/datetime/run_tests.sh',
 'simd':'evidence/round3/simd/run_tests.sh',
 'numeric_json':'evidence/round3/numeric_json/run_tests.sh',
}
def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()
def snapshot():
 files=list((ROOT/'app/src/main/java').rglob('*.java'))
 files.extend(p for p in (ROOT/'evidence').rglob('*') if p.is_file() and p.suffix in ('.java','.sh','.tsv','.jsonl','.c','.h','.gz','.zip'))
 return {str(p.relative_to(ROOT)):sha(p) for p in sorted(files)}
def main():
 OUT.mkdir(parents=True,exist_ok=True);sources=snapshot();results={};logs=[]
 for name,path in SUITES.items():
  command=['sh',path];proc=subprocess.run(command,cwd=ROOT,text=True,capture_output=True)
  logs.extend(['COMMAND: '+' '.join(command),proc.stdout,proc.stderr]);(OUT/'host-tests.log').write_text('\n'.join(logs))
  item={'command':command,'exit_code':proc.returncode,'summaries':[],'suite_results':[]}
  for line in proc.stdout.splitlines():
   if line.startswith('{'):
    try:item['suite_results'].append(json.loads(line))
    except json.JSONDecodeError:pass
   elif line.startswith('PASS'):
    item['summaries'].append(line)
  results[name]=item
  if proc.returncode:raise RuntimeError(name+' failed; see host-tests.log')
  print(name+': PASS',flush=True)
 assert sources==snapshot(),'Tested source changed during host run'
 report={'status':'PASS','suites':results,'source_sha256':sources,'business_server_contacted':False,'original_apk_executed':False,'original_source_recovered':False,'complete_behavioral_equivalence':False,'public_build':True,'scope':'Portable host regression and recorded reference fixtures; original-machine-code execution and reference generation have separate reports.'}
 (OUT/'host-verification.json').write_text(json.dumps(report,ensure_ascii=False,indent=2)+'\n')
 print(json.dumps({'status':report['status'],'suites':list(results)},ensure_ascii=False))
if __name__=='__main__':main()
