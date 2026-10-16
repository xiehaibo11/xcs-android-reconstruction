#!/usr/bin/env python3
"""Install/debug-test only in an explicitly named Android emulator.
Start scripts/fixture_server.py first; it listens exclusively on loopback.
"""
from pathlib import Path
import argparse, hashlib, json, os, subprocess

ROOT=Path(__file__).resolve().parents[1]
parser=argparse.ArgumentParser();parser.add_argument('--serial',default='emulator-5580');parser.add_argument('--adb-port',default='5038')
args=parser.parse_args()
if not args.serial.startswith('emulator-'):raise SystemExit('This verifier only installs into an explicitly isolated emulator')
ADB=['adb','-P',args.adb_port,'-s',args.serial]
env=dict(os.environ,ANDROID_USER_HOME=str(ROOT/'runtime/android'))
out=ROOT/'evidence/runtime';out.mkdir(parents=True,exist_ok=True)
def call(*commands,binary=False):
 p=subprocess.run(ADB+list(commands),env=env,check=True,capture_output=True)
 return p.stdout if binary else p.stdout.decode(errors='replace')
apk=ROOT/'dist/xcs-source-rebuild-debug.apk'
build=json.loads((ROOT/'dist/source-build.json').read_text())
if hashlib.sha256(apk.read_bytes()).hexdigest()!=build['apk_sha256']:raise SystemExit('APK differs from build manifest')
for entry in build['sources']:
 if hashlib.sha256((ROOT/entry['path']).read_bytes()).hexdigest()!=entry['sha256']:raise SystemExit('Source changed after compilation: '+entry['path'])
if call('shell','getprop','ro.kernel.qemu').strip()!='1':raise SystemExit('Not an emulator')
print(call('install','--no-incremental','-r',str(apk)),flush=True)
call('shell','am','force-stop','com.re.xcs.rebuild')
call('shell','run-as','com.re.xcs.rebuild','rm','-f','files/runtime-checks.json')
call('reverse','tcp:8081','tcp:8081');call('reverse','tcp:18889','tcp:18889')
log=call('shell','am','instrument','-w','com.re.xcs.rebuild/.RuntimeChecks')
(out/'instrumentation.log').write_text(log);print(log,flush=True)
result=json.loads(call('exec-out','run-as','com.re.xcs.rebuild','cat','files/runtime-checks.json'))
if result['status']=='PASS' and ('result=PASS '+str(len(result['assertions']))+' checks') not in log:raise SystemExit('Current instrumentation stream does not match the newly written report')
result.update(apk_sha256=hashlib.sha256(apk.read_bytes()).hexdigest(),apk=str(apk),emulator=args.serial,android_api=call('shell','getprop','ro.build.version.sdk').strip(),original_source_recovered=False,complete_behavioral_equivalence=False)
for name in ['login','main','preview','settings']:
 try:(out/(name+'.png')).write_bytes(call('exec-out','run-as','com.re.xcs.rebuild','cat','files/runtime-'+name+'.png',binary=True))
 except subprocess.CalledProcessError:
  if result['status']=='PASS':raise
(out/'verification.json').write_text(json.dumps(result,ensure_ascii=False,indent=2)+'\n')
(out/'fixture-observations.json').write_bytes((ROOT/'runtime/fixture-observations.json').read_bytes())
if result['status']!='PASS':raise SystemExit('Runtime checks failed')
print('Runtime PASS:',len(result['assertions']),'checks',flush=True)
