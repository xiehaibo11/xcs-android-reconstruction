#!/usr/bin/env python3
"""Opt-in real Android login checks. Ephemeral credentials; six HTTP routes and WS auth only."""
from pathlib import Path
import argparse,hashlib,json,os,socket,subprocess,sys,termios,threading

ROOT=Path(__file__).resolve().parents[1]
parser=argparse.ArgumentParser();parser.add_argument('--serial',default='emulator-5580');parser.add_argument('--adb-port',default='5038');parser.add_argument('--output-dir',default='evidence/round3/live');args=parser.parse_args()
if not args.serial.startswith('emulator-'):raise SystemExit('Only an explicitly named emulator is supported')
adb=['adb','-P',args.adb_port,'-s',args.serial]
def call(*command):return subprocess.run(adb+list(command),check=True,capture_output=True).stdout
def read_secret_stdin():
 # Read the tool-owned fd 0. getpass may open a different controlling /dev/tty.
 fd=sys.stdin.fileno()
 if not os.isatty(fd):raise RuntimeError('A terminal is required for non-echo credential input')
 before=termios.tcgetattr(fd);mode=before[:];mode[6]=before[6][:]
 mode[3]&=~(termios.ECHO|termios.ECHONL|termios.ICANON);mode[6][termios.VMIN]=1;mode[6][termios.VTIME]=0
 secret=bytearray()
 try:
  termios.tcsetattr(fd,termios.TCSANOW,mode)
  print('Credentials JSON on stdin (not echoed): ',end='',flush=True)
  while True:
   byte=os.read(fd,1)
   if byte in (b'\n',b'\r'):break
   if not byte:raise EOFError('Credential input closed')
   secret.extend(byte)
   if len(secret)>16384:raise ValueError('Credential input too long')
  return secret.decode('utf-8')
 finally:
  for i in range(len(secret)):secret[i]=0
  termios.tcsetattr(fd,termios.TCSANOW,before)
  print(flush=True)
if call('shell','getprop','ro.kernel.qemu').strip()!=b'1':raise SystemExit('Not an emulator')
apk=ROOT/'dist/xcs-source-rebuild-debug.apk';build=json.loads((ROOT/'dist/source-build.json').read_text())
if hashlib.sha256(apk.read_bytes()).hexdigest()!=build['apk_sha256']:raise SystemExit('APK build manifest differs')
for entry in build['sources']:
 if hashlib.sha256((ROOT/entry['path']).read_bytes()).hexdigest()!=entry['sha256']:raise SystemExit('Source changed after build')
call('install','--no-incremental','-r',str(apk));call('shell','am','force-stop','com.re.xcs.rebuild')
call('shell','run-as','com.re.xcs.rebuild','rm','-f','files/live-login-checks.json')
call('forward','tcp:19518','localabstract:xcs-rebuild-live-credentials')
process=subprocess.Popen(adb+['shell','am','instrument','-w','com.re.xcs.rebuild/.LiveLoginChecks'],stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.STDOUT,text=True)
lines=[];ready=threading.Event()
def read():
 for line in process.stdout:
  lines.append(line)
  if 'READY_FOR_EPHEMERAL_CREDENTIALS' in line:ready.set()
thread=threading.Thread(target=read,daemon=True);thread.start()
try:
 if not ready.wait(20):raise RuntimeError('Android credential socket not ready')
 secret=read_secret_stdin()
 supplied=json.loads(secret)
 if set(supplied)!={'host','username','password'}or not all(isinstance(x,str)and x for x in supplied.values()):raise ValueError('Expected host, username, password strings')
 with socket.create_connection(('127.0.0.1',19518),5)as connection:connection.sendall((secret+'\n').encode())
 del supplied,secret
 process.wait(timeout=150);thread.join(timeout=2)
 result=json.loads(call('exec-out','run-as','com.re.xcs.rebuild','cat','files/live-login-checks.json'))
 streamed=[]
 for line in lines:
  payload=line.split('stream=',1)[1] if line.startswith('INSTRUMENTATION_RESULT: stream=') else line.strip()
  if not payload.startswith('{'):continue
  try:item=json.loads(payload)
  except json.JSONDecodeError:continue
  if isinstance(item,dict) and {'status','requests','checks'}<=set(item):streamed.append(item)
 if process.returncode!=0 or len(streamed)!=1 or streamed[0]!=result:raise RuntimeError('Current instrumentation result differs from its newly written report')
 result.update(apk_sha256=build['apk_sha256'],android_api=call('shell','getprop','ro.build.version.sdk').decode().strip(),real_backend_contacted=True,credentials_recorded=False,original_source_recovered=False,complete_behavioral_equivalence=False)
 out=ROOT/args.output_dir;out.mkdir(parents=True,exist_ok=True)
 (out/'android-verification.json').write_text(json.dumps(result,ensure_ascii=False,indent=2)+'\n')
 (out/'instrumentation.log').write_text(''.join(lines))
 print(json.dumps(result,ensure_ascii=False),flush=True)
 if result['status']!='PASS_READ_ONLY_LIVE_LOGIN':raise SystemExit('Android live checks failed')
finally:
 if process.poll() is None:
  process.terminate();call('shell','am','force-stop','com.re.xcs.rebuild')
 call('forward','--remove','tcp:19518')
