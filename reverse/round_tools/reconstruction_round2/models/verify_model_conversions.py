
from pathlib import Path as _PublicPath
import sys as _public_sys
_public_sys.path.insert(0, str(_PublicPath(__file__).resolve().parents[3] / "scripts"))
from _paths import app_root as _public_app_root, java_home as _public_java_home
from pathlib import Path
import hashlib,json,random,struct,subprocess
ROOT=_public_app_root()
P=ROOT/'reconstruction';OUT=P/'build/model-tests';OUT.mkdir(parents=True,exist_ok=True)
E=P/'evidence/round2/models';JAVA=(_public_java_home()/'bin')
source=ROOT/'tools/blutter/dartsdk/v3.5.2/third_party/double-conversion/src'
subprocess.run(['clang++','-std=c++17','-O2','-I'+str(source),str(Path(__file__).with_name('double_oracle.cpp')),*map(str,source.glob('*.cc')),'-o',str(OUT/'oracle')],check=True)
sources=list((P/'app/src/main/java/com/re/xcs/rebuild/core').glob('*.java'))+[E/'ModelConversionTest.java']
subprocess.run([str(JAVA/'javac'),'--release','8','-d',str(OUT),*map(str,sources)],check=True)
tests=subprocess.run([str(JAVA/'java'),'-cp',str(OUT),'com.re.xcs.rebuild.core.ModelConversionTest'],check=True,capture_output=True,text=True)
values=[0,1,2,0x8000000000000000,0x7ff0000000000000,0xfff0000000000000,0x7ff8000000000000,0x000fffffffffffff,0x0010000000000000,0x7fefffffffffffff]
for number in [1.0,0.1,1.5,1e-6,1e-7,1e20,1e21,1e23,2.2250738585072014e-308]:
 bits=struct.unpack('>Q',struct.pack('>d',number))[0]
 values.extend(bits+x for x in [-2,-1,0,1,2]);values.extend((bits+x)^0x8000000000000000 for x in [-2,-1,0,1,2])
random.seed(352);values.extend(random.getrandbits(64)for _ in range(20000))
payload=''.join(f'{v:016x}\n'for v in values)
oracle=subprocess.run([str(OUT/'oracle')],input=payload,text=True,capture_output=True,check=True).stdout.splitlines()
actual=subprocess.run([str(JAVA/'java'),'-cp',str(OUT),'com.re.xcs.rebuild.core.ModelConversionTest','doubles'],input=payload,text=True,capture_output=True,check=True).stdout.splitlines()
assert len(actual)==len(oracle)==len(values)
differences=[{'bits':f'{v:016x}','oracle':a,'java':b}for v,a,b in zip(values,oracle,actual)if a!=b]
record={'status':'PASS'if not differences else 'FAIL','model_test_output':tests.stdout.strip(),'double_cases':len(values),'double_differences':differences[:30],'oracle':'Local Dart VM 3.5.2 double-conversion source and DoubleToCString flags; not target APK execution','original_source_recovered':False,'remaining':['DateTime.parse/toIso8601String full semantics','Mint selector target behavior','custom dynamic receiver types','cyclic collection formatting'],'sources':{str(p.relative_to(ROOT)):hashlib.sha256(p.read_bytes()).hexdigest()for p in sources}}
(E/'verification.json').write_text(json.dumps(record,ensure_ascii=False,indent=2)+'\n')
print(json.dumps({k:v for k,v in record.items()if k!='sources'},ensure_ascii=False))
if differences:raise SystemExit(1)
