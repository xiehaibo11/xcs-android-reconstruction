
from pathlib import Path as _PublicPath
import sys as _public_sys
_public_sys.path.insert(0, str(_PublicPath(__file__).resolve().parents[3] / "scripts"))
from _paths import app_root as _public_app_root, java_home as _public_java_home
from pathlib import Path
import base64,hashlib,json,os,random,subprocess
HERE=Path(__file__).resolve().parent;ROOT=_public_app_root();PROJECT=ROOT/'reconstruction';EVIDENCE=PROJECT/'evidence/round3/datetime';OUT=PROJECT/'build/datetime-tests';OUT.mkdir(parents=True,exist_ok=True)
JDK=_public_java_home()/'bin'
DART=HERE/'reference/dart-sdk/bin/dart'
subprocess.run([str(JDK/'javac'),'--release','8','-Xlint:-options','-d',str(OUT),str(PROJECT/'app/src/main/java/com/re/xcs/rebuild/core/DartDateTime.java'),str(EVIDENCE/'DateTimeTest.java')],check=True)
unit=subprocess.run([str(JDK/'java'),'-cp',str(OUT),'com.re.xcs.rebuild.core.DateTimeTest'],capture_output=True,text=True,check=True).stdout.strip()
base=['','2020-01-01','20200101','202001-01','2020-0101','2020-01-01\n','2020-01-01\r','2020-01-01\r\n','2020-01-01\u2028','２０２０-01-01','2020-01-01t00:00','2020-01-01Z','2020-01-01T00Z','2020-01-01T0000z','2020-01-01T000000+99:99','2020-01-01T00:00:00.000000999999Z','2020-01-01T00:00:00.'+'9'*10000+'Z','0000-00-00','-000000-00-00','+000000-00-00','-000001-01-01','+999999-12-31T00:00:00Z','-999999-01-01T00:00:00Z']
for y in [-999999,-600000,-584554,-300000,-292277,-271821,-10000,-9999,-1,0,1,9999,10000,275760,292278,300000,584554,600000,999999]:
 for month,day in [(1,1),(2,29),(0,0),(99,99)]:base.append(f'{y:+07d}-{month:02d}-{day:02d}T00:00:00.000001Z')
for text in ['+275760-09-13T00:00:00','+275760-09-12T23:59:59.999999','+275760-09-13T00:00:00.000001','-271821-04-20T00:00:00','-271821-04-19T23:59:59.999999','1969-12-31T23:59:59.999999','1901-12-13T20:45:52','1901-12-13T20:45:53','2038-01-19T03:14:07','2038-01-19T03:14:08','2024-03-10T01:59:59.999999','2024-03-10T02:00:00','2024-03-10T02:30:00','2024-03-10T03:00:00','2024-11-03T01:30:00','2024-03-31T02:30:00','2024-10-27T02:30:00','2024-04-07T01:45:00','2024-10-06T02:15:00','2011-12-30T12:00:00']:
 for suffix in ['', 'Z','+23:59','-23:59']:base.append(text+suffix)
for suffix in ['', 'Z','+00:00','+08:00','-08:00']:
 for tail in ['224191','224192','224193']:
  base.append('-290308-12-21T19:59:05.'+tail+suffix)
for n in range(1,11):base.append('2020-01-01T00:00:00.'+'1234567890'[:n]+'Z')
random.seed(3520315)
for i in range(6000):
 y=random.randint(-999999,999999) if i%3==0 else random.randint(1800,2200)
 m,d,h,mi,s=[random.randrange(100) for _ in range(5)]
 ystr=f'{y:+07d}' if y<0 or y>9999 else f'{y:04d}'
 frac=''.join(str(random.randrange(10)) for _ in range(random.randrange(1,12)))
 suffix=random.choice(['','Z','z','+08:30','-23:59','+99:99','-00'])
 base.append(f'{ystr}-{m:02d}-{d:02d}T{h:02d}:{mi:02d}:{s:02d}.{frac}{suffix}')
cases=list(dict.fromkeys(base));payload=''.join(base64.b64encode(s.encode()).decode()+'\n'for s in cases)
(HERE/'reference_cases.json').write_text(json.dumps(cases,ensure_ascii=False,indent=2)+'\n')
zones=['UTC','America/Los_Angeles','Asia/Shanghai','Europe/Berlin','Australia/Lord_Howe','Pacific/Apia']
diffs=[];results=[]
for zone in zones:
 env=os.environ.copy();env['TZ']=zone;env['DART_SUPPRESS_ANALYTICS']='true'
 reference=subprocess.run([str(DART),'--disable-analytics',str(HERE/'reference_oracle.dart')],input=payload,text=True,capture_output=True,check=True,env=env).stdout.splitlines()
 actual=subprocess.run([str(JDK/'java'),'-cp',str(OUT),'com.re.xcs.rebuild.core.DateTimeTest','oracle',zone],input=payload,text=True,capture_output=True,check=True).stdout.splitlines()
 assert len(actual)==len(reference)==len(cases),(zone,len(actual),len(reference),len(cases))
 differences=[{'zone':zone,'input':text,'reference':a,'java':b}for text,a,b in zip(cases,reference,actual)if a!=b]
 diffs.extend(differences);results.append({'zone':zone,'cases':len(cases),'differences':len(differences)})
 (HERE/('oracle-'+zone.replace('/','_')+'.tsv')).write_text('\n'.join(reference)+'\n')
 print(results[-1],flush=True)
report={'status':'PASS'if not diffs else 'DIFFERENCES','java_unit_test':unit,'oracle':'Official Dart SDK 3.5.2 macos_arm64 running reference_oracle.dart; not original APK execution','dart_version':subprocess.run([str(DART),'--version'],capture_output=True,text=True,check=True).stdout.strip(),'cases_per_zone':len(cases),'comparisons':len(cases)*len(zones),'zones':results,'differences':diffs,'original_source_recovered':False,'original_apk_executed':False,'business_server_contacted':False,'sources':{str(x.relative_to(ROOT)):hashlib.sha256(x.read_bytes()).hexdigest() for x in [PROJECT/'app/src/main/java/com/re/xcs/rebuild/core/DartDateTime.java',EVIDENCE/'DateTimeTest.java',HERE/'reference_oracle.dart',HERE/'reference_cases.json',HERE/'reference/date_time.dart',HERE/'reference/date_patch.dart',DART]}}
(EVIDENCE/'reference_verification.json').write_text(json.dumps(report,ensure_ascii=False,indent=2)+'\n')
print(json.dumps({'status':report['status'],'comparisons':report['comparisons'],'differences':len(diffs),'examples':diffs[:8]},ensure_ascii=False))
