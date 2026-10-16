#!/usr/bin/env python3
"""Execute original bounded ARM64 DateTime arithmetic. No Android startup, I/O or syscalls.
Dart stack/thread/constant-pool objects and the Mint allocator are explicitly modeled.
The full original regex/parser/formatting and system timezone provider are not emulated.
"""

from pathlib import Path as _PublicPath
import sys as _public_sys
_public_sys.path.insert(0, str(_PublicPath(__file__).resolve().parents[3] / "scripts"))
from _paths import app_root as _public_app_root, java_home as _public_java_home
from pathlib import Path
import io,json,hashlib,re,struct,sys,random
try:import unicorn
except ImportError:
 candidates=list((Path.home()/'.cache/uv/archive-v0').glob('*/unicorn/__init__.py'))
 if not candidates:raise SystemExit('Existing local Unicorn dependency required')
 sys.path.insert(0,str(candidates[0].parents[1]));import unicorn
from unicorn import Uc,UC_ARCH_ARM64,UC_MODE_ARM,UC_HOOK_CODE
from unicorn.arm64_const import *
from elftools.elf.elffile import ELFFile
HERE=Path(__file__).resolve().parent;ROOT=_public_app_root();E=ROOT/'reconstruction/evidence/round3/datetime'
blob=(ROOT/'unpacked/lib/arm64-v8a/libapp.so').read_bytes();elf=ELFFile(io.BytesIO(blob))
uc=Uc(UC_ARCH_ARM64,UC_MODE_ARM);uc.mem_map(0x1000,0xfff000)
for s in elf.iter_segments():
 if s['p_type']=='PT_LOAD':
  skip=max(0,0x1000-s['p_vaddr']);uc.mem_write(s['p_vaddr']+skip,s.data()[skip:])
DATA=0x90000000;STACK=0x91008000;STOP=0xa0000000;NULL=DATA+0x10001;THREAD=DATA+0x20000;MINT=DATA+0x30001
uc.mem_map(DATA,0x100000);uc.mem_map(STACK-0x8000,0x10000);uc.mem_map(STOP,0x1000)
def put(a,x,n=8):uc.mem_write(a,(x%(1<<(8*n))).to_bytes(n,'little'))
def signed(x):return x-(1<<64) if x&(1<<63) else x
# Constants actually read by _brokenDownDateToValue from the snapshot object pool.
MAX=8640000000000000000;DAY=86400000000
put(DATA+0xd5c0,DAY);put(DATA+0xd5c8,DATA+0x11001);put(DATA+0xd610,MAX+DAY);put(DATA+0xd618,MAX)
for idx,days in enumerate([[0,31,59,90,120,151,181,212,243,273,304,334],[0,31,60,91,121,152,182,213,244,274,305,335]]):
 arr=DATA+0x12001+idx*0x1000;put(DATA+0x11001+0xf+4*idx,arr,4);put(arr+0xb,24,4)
 for i,d in enumerate(days):put(arr+0xf+4*i,d*2,4)
coverage=set();allocator_calls=0
ranges=[(0x442320,0x4424e0),(0x4918e0,0x491b34)]
def hook(u,addr,size,extra):
 global allocator_calls
 if addr==0x6fa078:
  allocator_calls+=1;u.reg_write(UC_ARM64_REG_X0,MINT);u.reg_write(UC_ARM64_REG_PC,u.reg_read(UC_ARM64_REG_LR));return
 if not any(a<=addr<b for a,b in ranges):raise AssertionError('Unexpected external target '+hex(addr))
 coverage.add(addr)
uc.hook_add(UC_HOOK_CODE,hook)
def run(entry,x1=0,x2=0,x3=0,x5=0,x6=0,x7=0):
 for reg,val in [(UC_ARM64_REG_X1,x1),(UC_ARM64_REG_X2,x2),(UC_ARM64_REG_X3,x3),(UC_ARM64_REG_X5,x5),(UC_ARM64_REG_X6,x6),(UC_ARM64_REG_X7,x7),(UC_ARM64_REG_X15,STACK),(UC_ARM64_REG_X22,NULL),(UC_ARM64_REG_X26,THREAD),(UC_ARM64_REG_X27,DATA),(UC_ARM64_REG_X28,0),(UC_ARM64_REG_X29,0),(UC_ARM64_REG_LR,STOP)]:uc.reg_write(reg,val&((1<<64)-1))
 uc.emu_start(entry,STOP,count=20000)
 assert uc.reg_read(UC_ARM64_REG_PC)==STOP
 return uc.reg_read(UC_ARM64_REG_X0)
def days(y):return 365*(y-1970)+(y-1969)//4-(y-1901)//100+(y-1601)//400
random.seed(3520315);years=list(range(-1000,3001))+[random.randint(-999999,1000007)for _ in range(2000)]+[-999999,-271821,275760,999999]
helpers=0
for y in years:
 d=days(y);weekday=(d+4)%7;equiv=2008+(((1956 if y%4==0 and(y%16==0 or y%100!=0)else 1967)+weekday*12)-2008)%28
 for entry,want in [(0x442410,d),(0x4423c4,weekday),(0x442320,equiv)]:
  got=signed(run(entry,y));assert got==want,(hex(entry),y,got,want);helpers+=1
pattern=re.compile(r'^([+-]?\d{4,6})-?(\d\d)-?(\d\d)(?:[ T](\d\d)(?::?(\d\d)(?::?(\d\d)(?:[.,](\d+))?)?)?( ?[zZ]| ?([-+])(\d\d)(?::?(\d\d))?)?)?$',re.ASCII)
cases=json.loads((HERE/'reference_cases.json').read_text());ref=(HERE/'oracle-UTC.tsv').read_text().splitlines();arithmetic=0;rejected=0;fingerprint=hashlib.sha256()
for text,expected in zip(cases,ref):
 m=pattern.fullmatch(text)
 if m is None:continue
 g=m.groups();y,month,day=map(int,g[:3]);hour,minute,second=[int(v or 0)for v in g[3:6]];micros=int(((g[6]or'')+'000000')[:6]);
 if g[8]:minute-=(1 if g[8]=='+'else -1)*(60*int(g[9])+int(g[10]or 0))
 put(STACK,NULL+0x20);put(STACK+8,micros%1000);put(STACK+16,micros//1000)
 result=run(0x4918e0,y,month,day,hour,minute,second)
 actual=None if result==NULL else signed(int.from_bytes(uc.mem_read(result+7,8),'little')) if result&1 else signed(result)>>1
 want=-(1<<63) if expected.startswith('error\tRangeError') else None if expected.startswith('error\t') else int(expected.split('\t')[1]);assert actual==want,(text,actual,want)
 arithmetic+=1;rejected+=actual is None;fingerprint.update((str(actual)+'\n').encode())
report={'status':'PASS','scope':'Original ARM64 bounded arithmetic bodies, with modeled VM memory and Mint allocator; not original DateTime parse/format execution or whole APK','helper_comparisons':helpers,'normalized_component_cases':arithmetic,'range_rejections':rejected,'total_comparisons':helpers+arithmetic,'unicorn_version':unicorn.__version__,'original_elf_sha256':hashlib.sha256(blob).hexdigest(),'entrypoints':{'0x442410':'_dayFromYear','0x4423c4':'_weekDay','0x442320':'_equivalentYear','0x4918e0':'_brokenDownDateToValue (UTC branch)'},'modeled_boundaries':['Dart X15 stack, X22 null/bools, X26 stack-limit thread field','Constant pool/day arrays using confirmed original constant values','0x6fa078 Mint allocation returns writable modeled object; arithmetic result and object payload stores execute original instructions'],'instructions_observed':len(coverage),'instruction_addresses':[hex(x)for x in sorted(coverage)],'result_fingerprint_sha256':fingerprint.hexdigest(),'syscalls_executed':False,'business_server_contacted':False,'original_source_recovered':False}
(E/'machine_execution.json').write_text(json.dumps(report,indent=2)+'\n');print(json.dumps({k:v for k,v in report.items()if k!='instruction_addresses'}))
