
from pathlib import Path as _PublicPath
import sys as _public_sys
_public_sys.path.insert(0, str(_PublicPath(__file__).resolve().parents[3] / "scripts"))
from _paths import app_root as _public_app_root, java_home as _public_java_home
from pathlib import Path
import json,random
HERE=Path(__file__).resolve().parent
cases=[]
def emit(n):
 for mode,source in [('root',n),('root',n+' '),('array','['+n+']'),('object','{"n":'+n+'}')]:cases.append([mode,source])
boundaries=['0','-0','0.0','-0.0','-0e0','1e0','1E+0','1e-0',str(-(1<<63)),str((1<<63)-1),str(-(1<<63)-1),str(1<<63),'18446744073709551615','-18446744073709551616']
for e in [30,31,52,53,54,62,63,64]:
 for d in [-3,-2,-1,0,1,2,3]:
  for sign in [1,-1]:boundaries.append(str(sign*((1<<e)+d)))
for sign in ['', '-']:
 for n in ['1e309','1e-400','1e400','1e401','1e-401','1.7976931348623157e308','1.7976931348623159e308','2.2250738585072014e-308','2.2250738585072011e-308','4.9406564584124654e-324','2.4703282292062327e-324','2.4703282292062328e-324','9'*400,'9'*400+'e-401','9'*400+'e-400','0.'+'0'*401+'1e401','0e'+'9'*100,'1e'+'9'*100,'1e-'+'9'*100,'1e'+'0'*100+'1','9007199254740991.00000000000000000000001']:
  boundaries.append(sign+n)
for n in dict.fromkeys(boundaries):emit(n)
rng=random.Random(3521303)
for _ in range(4000):emit(str(rng.randrange(-(1<<63),1<<63)))
for _ in range(3000):
 n=str(rng.randrange(1,10))+''.join(str(rng.randrange(10)) for _ in range(rng.randrange(19,120)))
 emit(('-' if rng.randrange(2) else '')+n)
for _ in range(6000):
 n=str(rng.randrange(1,10))+''.join(str(rng.randrange(10)) for _ in range(rng.randrange(0,35)))
 if rng.randrange(2):
  pos=rng.randrange(1,len(n)+1);n=n[:pos]+'.'+n[pos:]+'1'
 n+=rng.choice(['e','E'])+rng.choice(['','+','-'])+str(rng.randrange(0,601))
 emit(('-' if rng.randrange(2) else '')+n)
invalid=['','-','+1','.1','-.1','1.','1.e2','1e','1e+','1e-','1e--1','1ee1','01','-01','00','-00','0x10','0b1','NaN','Infinity','-Infinity','--1','1_000','1,2','1 2','1true','\u0661','0\u0661','1.\u0661','1e\u0661','\x001','1\x00','1\v','1\f']
for n in invalid:
 if n in ['', '1,2']:cases.append(['root',n])
 else:emit(n)
(HERE/'cases.json').write_text(json.dumps(cases,separators=(',',':'))+'\n')
print(json.dumps({'rows':len(cases),'boundary_tokens':len(set(boundaries)),'random_tokens':13000,'malformed_tokens':len(invalid),'seed':3521303}))
