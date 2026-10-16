
from pathlib import Path as _PublicPath
import sys as _public_sys
_public_sys.path.insert(0, str(_PublicPath(__file__).resolve().parents[3] / "scripts"))
from _paths import app_root as _public_app_root, java_home as _public_java_home
from pathlib import Path
import json,zipfile,base64,hashlib
h=Path(__file__).resolve().parent;e=_public_app_root()/'reconstruction/evidence/round3/datetime'
inputs=json.loads((h/'reference_cases.json').read_text());zones=['UTC','America/Los_Angeles','Asia/Shanghai','Europe/Berlin','Australia/Lord_Howe','Pacific/Apia']
content={'inputs.base64.txt':''.join(base64.b64encode(s.encode()).decode()+'\n' for s in inputs).encode(),'zones.txt':('\n'.join(zones)+'\n').encode()}
for z in zones:content['oracle-'+z.replace('/','_')+'.tsv']=(h/('oracle-'+z.replace('/','_')+'.tsv')).read_bytes()
manifest={'oracle':'Official Dart SDK 3.5.2 macos_arm64, not original APK execution','cases_per_zone':len(inputs),'comparisons':len(inputs)*len(zones),'zones':zones,'files':{k:hashlib.sha256(v).hexdigest()for k,v in content.items()},'original_source_recovered':False}
content['manifest.json']=(json.dumps(manifest,indent=2)+'\n').encode()
with zipfile.ZipFile(e/'reference-fixtures.zip','w',compression=zipfile.ZIP_DEFLATED,compresslevel=9)as z:
 for k,v in content.items():
  i=zipfile.ZipInfo(k,(2026,10,15,0,0,0));i.compress_type=zipfile.ZIP_DEFLATED;z.writestr(i,v,compresslevel=9)
(e/'reference_fixture_manifest.json').write_text(json.dumps({**manifest,'archive_sha256':hashlib.sha256((e/'reference-fixtures.zip').read_bytes()).hexdigest()},indent=2)+'\n')
print('fixture comparisons',manifest['comparisons'],'archive bytes',(e/'reference-fixtures.zip').stat().st_size)
