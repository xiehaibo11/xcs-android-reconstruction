#!/usr/bin/env python3
"""Rebuild local snapshot/reference oracle and compare Java without network access."""

from pathlib import Path as _PublicPath
import sys as _public_sys
_public_sys.path.insert(0, str(_PublicPath(__file__).resolve().parents[3] / "scripts"))
from _paths import app_root as _public_app_root, java_home as _public_java_home
from pathlib import Path
import json, random, subprocess, shutil
ROOT=_public_app_root()
HERE=Path(__file__).resolve().parent
EVIDENCE=ROOT/'reconstruction/evidence/round3/mint'

def main():
    vals={0,-1,1,-(1<<63),(1<<63)-1}
    for e in range(64):
        for v in (1<<e,-(1<<e)):
            vals.update(v+d for d in range(-3,4) if -(1<<63)<=v+d<(1<<63))
    rng=random.Random(35260)
    vals.update(rng.randrange(-(1<<63),1<<63) for _ in range(20000))
    (HERE/'cases.txt').write_text(''.join(str(v)+'\n' for v in sorted(vals)))
    for cmd in json.loads((HERE/'build_commands.json').read_text()):subprocess.run(cmd,check=True)
    subprocess.run([str(HERE/'mint_oracle'),str(ROOT/'unpacked/lib/arm64-v8a/libapp.so'),str(HERE/'cases.txt'),str(HERE/'oracle.tsv')],check=True)
    shutil.copyfile(HERE/'oracle.tsv',EVIDENCE/'reference.tsv')
    result=subprocess.run([str(EVIDENCE/'run_tests.sh')],check=True,text=True,capture_output=True)
    report=json.loads(result.stdout)
    (EVIDENCE/'verification.json').write_text(json.dumps(report,indent=2)+'\n')
    print(json.dumps(report))
    subprocess.run(['python3',str(HERE/'build_contracts.py')],check=True)

if __name__=='__main__':main()
