#!/usr/bin/env python3
"""Offline SDK build. This compiles reconstructed Java, never decompiler pseudocode."""
from pathlib import Path
import hashlib, json, shutil, subprocess, zipfile, xml.etree.ElementTree as ET
from build_environment import android_sdk, build_tools, jdk_bin
from prepare_dev_assets import prepare

ROOT = Path(__file__).resolve().parents[1]
SDK = android_sdk()
JAVA = jdk_bin()
BT = build_tools(SDK)
PLATFORM = SDK / 'platforms/android-35/android.jar'
OUT = ROOT / 'build/source'
DIST = ROOT / 'dist'

def run(args):
    print('+', ' '.join(map(str,args)), flush=True)
    subprocess.run(list(map(str,args)), check=True, cwd=ROOT)

def main():
    OUT.mkdir(parents=True, exist_ok=True); DIST.mkdir(exist_ok=True)
    classes = OUT/'classes'
    if classes.exists(): shutil.rmtree(classes)
    classes.mkdir()
    assets = ROOT/'app/src/main/assets'
    assets.mkdir(parents=True, exist_ok=True)
    # Public builds use only the verified, non-key assets checked into this
    # repository. Never recover keys or assets implicitly from a neighboring APK.
    manifest_path = ROOT / 'evidence/retained_assets.json'
    retained = json.loads(manifest_path.read_text())
    for entry in retained:
        file = ROOT / entry['path']
        if not file.resolve().is_relative_to(assets.resolve()) or 'key' in file.relative_to(assets).parts:
            raise RuntimeError('Retained asset manifest contains an invalid/key path')
        if not file.is_file() or hashlib.sha256(file.read_bytes()).hexdigest() != entry['sha256']:
            raise RuntimeError('Retained asset missing or changed: ' + entry['path'])
    development_assets = prepare()
    (OUT/'retained_assets.json').write_text(json.dumps(retained,ensure_ascii=False,indent=2)+'\n')
    sources=sorted((ROOT/'app/src/main/java').rglob('*.java'))
    sources+=sorted((ROOT/'app/src/androidTest/java').rglob('*.java'))
    if not sources: raise RuntimeError('No actual source files')
    source_hashes=[{'path':str(p.relative_to(ROOT)),'sha256':hashlib.sha256(p.read_bytes()).hexdigest()} for p in sources]
    run([JAVA/'javac','--release','8','-encoding','UTF-8','-classpath',PLATFORM,'-d',classes,*sources])
    run([JAVA/'jar','cf',OUT/'classes.jar','-C',classes,'.'])
    dex=OUT/'dex'; dex.mkdir(exist_ok=True)
    run([BT/'d8','--min-api','26','--lib',PLATFORM,'--output',dex,OUT/'classes.jar'])
    raw=OUT/'resources.apk'
    ET.register_namespace('android','http://schemas.android.com/apk/res/android')
    manifest=ET.parse(ROOT/'app/src/main/AndroidManifest.xml')
    manifest.getroot().set('package','com.re.xcs.rebuild')
    manifest.write(OUT/'AndroidManifest.xml',encoding='utf-8',xml_declaration=True)
    run([BT/'aapt2','link','-I',PLATFORM,'--manifest',OUT/'AndroidManifest.xml','-A',assets,'-o',raw])
    unsigned=OUT/'unsigned.apk'; shutil.copyfile(raw,unsigned)
    with zipfile.ZipFile(unsigned,'a',zipfile.ZIP_DEFLATED) as z:
        for p in sorted(dex.glob('*.dex')): z.write(p,p.name)
    aligned=OUT/'aligned.apk'
    run([BT/'zipalign','-f','-p','4',unsigned,aligned])
    key=ROOT/'build/reconstruction-debug.jks'
    if not key.exists():
        run([JAVA/'keytool','-genkeypair','-keystore',key,'-storepass','android','-keypass','android','-alias','reconstruction','-dname','CN=XCS Reconstruction Debug','-keyalg','RSA','-keysize','2048','-validity','3650'])
    apk=DIST/'xcs-source-rebuild-debug.apk'
    run([BT/'apksigner','sign','--ks',key,'--ks-key-alias','reconstruction','--ks-pass','pass:android','--key-pass','pass:android','--out',apk,aligned])
    run([BT/'apksigner','verify','--verbose',apk])
    for entry in source_hashes:
        if hashlib.sha256((ROOT/entry['path']).read_bytes()).hexdigest()!=entry['sha256']:
            raise RuntimeError('Source changed during compilation: '+entry['path'])
    report={'build':'PASS','source_kind':'new Java reconstruction; not original Dart/Rust/Go source','source_files':len(sources),'apk':str(apk),'apk_sha256':hashlib.sha256(apk.read_bytes()).hexdigest(),'min_sdk':26,'target_sdk':28,'compile_sdk':35,'compiler':'javac --release 8 + D8 + AAPT2','original_source_recovered':False,'complete_behavioral_equivalence':False,'sources':source_hashes,'public_build':True,'development_rsa_assets':development_assets,'non_key_asset_files':len(retained),'android_build_tools':BT.name}
    (DIST/'source-build.json').write_text(json.dumps(report,ensure_ascii=False,indent=2)+'\n')
    print(apk)
if __name__=='__main__': main()
