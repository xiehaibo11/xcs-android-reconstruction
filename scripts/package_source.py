#!/usr/bin/env python3
"""Bundle editable reconstruction and evidence; never bundle generated binaries as source."""
from pathlib import Path
import hashlib
import json
import zipfile

ROOT = Path(__file__).resolve().parents[1]
DIST = ROOT / 'dist'

def main():
    DIST.mkdir(exist_ok=True)
    files = []
    for directory in ['app/src', 'evidence', 'gradle', 'scripts', 'reverse']:
        files.extend(p for p in (ROOT / directory).rglob('*') if p.is_file()
                     and not any(part in ('__pycache__', 'classes', 'runtime') for part in p.relative_to(ROOT).parts)
                     and not str(p.relative_to(ROOT)).startswith('app/src/main/assets/key/')
                     and p.suffix.lower() not in ('.pem', '.jks', '.p12', '.pfx', '.keystore', '.log'))
    files.extend(ROOT / name for name in ['app/build.gradle', 'build.gradle', 'settings.gradle',
                                         'gradle.properties', 'gradlew', '.gitignore', '重建工程说明.txt',
                                         'README.md', 'NOTICE.md', 'PUBLICATION.json', 'PUBLIC_VALIDATION.json'] if (ROOT / name).is_file())
    files = sorted(set(files))
    package = DIST / 'xcs-reconstruction-source.zip'
    entries = []
    with zipfile.ZipFile(package, 'w', zipfile.ZIP_DEFLATED, compresslevel=9) as z:
        for path in files:
            relative = str(path.relative_to(ROOT))
            data = path.read_bytes()
            if b'-----BEGIN PRIVATE KEY-----\n' in data or b'-----BEGIN RSA PRIVATE KEY-----\n' in data:
                raise RuntimeError('Refusing to package private key material: ' + relative)
            z.write(path, 'xcs-reconstruction/' + relative)
            entries.append({'path': relative, 'sha256': hashlib.sha256(path.read_bytes()).hexdigest()})
    with zipfile.ZipFile(package) as z:
        assert z.testzip() is None
        for entry in entries:
            assert hashlib.sha256(z.read('xcs-reconstruction/' + entry['path'])).hexdigest() == entry['sha256']
    report = {'status': 'PASS', 'archive': str(package), 'bytes': package.stat().st_size,
              'sha256': hashlib.sha256(package.read_bytes()).hexdigest(), 'files': entries,
              'source_kind': 'Public Java reconstruction with verified non-key retained assets; local RSA fixture assets excluded',
              'original_source_recovered': False, 'complete_behavioral_equivalence': False,
              'external_dependencies': ['JDK', 'Android SDK', 'Gradle/AGP cache for offline Gradle build'],
              'all_key_material_excluded': True,
              'full_reverse_engineering_evidence_location': 'Historical APP/analysis work products are outside this public source archive'}
    (DIST / 'source-package.json').write_text(json.dumps(report, ensure_ascii=False, indent=2) + '\n')
    print(json.dumps({key: value for key, value in report.items() if key != 'files'}, ensure_ascii=False))

if __name__ == '__main__':
    main()
