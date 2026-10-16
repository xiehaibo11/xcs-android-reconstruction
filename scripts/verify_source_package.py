#!/usr/bin/env python3
"""Actually unpack and build the distributed source ZIP without original APK inputs."""
from pathlib import Path
import hashlib
import json
import subprocess
import tempfile
import zipfile

ROOT = Path(__file__).resolve().parents[1]
DIST = ROOT / 'dist'

def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()

def main():
    package = DIST / 'xcs-reconstruction-source.zip'
    packaged = json.loads((DIST / 'source-package.json').read_text())
    assert sha(package) == packaged['sha256']
    with tempfile.TemporaryDirectory(prefix='xcs-source-standalone-') as temporary:
        parent = Path(temporary)
        with zipfile.ZipFile(package) as z:
            for entry in z.infolist():
                destination = (parent / entry.filename).resolve()
                assert destination.is_relative_to(parent.resolve())
            z.extractall(parent)
        project = parent / 'xcs-reconstruction'
        assert not (parent / 'input/app_xcs.apk').exists()
        assert not (parent / 'apktool/decoded').exists()
        assert not (project / 'app/src/main/assets/key').exists(), 'Source archive must not include key assets'
        for entry in packaged['files']:
            assert sha(project / entry['path']) == entry['sha256']
        commands = [
            ['python3', 'scripts/build_source.py'],
            ['sh', 'evidence/business/run_tests.sh'],
            ['sh', 'evidence/logic/run_tests.sh'],
            ['sh', 'evidence/round2/callbacks/run_tests.sh'],
            ['sh', 'evidence/round2/models/run_tests.sh'],
            ['sh', 'evidence/round3/integration/run_tests.sh'],
            ['sh', 'evidence/round3/mint/run_tests.sh'],
            ['sh', 'evidence/round3/datetime/run_tests.sh'],
            ['sh', 'evidence/round3/simd/run_tests.sh'],
            ['sh', 'evidence/round3/numeric_json/run_tests.sh'],
        ]
        results = []
        logs = []
        for command in commands:
            result = subprocess.run(command, cwd=project, text=True, capture_output=True)
            logs.extend(['COMMAND: ' + ' '.join(command), result.stdout, result.stderr])
            (DIST / 'standalone-build.log').write_text('\n'.join(logs))
            observed = {'command': command, 'exit_code': result.returncode, 'summaries': [], 'suite_results': []}
            # Preserve actual suite counts/results, rather than hard-code stale totals.
            for line in result.stdout.splitlines():
                if line.startswith('{'):
                    try: observed['suite_results'].append(json.loads(line))
                    except json.JSONDecodeError: pass
                elif line.startswith('PASS'): observed['summaries'].append(line)
            results.append(observed)
            if result.returncode:
                raise RuntimeError('Standalone command failed: ' + ' '.join(command))
        rebuilt = json.loads((project / 'dist/source-build.json').read_text())
        tested = json.loads((DIST / 'source-build.json').read_text())
        assert rebuilt['sources'] == tested['sources']
        with zipfile.ZipFile(project / 'dist/xcs-source-rebuild-debug.apk') as new, \
                zipfile.ZipFile(DIST / 'xcs-source-rebuild-debug.apk') as tested_apk:
            dex_names = sorted(n for n in new.namelist() if n.endswith('.dex'))
            assert dex_names == sorted(n for n in tested_apk.namelist() if n.endswith('.dex'))
            for name in dex_names:
                assert new.read(name) == tested_apk.read(name), name
            asset_names = sorted(n for n in new.namelist() if n.startswith('assets/') and not n.startswith('assets/key/') and not n.endswith('/'))
            assert asset_names == sorted(n for n in tested_apk.namelist() if n.startswith('assets/') and not n.startswith('assets/key/') and not n.endswith('/'))
            for name in asset_names:
                assert new.read(name) == tested_apk.read(name), name
            private_name = 'assets/key/private_key.pem'
            assert private_name in new.namelist() and private_name in tested_apk.namelist()
            assert new.read(private_name) != tested_apk.read(private_name), 'Standalone build must generate a fresh local key'
        report = {
            'status': 'PASS', 'archive_sha256': sha(package),
            'original_apk_available_to_standalone_build': False,
            'original_apktool_project_available': False,
            'commands': results, 'compiled_java_input_files': len(rebuilt['sources']),
            'compiled_inputs_identical_to_local_sdk_build': True,
            'all_dex_bytes_identical_to_local_sdk_apk': True,
            'all_non_key_assets_identical_to_local_sdk_apk': True,
            'new_debug_signing_key_generated': True,
            'new_local_rsa_fixture_pair_generated': True, 'source_archive_contains_keys': False,
            'original_source_recovered': False, 'complete_behavioral_equivalence': False,
            'scope': 'Independent public source ZIP extraction, SDK build/sign verification and host core tests. Public adaptation has not been executed on the emulator.'
        }
        (DIST / 'standalone-build-verification.json').write_text(json.dumps(report, ensure_ascii=False, indent=2) + '\n')
        print(json.dumps(report, ensure_ascii=False))

if __name__ == '__main__':
    main()
