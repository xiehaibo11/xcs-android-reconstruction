"""Discover local build prerequisites without a developer-specific absolute path."""
from pathlib import Path
import os
import shutil
import subprocess
import sys

def jdk_bin():
    candidates = []
    if os.environ.get('JAVA_HOME'):
        candidates.append(Path(os.environ['JAVA_HOME']) / 'bin')
    javac = shutil.which('javac')
    if javac:
        candidates.append(Path(javac).parent)
    if sys.platform == 'darwin' and Path('/usr/libexec/java_home').exists():
        result = subprocess.run(['/usr/libexec/java_home'], capture_output=True, text=True)
        if result.returncode == 0:
            candidates.append(Path(result.stdout.strip()) / 'bin')
    for candidate in candidates:
        if all((candidate / tool).is_file() for tool in ('java', 'javac', 'jar', 'keytool')):
            check = subprocess.run([str(candidate / 'javac'), '-version'], capture_output=True)
            if check.returncode == 0:
                return candidate
    raise RuntimeError('Set JAVA_HOME to a JDK 17 or newer, or put JDK tools on PATH.')

def android_sdk():
    candidates = [Path(os.environ[name]) for name in ('ANDROID_SDK_ROOT', 'ANDROID_HOME') if os.environ.get(name)]
    candidates.extend([Path.home() / 'Library/Android/sdk', Path.home() / 'Android/Sdk'])
    if os.environ.get('LOCALAPPDATA'):
        candidates.append(Path(os.environ['LOCALAPPDATA']) / 'Android/Sdk')
    for candidate in candidates:
        if (candidate / 'platforms/android-35/android.jar').is_file():
            return candidate
    raise RuntimeError('Set ANDROID_SDK_ROOT to an Android SDK with platforms;android-35 installed.')

def build_tools(sdk):
    version = os.environ.get('ANDROID_BUILD_TOOLS')
    candidates = [sdk / 'build-tools' / version] if version else sorted(
        (sdk / 'build-tools').glob('*'), key=lambda p: tuple(int(n) if n.isdigit() else 0 for n in p.name.split('.')), reverse=True)
    for candidate in candidates:
        if all((candidate / tool).is_file() for tool in ('d8', 'aapt2', 'zipalign', 'apksigner')):
            return candidate
    raise RuntimeError('Install Android SDK Build Tools (tested with 37.0.0).')
