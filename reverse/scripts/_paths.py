"""Local-input configuration for the published analysis tools."""
import os
import shutil
from pathlib import Path


def app_root():
    value = os.environ.get("XCS_REVERSE_APP_ROOT")
    if not value:
        raise RuntimeError("Set XCS_REVERSE_APP_ROOT to your external APP input directory; see reverse/README.md")
    return Path(value).expanduser().resolve()


def workspace_root():
    app = app_root()
    if app.name != "APP":
        raise RuntimeError("Tools using workspace_root require XCS_REVERSE_APP_ROOT to name an APP directory")
    return app.parent


def study_root():
    value = os.environ.get("XCS_REVERSE_STUDY_ROOT")
    return Path(value).expanduser().resolve() if value else app_root() / "external/software-project-study"


def java_home():
    value = os.environ.get("JAVA_HOME")
    if value:
        return Path(value).expanduser().resolve()
    compiler = shutil.which("javac")
    if not compiler:
        raise RuntimeError("Install a JDK and set JAVA_HOME")
    return Path(compiler).resolve().parent.parent
