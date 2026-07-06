from __future__ import annotations

import json
import shutil
import tarfile
import zipfile
from pathlib import Path

from ..models import ArtifactType


def _safe_extract_zip(zf: zipfile.ZipFile, dest: Path) -> None:
    for member in zf.namelist():
        target = (dest / member).resolve()
        if not str(target).startswith(str(dest.resolve())):
            raise ValueError(f"unsafe zip path: {member}")
    zf.extractall(dest)


def _safe_extract_tar(tf: tarfile.TarFile, dest: Path) -> None:
    for member in tf.getmembers():
        target = (dest / member.name).resolve()
        if not str(target).startswith(str(dest.resolve())):
            raise ValueError(f"unsafe tar path: {member.name}")
    tf.extractall(dest)


def unpack(input_path: Path, workdir: Path) -> Path:
    workdir.mkdir(parents=True, exist_ok=True)
    extracted = workdir / "extracted"
    if input_path.is_dir():
        if extracted.exists():
            shutil.rmtree(extracted)
        shutil.copytree(input_path, extracted)
        return extracted
    suffix = input_path.suffix.lower()
    if suffix == ".vsix" or suffix == ".zip":
        with zipfile.ZipFile(input_path) as zf:
            _safe_extract_zip(zf, extracted)
        ext_dir = extracted / "extension"
        return ext_dir if ext_dir.is_dir() else extracted
    if suffix in (".tgz", ".gz") or input_path.name.endswith(".tar.gz"):
        with tarfile.open(input_path, "r:gz") as tf:
            _safe_extract_tar(tf, extracted)
        pkg_dir = extracted / "package"
        return pkg_dir if pkg_dir.is_dir() else extracted
    raise ValueError(f"unsupported input type: {input_path.name}")


def detect_artifact_type(payload_root: Path) -> ArtifactType:
    manifest = payload_root / "package.json"
    if not manifest.exists():
        return ArtifactType.UNKNOWN
    try:
        data = json.loads(manifest.read_text(encoding="utf-8", errors="replace"))
    except json.JSONDecodeError:
        return ArtifactType.UNKNOWN
    engines = data.get("engines") or {}
    if "vscode" in engines or "activationEvents" in data or "contributes" in data:
        return ArtifactType.EXTENSION
    return ArtifactType.NPM
