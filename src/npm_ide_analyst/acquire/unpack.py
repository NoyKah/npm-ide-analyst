from __future__ import annotations

import json
import shutil
import tarfile
import zipfile
from pathlib import Path

from ..models import ArtifactType


def _safe_extract_zip(zf: zipfile.ZipFile, dest: Path) -> None:
    dest_resolved = dest.resolve()
    for member in zf.namelist():
        target = (dest / member).resolve()
        try:
            target.relative_to(dest_resolved)
        except ValueError:
            raise ValueError(f"unsafe zip path: {member}")
    zf.extractall(dest)


def _safe_extract_tar(tf: tarfile.TarFile, dest: Path) -> None:
    dest_resolved = dest.resolve()
    for member in tf.getmembers():
        target = (dest / member.name).resolve()
        try:
            target.relative_to(dest_resolved)
        except ValueError:
            raise ValueError(f"unsafe tar path: {member.name}")
    tf.extractall(dest)


def find_payload_root(root: Path) -> Path:
    """Locate the analyzed package's directory within an extracted tree.

    Samples don't always have package.json at the top: npm tarballs wrap it in
    package/, VSIX in extension/, and real-world samples arrive arbitrarily nested
    (e.g. .../tiaan/package/package.json). Assuming the top level breaks both
    artifact-type detection and detonation. Resolve the real root here.
    """
    # Fast paths: manifest at the top, or a conventional wrapper directory.
    if (root / "package.json").exists():
        return root
    for wrapper in ("package", "extension"):
        if (root / wrapper / "package.json").exists():
            return root / wrapper
    # Otherwise find the shallowest package.json that isn't a bundled dependency
    # (node_modules); that's the package actually being analyzed.
    candidates = [p for p in root.rglob("package.json")
                  if "node_modules" not in p.parts]
    if not candidates:
        return root
    candidates.sort(key=lambda p: (
        len(p.relative_to(root).parts),
        0 if p.parent.name in ("package", "extension") else 1,
        str(p),
    ))
    return candidates[0].parent


def unpack(input_path: Path, workdir: Path) -> Path:
    workdir.mkdir(parents=True, exist_ok=True)
    extracted = workdir / "extracted"
    if input_path.is_dir():
        if extracted.exists():
            shutil.rmtree(extracted)
        shutil.copytree(input_path, extracted)
    else:
        suffix = input_path.suffix.lower()
        if suffix in (".vsix", ".zip"):
            with zipfile.ZipFile(input_path) as zf:
                _safe_extract_zip(zf, extracted)
        elif suffix in (".tgz", ".gz") or input_path.name.endswith(".tar.gz"):
            with tarfile.open(input_path, "r:gz") as tf:
                _safe_extract_tar(tf, extracted)
        else:
            raise ValueError(f"unsupported input type: {input_path.name}")
    return find_payload_root(extracted)


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
