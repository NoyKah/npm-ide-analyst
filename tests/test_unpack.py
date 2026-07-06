import json
import tarfile
import zipfile
from pathlib import Path
import pytest
from npm_ide_analyst.acquire.unpack import unpack, detect_artifact_type
from npm_ide_analyst.models import ArtifactType


def _write_pkg_json(d: Path, extra: dict):
    d.mkdir(parents=True, exist_ok=True)
    (d / "package.json").write_text(json.dumps({"name": "x", "version": "1.0.0", **extra}))


def test_unpack_directory_npm(tmp_path):
    src = tmp_path / "pkg"
    _write_pkg_json(src, {})
    root = unpack(src, tmp_path / "work")
    assert (root / "package.json").exists()
    assert detect_artifact_type(root) == ArtifactType.NPM


def test_unpack_tgz_strips_package_dir(tmp_path):
    inner = tmp_path / "stage" / "package"
    _write_pkg_json(inner, {})
    tgz = tmp_path / "evil-1.0.0.tgz"
    with tarfile.open(tgz, "w:gz") as tf:
        tf.add(inner, arcname="package")
    root = unpack(tgz, tmp_path / "work")
    assert (root / "package.json").exists()


def test_unpack_vsix_detects_extension(tmp_path):
    stage = tmp_path / "stage" / "extension"
    _write_pkg_json(stage, {"engines": {"vscode": "^1.80.0"},
                            "activationEvents": ["*"]})
    vsix = tmp_path / "pub.evil-1.0.0.vsix"
    with zipfile.ZipFile(vsix, "w") as zf:
        zf.write(stage / "package.json", "extension/package.json")
    root = unpack(vsix, tmp_path / "work")
    assert detect_artifact_type(root) == ArtifactType.EXTENSION


def test_unpack_zip_rejects_traversal(tmp_path):
    stage = tmp_path / "stage"
    stage.mkdir()
    (stage / "e.txt").write_text("pwned")
    vsix = tmp_path / "evil.vsix"
    with zipfile.ZipFile(vsix, "w") as zf:
        zf.write(stage / "e.txt", "../escaped.txt")
    with pytest.raises(ValueError, match="unsafe zip path"):
        unpack(vsix, tmp_path / "work")


def test_unpack_tar_rejects_traversal(tmp_path):
    stage = tmp_path / "stage"
    stage.mkdir()
    src = stage / "e.txt"
    src.write_text("pwned")
    tgz = tmp_path / "evil.tgz"
    with tarfile.open(tgz, "w:gz") as tf:
        tf.add(src, arcname="../escaped.txt")
    with pytest.raises(ValueError, match="unsafe tar path"):
        unpack(tgz, tmp_path / "work")
