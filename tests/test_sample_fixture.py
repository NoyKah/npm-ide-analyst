"""The persisted `colorz-utill` lab sample builds and analyzes as malicious.

Static-only (no Docker required) so it runs in any CI: guards both the sample
builder and the verdict-escalation logic against regressions.
"""
import importlib.util
from pathlib import Path

from npm_ide_analyst.acquire.unpack import unpack, detect_artifact_type
from npm_ide_analyst.models import ArtifactType
from npm_ide_analyst.static.engine import run_static
from npm_ide_analyst.models import Report, Sample

BUILD = Path("samples/colorz-utill/build.py")


def _load_builder():
    spec = importlib.util.spec_from_file_location("colorz_build", BUILD)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def test_sample_builds_and_scores_malicious(tmp_path):
    builder = _load_builder()
    tgz = builder.build(tmp_path)
    assert tgz.exists()

    payload_root = unpack(tgz, tmp_path / "work")
    assert detect_artifact_type(payload_root) == ArtifactType.NPM

    findings = run_static(payload_root)
    categories = {f.category for f in findings}
    # the sample is built to trip these detectors statically
    for expected in {"lifecycle-script", "process-exec", "network",
                     "secret-access", "exfil-channel", "registry-override",
                     "dynamic-code", "obfuscation"}:
        assert expected in categories, f"missing detector: {expected}"

    sample = Sample(name="colorz-utill", version="2.3.9",
                    artifact_type=ArtifactType.NPM, root=payload_root,
                    sha256="", sha512="")
    report = Report(sample=sample, findings=findings, generated_at="t")
    assert report.verdict == "malicious"
