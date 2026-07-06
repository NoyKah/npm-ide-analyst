from __future__ import annotations

import json
import os
from datetime import datetime, timezone
from pathlib import Path

import click

from .acquire.collect_windows import collect as collect_artifacts
from .acquire.hashing import hash_file
from .acquire.unpack import detect_artifact_type, unpack
from .correlate.timeline import build_timeline
from .models import Report, Sample
from .report.html_report import write_html
from .report.json_report import load_report, write_json
from .sandbox.findings import behavior_to_findings
from .sandbox.orchestrator import (
    SandboxUnavailable, build_image, detonate, docker_available,
)
from .static.engine import run_static


def _now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


@click.group()
def cli() -> None:
    """DFIR triage for malicious npm packages and IDE extensions."""


@cli.command()
@click.argument("input_path", type=click.Path(exists=True, path_type=Path))
@click.option("--out", "out_dir", required=True, type=click.Path(path_type=Path))
@click.option("--dynamic/--no-dynamic", default=False,
              help="Detonate the sample in a hardened Docker sandbox.")
def analyze(input_path: Path, out_dir: Path, dynamic: bool) -> None:
    """Static analysis of a .vsix, npm .tgz, or directory."""
    out_dir.mkdir(parents=True, exist_ok=True)
    work = out_dir / "_work"
    payload_root = unpack(input_path, work)
    manifest = json.loads(
        (payload_root / "package.json").read_text(encoding="utf-8", errors="replace")
    ) if (payload_root / "package.json").exists() else {}
    sha256, sha512 = hash_file(input_path) if input_path.is_file() else ("", "")
    sample = Sample(
        name=manifest.get("name", input_path.stem),
        version=manifest.get("version"),
        artifact_type=detect_artifact_type(payload_root),
        root=payload_root, sha256=sha256, sha512=sha512,
    )
    findings = run_static(payload_root)
    behavior = []
    timeline = []
    if dynamic:
        if not docker_available():
            click.echo("WARNING: --dynamic requested but Docker is unavailable; "
                       "running static-only.", err=True)
        else:
            build_image()
            behavior = detonate(payload_root, sample.artifact_type)
            findings = findings + behavior_to_findings(behavior)
            timeline = build_timeline(behavior)
    report = Report(sample=sample, findings=findings, generated_at=_now(),
                    behavior=behavior, timeline=timeline)
    write_json(report, out_dir / "report.json")
    write_html(report, out_dir / "report.html")
    click.echo(f"verdict={report.verdict} score={report.score} "
               f"findings={len(findings)} -> {out_dir}")


@cli.command()
@click.option("--out", "out_dir", required=True, type=click.Path(path_type=Path))
def collect(out_dir: Path) -> None:
    """Read-only collection of DFIR artifacts from this Windows host."""
    out_dir.mkdir(parents=True, exist_ok=True)
    profile = Path(os.environ.get("USERPROFILE", str(Path.home())))
    appdata = Path(os.environ.get("APPDATA", str(profile / "AppData" / "Roaming")))
    local = Path(os.environ.get("LOCALAPPDATA", str(profile / "AppData" / "Local")))
    manifest = collect_artifacts(out_dir / "artifacts", profile, appdata, local)
    (out_dir / "manifest.json").write_text(json.dumps(manifest, indent=2), encoding="utf-8")
    click.echo(f"collected {len(manifest)} files -> {out_dir}")


@cli.command(name="report")
@click.argument("json_path", type=click.Path(exists=True, path_type=Path))
@click.option("--out", "out_path", required=True, type=click.Path(path_type=Path))
def report_cmd(json_path: Path, out_path: Path) -> None:
    """Re-render HTML from a saved report.json."""
    rpt = load_report(json_path)
    write_html(rpt, out_path)
    click.echo(f"rendered {out_path}")
