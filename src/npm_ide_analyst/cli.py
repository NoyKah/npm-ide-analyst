from __future__ import annotations

import json
import os
import subprocess
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path

import click

from .acquire.collect_windows import collect as collect_artifacts
from .acquire.hashing import hash_file
from .acquire.unpack import detect_artifact_type, unpack
from .correlate.timeline import build_timeline
from .debug import DebugCollector, stage
from .models import Report, Sample
from .report.html_report import write_html
from .report.json_report import load_report, write_json
from .sandbox.findings import behavior_to_findings
from .sandbox.orchestrator import (
    build_image, detonate, docker_available, image_exists,
)
from .static.engine import run_static
from .static.ioc_scan import iter_js_files

_DYNAMIC_LOC = "[dynamic]"


def _now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


def _progress(quiet: bool, msg: str) -> None:
    """Emit a stage progress line to stderr (stdout stays the machine result)."""
    if not quiet:
        click.echo(f"[*] {msg}", err=True)


@click.group()
def cli() -> None:
    """DFIR triage for malicious npm packages and IDE extensions."""


@cli.command()
@click.argument("input_path", type=click.Path(exists=True, path_type=Path))
@click.option("--out", "out_dir", required=True, type=click.Path(path_type=Path))
@click.option("--dynamic/--no-dynamic", default=False,
              help="Detonate the sample in a hardened Docker sandbox.")
@click.option("--sinkhole/--no-sinkhole", default=False,
              help="Detonate against a real DNS+HTTP(S) sinkhole on an internal, "
                   "internet-less network to capture live C2 dialog for "
                   "hostname-based traffic. Implies --dynamic.")
@click.option("--trace-native/--no-trace-native", default=False,
              help="Under --dynamic/--sinkhole: run dropped/native binaries under "
                   "strace (adds CAP_SYS_PTRACE, weakening isolation; executes "
                   "native payload code). Opt-in, default off.")
@click.option("--timeout", default=30, show_default=True, type=int,
              help="Detonation wall-clock timeout in seconds (per sample).")
@click.option("--rebuild-image", is_flag=True, default=False,
              help="Force a rebuild of the sandbox image (otherwise it is reused "
                   "if already built, so detonation needs no network).")
@click.option("--quiet", "-q", is_flag=True, default=False,
              help="Suppress progress output.")
@click.option("--debug", is_flag=True, default=False,
              help="Write debug.json (stage timings, raw harness event log, "
                   "container diagnostics, static + env info) for troubleshooting.")
def analyze(input_path: Path, out_dir: Path, dynamic: bool, sinkhole: bool,
            trace_native: bool, timeout: int, rebuild_image: bool, quiet: bool,
            debug: bool) -> None:
    """Static analysis of a .vsix, npm .tgz, or directory."""
    if trace_native and not (dynamic or sinkhole):
        raise click.UsageError(
            "--trace-native requires --dynamic or --sinkhole (it deepens "
            "detonation, which only runs with one of those).")
    out_dir.mkdir(parents=True, exist_ok=True)
    dbg = DebugCollector() if debug else None

    _progress(quiet, f"acquiring {input_path.name} ...")
    with stage(dbg, "acquire"):
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

    js_count = sum(1 for _ in iter_js_files(payload_root))
    _progress(quiet, f"static analysis of {sample.artifact_type} '{sample.name}' "
                     f"({js_count} JS files) ...")
    with stage(dbg, "static"):
        findings = run_static(payload_root)
    _progress(quiet, f"static analysis done: {len(findings)} findings")
    behavior = []
    timeline = []
    if dynamic or sinkhole:
        if not docker_available():
            click.echo("WARNING: dynamic/sinkhole requested but Docker is "
                       "unavailable; running static-only.", err=True)
        else:
            # Docker was just verified above; tell the sandbox helpers to trust
            # that rather than each re-running the ~15s `docker info` probe.
            try:
                remote_host = os.environ.get("DOCKER_HOST")
                if remote_host:
                    click.echo(f"NOTE: detonating on remote Docker daemon "
                               f"({remote_host}) via mount-free stream transport.",
                               err=True)
                    if sinkhole:
                        click.echo("WARNING: --sinkhole is not supported on a "
                                   "remote daemon; using isolated detonation.",
                                   err=True)
                if trace_native:
                    click.echo(
                        "WARNING: --trace-native adds CAP_SYS_PTRACE (weakening "
                        "container isolation) and EXECUTES native payload code "
                        "under strace. All other container limits hold. "
                        "Proceeding.", err=True)
                dyn_debug = dbg.data["dynamic"] if dbg is not None else None
                with stage(dbg, "detonation"):
                    if rebuild_image or not image_exists():
                        _progress(quiet, "building sandbox image (first run; needs "
                                         "network to pull the base image) ...")
                        build_image(assume_docker=True)
                    else:
                        _progress(quiet, "using cached sandbox image")
                    _progress(quiet, f"detonating in isolated sandbox "
                                     f"(timeout {timeout}s) ...")
                    behavior = detonate(payload_root, sample.artifact_type,
                                        timeout=timeout, assume_docker=True,
                                        sinkhole=sinkhole, trace_native=trace_native,
                                        debug=dyn_debug)
                _progress(quiet, f"detonation captured {len(behavior)} behavior events")
                findings = findings + behavior_to_findings(behavior)
                timeline = build_timeline(behavior)
                if sinkhole:
                    click.echo("NOTE: the sinkhole captures hostname-based C2; "
                               "hard-coded public IPs are not routed on the "
                               "internal network.", err=True)
            except Exception as exc:
                # Detonation is best-effort: any failure (Docker error, harness
                # crash, sinkhole provisioning failure) degrades to a static-only
                # report rather than aborting triage. Intentionally broad.
                if dbg is not None:
                    dbg.error("detonation", exc)
                # Surface the underlying command stderr (e.g. a docker build DNS
                # failure) instead of only the opaque "exit status 1".
                stderr = getattr(exc, "stderr", None)
                if isinstance(stderr, bytes):
                    stderr = stderr.decode("utf-8", "replace")
                detail = f": {stderr.strip()[:600]}" if stderr else ""
                click.echo(f"WARNING: detonation failed ({exc}){detail}; "
                           "continuing static-only.", err=True)
                behavior = []
                timeline = []

    _progress(quiet, "writing report ...")
    with stage(dbg, "report"):
        report = Report(sample=sample, findings=findings, generated_at=_now(),
                        behavior=behavior, timeline=timeline)
        write_json(report, out_dir / "report.json")
        write_html(report, out_dir / "report.html")

    if dbg is not None:
        _fill_debug(dbg, sample, payload_root, findings, behavior, report)
        dbg.write(out_dir / "debug.json")
    click.echo(f"verdict={report.verdict} score={report.score} "
               f"findings={len(findings)} -> {out_dir}")


def _fill_debug(dbg: DebugCollector, sample, payload_root: Path,
                findings, behavior, report) -> None:
    """Populate the sample / static / dynamic summary sections of the bundle."""
    dbg.data["sample"] = {
        "name": sample.name, "version": sample.version,
        "artifact_type": str(sample.artifact_type), "sha256": sample.sha256,
    }
    dbg.data["verdict"] = report.verdict
    dbg.data["score"] = report.score
    dbg.data["static"] = {
        "js_files_scanned": [str(p.relative_to(payload_root))
                             for p in iter_js_files(payload_root)],
        "ast_unparseable": [f.location for f in findings
                            if f.id.startswith("AST-UNPARSEABLE")],
        "findings_by_category": dict(Counter(f.category for f in findings)),
        "n_static": sum(1 for f in findings if f.location != _DYNAMIC_LOC),
        "n_dynamic": sum(1 for f in findings if f.location == _DYNAMIC_LOC),
    }
    dbg.data["dynamic"]["behavior_event_count"] = len(behavior)
    dbg.data["dynamic"]["decoded_strings"] = [
        b.detail for b in behavior if b.kind in ("decode", "eval")]


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


if __name__ == "__main__":
    cli()
