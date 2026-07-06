"""Safety regression test: static analysis never executes sample code.

This test verifies the core safety invariant: the static analysis pipeline
only performs static parsing and scanning of sample code as data. It should
never execute, require(), or dynamically evaluate any code from the sample.

We use a "canary" file: a malicious JS file that, if ever executed,
would write to a known path. By asserting this file is never created,
we prove static analysis never ran the code.
"""
import json
from pathlib import Path

from click.testing import CliRunner
from npm_ide_analyst.cli import cli
from npm_ide_analyst.static.engine import run_static


def test_static_engine_never_executes_sample_code(tmp_path):
    """Test run_static() never executes sample JS code."""
    # Prepare canary path: the JS will try to write here if executed
    canary_path = tmp_path / "canary_marker.txt"

    # Create a fake npm package with malicious-looking JS
    pkg = tmp_path / "pkg"
    pkg.mkdir()

    # Write package.json with a postinstall script
    (pkg / "package.json").write_text(
        json.dumps({
            "name": "safety-test-pkg",
            "version": "1.0.0",
            "scripts": {"postinstall": "node ./malicious.js"}
        })
    )

    # Write JS that would write the canary file if executed
    # This is valid JS that esprima can parse, but should never be run.
    canary_code = f"""
const fs = require('fs');
fs.writeFileSync('{canary_path}', 'pwned');
process.exit(0);
"""
    (pkg / "malicious.js").write_text(canary_code, encoding="utf-8")

    # Run the static engine: this should parse malicious.js as data,
    # analyze it for IOCs (network calls, process execution, etc.),
    # but NEVER execute it.
    findings = run_static(pkg)

    # Verify no execution: the canary file should not exist
    assert not canary_path.exists(), (
        "Safety invariant violated: static engine executed sample code "
        "(canary file was created)"
    )

    # Verify the engine still worked: it should have found findings
    # (lifecycle script, require fs, writeFileSync call, etc.)
    assert len(findings) > 0, (
        "Static engine produced no findings; it may have done nothing at all"
    )

    # Verify we detected the lifecycle script and code patterns
    categories = {f.category for f in findings}
    assert "lifecycle-script" in categories, (
        "Expected to detect postinstall lifecycle script"
    )


def test_cli_analyze_never_executes_sample_code(tmp_path):
    """Test CLI analyze command never executes sample JS code."""
    # Prepare canary path
    canary_path = tmp_path / "canary_marker_cli.txt"

    # Create a fake npm package
    pkg = tmp_path / "pkg"
    pkg.mkdir()

    (pkg / "package.json").write_text(
        json.dumps({
            "name": "safety-test-cli",
            "version": "2.0.0",
            "scripts": {"postinstall": "node ./evil.js"}
        })
    )

    # Malicious JS that would write the canary if executed
    canary_code = f"""
const fs = require('fs');
const path = require('path');
fs.writeFileSync('{canary_path}', 'pwned-cli');
"""
    (pkg / "evil.js").write_text(canary_code, encoding="utf-8")

    # Run the CLI analyze command
    out = tmp_path / "out"
    runner = CliRunner()
    result = runner.invoke(cli, ["analyze", str(pkg), "--out", str(out)])

    # Verify the CLI succeeded
    assert result.exit_code == 0, f"CLI failed: {result.output}"

    # Verify no execution: canary file should not exist
    assert not canary_path.exists(), (
        "Safety invariant violated: CLI executed sample code "
        "(canary file was created)"
    )

    # Verify the CLI still produced output
    assert (out / "report.json").exists(), "CLI did not produce report.json"
    assert (out / "report.html").exists(), "CLI did not produce report.html"

    # Verify findings were produced
    report_data = json.loads((out / "report.json").read_text())
    assert report_data["findings"], (
        "CLI produced no findings; it may not have analyzed the code"
    )
