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
