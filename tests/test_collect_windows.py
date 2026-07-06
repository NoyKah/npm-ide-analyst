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
