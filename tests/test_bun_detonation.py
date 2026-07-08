import shutil
import subprocess
from pathlib import Path

import pytest

from npm_ide_analyst.models import ArtifactType
from npm_ide_analyst.sandbox.orchestrator import IMAGE_TAG, build_image, docker_available, detonate

pytestmark = pytest.mark.skipif(not docker_available(), reason="docker unavailable")


@pytest.fixture(scope="module")
def image():
    build_image(assume_docker=True)
    return IMAGE_TAG


def test_bun_is_installed_in_image(image):
    r = subprocess.run(
        ["docker", "run", "--rm", "--entrypoint", "bun", image, "--version"],
        capture_output=True, timeout=60, text=True,
    )
    assert r.returncode == 0, r.stderr
    assert r.stdout.strip(), "bun --version produced no output"


FIXTURE = Path("tests/fixtures/bun_loader")


def test_bun_payload_is_detonated_under_instrumentation(image):
    events = detonate(FIXTURE, ArtifactType.NPM, timeout=30, assume_docker=True)
    kinds = {(e.kind, e.detail) for e in events}
    # The re-exec into bun is announced...
    assert any(k == "runtime-reexec" and "bun" in d for k, d in kinds), \
        f"no bun runtime-reexec captured; got {sorted(kinds)}"
    # ...and the bun PAYLOAD's own behavior (secret read under bun) was captured,
    # proving the payload ran hooked rather than invisibly.
    assert any(e.kind in ("secret", "file") and "credentials" in e.detail
               for e in events), "bun payload's secret read was not captured"


def test_bun_payload_network_is_captured_and_neutered(image):
    # --network none: the payload's fetch is logged (visibility) but never opens
    # a socket. We assert the fetch target was recorded.
    events = detonate(FIXTURE, ArtifactType.NPM, timeout=30, assume_docker=True)
    assert any(e.kind == "network" and "c2.example.test" in e.detail
               for e in events), "bun payload's fetch target was not captured"
