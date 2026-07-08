import shutil
import subprocess

import pytest

from npm_ide_analyst.sandbox.orchestrator import IMAGE_TAG, build_image, docker_available

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
