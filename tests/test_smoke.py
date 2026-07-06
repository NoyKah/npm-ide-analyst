import npm_ide_analyst


def test_package_has_version():
    assert isinstance(npm_ide_analyst.__version__, str)
    assert npm_ide_analyst.__version__
