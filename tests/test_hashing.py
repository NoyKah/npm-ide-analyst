import hashlib
from npm_ide_analyst.acquire.hashing import hash_file


def test_hash_file(tmp_path):
    p = tmp_path / "blob.bin"
    data = b"malicious-payload-bytes"
    p.write_bytes(data)
    sha256, sha512 = hash_file(p)
    assert sha256 == hashlib.sha256(data).hexdigest()
    assert sha512 == hashlib.sha512(data).hexdigest()
