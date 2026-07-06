// src/npm_ide_analyst/sandbox/harness/run-npm.js
'use strict';
const path = require('path');
const fs = require('fs');
const { emit } = require('./emit.js');

function main() {
  const dir = process.env.ANALYST_SAMPLE_DIR || '/work/sample';
  emit('detonation', 'npm detonation start', { dir });
  let manifest = {};
  try { manifest = JSON.parse(fs.readFileSync(path.join(dir, 'package.json'), 'utf8')); }
  catch (e) { emit('detonation', 'no package.json', {}); }

  const scripts = manifest.scripts || {};
  for (const hook of ['preinstall', 'install', 'postinstall']) {
    const cmd = scripts[hook];
    if (!cmd) continue;
    emit('detonation', `lifecycle ${hook}: ${cmd}`, { hook, cmd });
    const m = /node\s+(\S+)/.exec(cmd);
    if (m) {
      try { require(path.resolve(dir, m[1])); }
      catch (e) { emit('detonation', `lifecycle ${hook} error: ${e && e.message}`, {}); }
    }
  }
  if (manifest.main) {
    try { require(path.resolve(dir, manifest.main)); }
    catch (e) { emit('detonation', `main error: ${e && e.message}`, {}); }
  }
  emit('detonation', 'npm detonation end', {});
}
main();
setTimeout(() => process.exit(0), 200);
