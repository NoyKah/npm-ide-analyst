// src/npm_ide_analyst/sandbox/harness/run-npm.js
'use strict';
const path = require('path');
const fs = require('fs');
const { emit } = require('./emit.js');
const { resolveWithin } = require('./resolve-within.js');

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
      const target = resolveWithin(dir, m[1]);
      if (!target) {
        emit('detonation', `blocked require outside sample: ${path.resolve(dir, m[1])}`, { hook, rel: m[1] });
        continue;
      }
      try { require(target); }
      catch (e) { emit('detonation', `lifecycle ${hook} error: ${e && e.message}`, {}); }
    }
  }
  if (manifest.main) {
    const target = resolveWithin(dir, manifest.main);
    if (!target) {
      emit('detonation', `blocked require outside sample: ${path.resolve(dir, manifest.main)}`, { rel: manifest.main });
    } else {
      try { require(target); }
      catch (e) { emit('detonation', `main error: ${e && e.message}`, {}); }
    }
  }
  emit('detonation', 'npm detonation end', {});
}
main();
setTimeout(() => process.exit(0), 200);
