// src/npm_ide_analyst/sandbox/harness/run-vsix.js
'use strict';
const path = require('path');
const fs = require('fs');
const { emit } = require('./emit.js');
const { resolveWithin } = require('./resolve-within.js');
const { makeContext } = require('./vscode-mock.js');
const { installEvalScope } = require('./eval-scope.js');

async function main() {
  const dir = process.env.ANALYST_SAMPLE_DIR || '/work/sample';
  emit('detonation', 'vsix detonation start', { dir });
  installEvalScope(dir);
  let manifest = {};
  try { manifest = JSON.parse(fs.readFileSync(path.join(dir, 'package.json'), 'utf8')); }
  catch (e) { emit('detonation', 'no package.json', {}); }
  const mainRel = manifest.main || './extension.js';
  const target = resolveWithin(dir, mainRel);
  if (!target) {
    emit('detonation', `blocked require outside sample: ${path.resolve(dir, mainRel)}`, { rel: mainRel });
    emit('detonation', 'vsix detonation end', {});
    return;
  }
  try {
    const mod = require(target);
    if (mod && typeof mod.activate === 'function') {
      emit('detonation', 'calling activate()', {});
      await Promise.resolve(mod.activate(makeContext()));
    } else {
      emit('detonation', 'no activate() export', {});
    }
  } catch (e) {
    emit('detonation', `error: ${e && e.message}`, {});
  }
  emit('detonation', 'vsix detonation end', {});
}
main().then(() => setTimeout(() => process.exit(0), 200));
