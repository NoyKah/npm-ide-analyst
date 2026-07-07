// src/npm_ide_analyst/sandbox/harness/eval-scope.js
'use strict';
const path = require('path');
const { createRequire } = require('module');
const { emit } = require('./emit.js');

// The eval/Function hooks in preload.js run decoded payloads via INDIRECT eval,
// which executes in global scope. There, CommonJS `require`/`module`/`exports`
// don't exist, so an obfuscated loader that evals code using require() aborts
// with "require is not defined" — hiding all downstream behavior (the real C2
// beacon, dropped files, etc.). To preserve detonation fidelity we publish a
// sample-bound `require` and a `module`/`exports` on the global object, so
// eval'd payloads resolve builtins + sample modules and keep executing.
//
// Normal module-local `require` is lexically scoped and unaffected by this;
// only code with no lexical `require` (i.e. eval'd/global code) falls back here.
function installEvalScope(dir) {
  try {
    const sampleRequire = createRequire(path.join(dir, 'index.js'));
    globalThis.require = sampleRequire;
    globalThis.module = { exports: {} };
    globalThis.exports = globalThis.module.exports;
    globalThis.__filename = path.join(dir, 'index.js');
    globalThis.__dirname = dir;
  } catch (e) {
    emit('detonation', `eval-scope setup failed: ${e && e.message}`, {});
  }
}

module.exports = { installEvalScope };
