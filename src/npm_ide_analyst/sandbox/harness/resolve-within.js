// src/npm_ide_analyst/sandbox/harness/resolve-within.js
'use strict';
const path = require('path');

// Resolve `rel` against `dir` and return the absolute path ONLY if it stays
// inside `dir`. Returns null when the resolved target escapes the sample dir
// (e.g. a malicious manifest with "main": "../../../../etc/something").
//
// Containment is checked with path.relative: a target inside `dir` yields a
// relative path that neither starts with ".." (a parent-dir escape) nor is
// absolute (a different drive/root on Windows). The empty string (target === dir)
// is treated as contained.
function resolveWithin(dir, rel) {
  const base = path.resolve(dir);
  const target = path.resolve(base, rel);
  const relPath = path.relative(base, target);
  if (relPath === '..' || relPath.startsWith('..' + path.sep) || path.isAbsolute(relPath)) {
    return null;
  }
  return target;
}

module.exports = { resolveWithin };
