// src/npm_ide_analyst/sandbox/harness/emit.js
'use strict';
const fs = require('fs');
const { performance } = require('perf_hooks');

const LOG = process.env.ANALYST_EVENT_LOG;
// Write the log line via fs.writeSync on a raw fd, never via
// appendFileSync/writeFileSync. Those are hooked (neutered/logged) by
// preload.js, and Node's own appendFileSync implementation internally calls
// back into fs.writeFileSync on the same shared module object — so routing
// through them would either recurse into emit() forever or get the log
// write silently neutered by the write-hook. fs.openSync/writeSync/closeSync
// are left unpatched, so they're a safe, direct path to disk.
function rawAppend(path, line) {
  const fd = fs.openSync(path, 'a');
  try {
    fs.writeSync(fd, line);
  } finally {
    fs.closeSync(fd);
  }
}

function emit(kind, detail, data) {
  const rec = {
    kind,
    detail: String(detail).slice(0, 2000),
    data: data || {},
    ts: performance.now(),
    stack: (new Error().stack || '').split('\n').slice(2, 5).join(' | ').slice(0, 500),
  };
  const line = JSON.stringify(rec) + '\n';
  try {
    if (LOG) rawAppend(LOG, line);
    else process.stdout.write(line);
  } catch (_) { /* never let logging throw into the payload */ }
}

module.exports = { emit };
