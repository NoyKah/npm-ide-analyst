// src/npm_ide_analyst/sandbox/harness/preload-bun.js
// Bun entrypoint (injected via `bun --preload`). Shares hooks-core.js and adds
// Bun-native hooks (Bun.spawn*, global fetch) that node-compat hooks don't cover.
'use strict';
const { reexecPlan, runReexec } = require('./hooks-core.js');
const { emit } = require('./emit.js');

// --- Bun.spawn / Bun.spawnSync: allow-listed re-exec, else log + neuter ---
if (typeof globalThis.Bun !== 'undefined' && Bun && typeof Bun.spawn === 'function') {
  const wrap = (name, sync) => {
    const orig = Bun[name];
    if (typeof orig !== 'function') return;
    Bun[name] = function (cmd, opts) {
      // Bun.spawn(["bun","x.js"], opts) or Bun.spawn({cmd:["bun","x.js"], ...}).
      const argv = Array.isArray(cmd) ? cmd.map(String)
                 : (cmd && Array.isArray(cmd.cmd)) ? cmd.cmd.map(String) : [];
      const plan = reexecPlan(argv[0], argv.slice(1));
      if (plan) {
        // runReexec uses node child_process (also hooked under bun) so events
        // and child-registry/waitForChildren behave identically. Its return
        // value is node-shaped, so adapt it to Bun.spawn/spawnSync's contract.
        if (sync) {
          const out = runReexec(plan, { sync: true, callerEnv: opts && opts.env });
          return { exitCode: 0, stdout: out, stderr: Buffer.from(''), success: true };
        }
        const child = runReexec(plan, { sync: false, callerEnv: opts && opts.env });
        return {
          pid: child.pid,
          exited: new Promise((resolve) => {
            child.on('exit', (code) => resolve(code == null ? 0 : code));
            child.on('error', () => resolve(1));
          }),
          kill: (sig) => child.kill(sig),
          stdout: null,
          stderr: null,
        };
      }
      emit('process', `Bun.${name}: ${JSON.stringify(argv[0])}`, { fn: `Bun.${name}`, args: argv.slice(0, 2) });
      // Neuter: return a benign stub with the shape callers expect.
      if (sync) return { exitCode: 0, stdout: Buffer.from(''), stderr: Buffer.from(''), success: true };
      return { pid: -1, exited: Promise.resolve(0), kill() {}, stdout: null, stderr: null };
    };
  };
  wrap('spawn', false);
  wrap('spawnSync', true);
}

// --- global fetch: log + (neuter | sinkhole-delegate) ---
if (typeof globalThis.fetch === 'function') {
  const origFetch = globalThis.fetch;
  globalThis.fetch = function (input, init) {
    const url = typeof input === 'string' ? input : (input && input.url) || String(input);
    emit('network', `fetch: ${url}`, { scheme: 'fetch', url: String(url) });
    if (process.env.ANALYST_SINKHOLE) {
      return origFetch(input, init); // real fetch -> sinkhole captures the dialog
    }
    return Promise.reject(new Error('network neutered')); // no socket opened
  };
}
