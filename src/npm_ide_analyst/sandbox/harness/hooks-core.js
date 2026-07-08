// src/npm_ide_analyst/sandbox/harness/hooks-core.js
// Shared detonation hooks, required by preload.js (node -r) and
// preload-bun.js (bun --preload).
'use strict';
const { emit } = require('./emit.js');
const { traceExec } = require('./trace.js');
const TRACE_NATIVE = process.env.ANALYST_TRACE_NATIVE === '1';

const path = require('path');
const { resolveWithin } = require('./resolve-within.js');
const SAMPLE_DIR = process.env.ANALYST_SAMPLE_DIR || '/work/sample';
const RUNTIMES = new Set(['bun', 'bunx', 'node', 'nodejs']);

// Real (unpatched) spawns captured before the child_process loop patches them.
const _realCp = require('child_process');
const REAL_SPAWN = _realCp.spawn;
const REAL_SPAWN_SYNC = _realCp.spawnSync;

// --- live re-exec'd children, awaited before the runner exits ---
const _children = [];
function registerChild(child) {
  _children.push(new Promise((resolve) => {
    let done = false;
    const fin = () => { if (!done) { done = true; resolve(); } };
    child.on('exit', fin);
    child.on('close', fin);
    child.on('error', fin);
  }));
}
async function waitForChildren(deadlineMs) {
  if (_children.length === 0) return;
  let timer;
  const deadline = new Promise((r) => { timer = setTimeout(r, Number(deadlineMs) || 8000); });
  await Promise.race([Promise.allSettled(_children), deadline]);
  clearTimeout(timer);
}

// Naive whitespace tokenizer for exec()/execSync() string commands.
function tokenize(cmdStr) {
  return String(cmdStr).trim().split(/\s+/).filter(Boolean);
}

// Decide whether (file, argv) is an allow-listed JS-runtime re-exec of an
// in-sample script. Returns a rewrite plan or null (=> stay neutered).
function reexecPlan(file, argv) {
  const base = path.basename(String(file || '')).replace(/\.exe$/i, '');
  if (!RUNTIMES.has(base)) return null;
  const args = Array.isArray(argv) ? argv.map(String) : [];
  const script = args.find((a) => !a.startsWith('-'));
  if (!script) return null;
  const target = resolveWithin(SAMPLE_DIR, script);
  if (!target) return null;
  const runtime = (base === 'bun' || base === 'bunx') ? 'bun' : 'node';
  // Derive preload paths from this file's dir so they resolve BOTH in-container
  // (/harness) and in the no-Docker unit test (repo .../harness). Replace the
  // (possibly relative) script arg with its absolute resolved path so the child
  // finds it regardless of its cwd.
  const inject = runtime === 'bun'
    ? ['--preload', path.join(__dirname, 'preload-bun.js')]
    : ['-r', path.join(__dirname, 'preload.js')];
  const idx = args.indexOf(script);
  const finalArgs = [...args.slice(0, idx), ...inject, target, ...args.slice(idx + 1)];
  return { runtime, file: base, args: finalArgs, target };
}

// Force our ANALYST_* env into the child regardless of caller-supplied env.
function childEnv(callerEnv) {
  const e = Object.assign({}, callerEnv || process.env);
  for (const k of ['ANALYST_SAMPLE_DIR', 'ANALYST_EVENT_LOG', 'ANALYST_SINKHOLE',
                   'ANALYST_TRACE_NATIVE', 'ANALYST_DETONATE_MS']) {
    if (process.env[k] !== undefined) e[k] = process.env[k];
  }
  return e;
}

// Actually run an allow-listed re-exec under our preload. stdio is forced so
// the child's event stream reaches us: in file-log mode it writes to the shared
// ANALYST_EVENT_LOG; in stream mode (ANALYST_EVENT_LOG="") emit -> stdout, which
// we inherit to the parent's stdout.
function runReexec(plan, { sync, callerEnv }) {
  const opts = { env: childEnv(callerEnv), stdio: ['ignore', 'inherit', 'inherit'] };
  emit('runtime-reexec', `${plan.runtime} ${plan.target}`,
       { runtime: plan.runtime, script: plan.target });
  if (sync) {
    REAL_SPAWN_SYNC(plan.file, plan.args, opts);
    return Buffer.from(''); // execSync/spawnSync callers expect a Buffer/result
  }
  const child = REAL_SPAWN(plan.file, plan.args, opts);
  registerChild(child);
  return child;
}

// When ANALYST_SINKHOLE is set, the detonation runs on an internet-less internal
// Docker network with a real sinkhole. Network hooks then LOG and DELEGATE to the
// real implementation so traffic reaches the sinkhole. Everything else stays neutered.
const SINKHOLE = !!process.env.ANALYST_SINKHOLE;

// --- child_process: allow-listed re-exec, else log + neuter ---
const cp = require('child_process');
for (const fn of ['exec', 'execSync', 'spawn', 'spawnSync', 'execFile', 'execFileSync', 'fork']) {
  if (typeof cp[fn] !== 'function') continue;
  const orig = cp[fn];
  const isSync = fn.endsWith('Sync');
  cp[fn] = function (...args) {
    // Derive (file, argv) for the allowlist check.
    let file = null;
    let argv = [];
    if (fn === 'exec' || fn === 'execSync') {
      const toks = tokenize(args[0]);
      file = toks[0];
      argv = toks.slice(1);
    } else if (fn !== 'fork') {
      file = args[0];
      argv = Array.isArray(args[1]) ? args[1] : [];
    }
    const plan = fn !== 'fork' ? reexecPlan(file, argv) : null;
    if (plan) {
      const callerOpts = args.find((a) => a && typeof a === 'object' && !Array.isArray(a));
      return runReexec(plan, { sync: isSync, callerEnv: callerOpts && callerOpts.env });
    }
    // Not allow-listed: existing behavior (log + trace-native | neuter).
    emit('process', `${fn}: ${JSON.stringify(args[0])}`, { fn, args: args.slice(0, 2) });
    if (TRACE_NATIVE && fn !== 'fork') {
      return traceExec(fn, args, orig);
    }
    if (isSync) return Buffer.from('');
    const cb = args.find((a) => typeof a === 'function');
    if (cb) process.nextTick(() => cb(null, '', ''));
    const { EventEmitter } = require('events');
    const stub = new EventEmitter();
    stub.stdout = new EventEmitter();
    stub.stderr = new EventEmitter();
    stub.kill = () => {};
    return stub;
  };
}

// --- network: http/https request/get: log + (neuter | delegate) ---
function hookHttp(mod, scheme) {
  for (const fn of ['request', 'get']) {
    const orig = mod[fn];
    if (typeof orig !== 'function') continue;
    mod[fn] = function (...args) {
      let url = args[0];
      if (typeof url === 'object' && url) {
        url = `${url.protocol || scheme + ':'}//${url.host || url.hostname}${url.path || ''}`;
      }
      emit('network', `${scheme} ${fn}: ${url}`, { scheme, url: String(url) });
      if (SINKHOLE) {
        return orig.apply(mod, args); // real request → sinkhole captures the dialog
      }
      const { EventEmitter } = require('events');
      const req = new EventEmitter();
      req.write = (chunk) => { emit('network', `body: ${chunk}`, { body: String(chunk).slice(0, 2000) }); return true; };
      req.end = () => {};
      req.setHeader = () => {};
      req.abort = () => {};
      return req; // neutered: never opens a socket
    };
  }
}
hookHttp(require('http'), 'http');
hookHttp(require('https'), 'https');

// --- net.Socket.connect: log + (neuter | delegate) ---
const net = require('net');
const origConnect = net.Socket.prototype.connect;
net.Socket.prototype.connect = function (...args) {
  const opt = args[0];
  const target = typeof opt === 'object' ? `${opt.host || opt.path}:${opt.port || ''}` : String(opt);
  emit('network', `socket connect: ${target}`, { target });
  if (SINKHOLE) {
    return origConnect.apply(this, args); // real connect → sinkhole
  }
  this.destroy && this.destroy();
  return this; // neutered
};

// --- dns: log; sinkhole -> real resolver (hits sinkhole via --dns), else synthetic ---
const dns = require('dns');
for (const fn of ['lookup', 'resolve', 'resolve4', 'resolve6']) {
  if (typeof dns[fn] !== 'function') continue;
  const orig = dns[fn];
  dns[fn] = function (host, ...rest) {
    emit('dns', `${fn}: ${host}`, { host });
    if (SINKHOLE) {
      return orig.apply(dns, [host, ...rest]); // real resolve → sinkhole DNS
    }
    const cb = rest.find((a) => typeof a === 'function');
    if (cb) process.nextTick(() => cb(null, fn === 'lookup' ? '127.0.0.1' : ['127.0.0.1']));
  };
}

// --- fs: log reads (flag sensitive), neuter writes ---
const fs = require('fs');
const SENSITIVE = /\.ssh|\.aws|\.npmrc|\.env|credentials|id_rsa|cookies|Login Data|\.docker/i;
function classify(p) { return SENSITIVE.test(String(p)) ? 'secret' : 'file'; }
for (const fn of ['readFile', 'readFileSync', 'createReadStream']) {
  const orig = fs[fn];
  if (typeof orig !== 'function') continue;
  fs[fn] = function (p, ...rest) {
    emit(classify(p), `${fn}: ${p}`, { path: String(p) });
    return orig.apply(fs, [p, ...rest]); // allow read (canary data planted by container)
  };
}
for (const fn of ['writeFile', 'writeFileSync', 'appendFileSync']) {
  const orig = fs[fn];
  if (typeof orig !== 'function') continue;
  fs[fn] = function (p, data, ...rest) {
    // Never let the payload write outside the tmp workdir; log intent, neuter absolute/escape paths.
    emit('file', `${fn}: ${p}`, { path: String(p), write: true });
    if (String(p).startsWith('/work/')) return orig.apply(fs, [p, data, ...rest]);
    return undefined; // neutered
  };
}

// --- decode helpers: log decoded payloads ---
const origBufFrom = Buffer.from;
Buffer.from = function (value, enc, ...rest) {
  if (enc === 'base64' && typeof value === 'string') {
    try {
      const decoded = origBufFrom.call(Buffer, value, 'base64').toString('utf8');
      if (/https?:|eval|require|process|child_process/i.test(decoded)) {
        emit('decode', `base64 -> ${decoded.slice(0, 300)}`, { decoded: decoded.slice(0, 2000) });
      }
    } catch (_) {}
  }
  return origBufFrom.call(Buffer, value, enc, ...rest);
};
if (typeof globalThis.atob === 'function') {
  const origAtob = globalThis.atob;
  globalThis.atob = function (s) {
    const out = origAtob(s);
    emit('decode', `atob -> ${out.slice(0, 300)}`, { decoded: out.slice(0, 2000) });
    return out;
  };
}

// --- eval / Function: log de-obfuscated code, then still run it ---
const origEval = globalThis.eval;
// NOTE: reassigning eval to a wrapper makes it an indirect eval (global scope) — acceptable here.
globalThis.eval = function (code) {
  emit('eval', `eval: ${String(code).slice(0, 300)}`, { code: String(code).slice(0, 2000) });
  return origEval(code);
};
const OrigFunction = globalThis.Function;
globalThis.Function = new Proxy(OrigFunction, {
  apply(target, thisArg, args) {
    emit('eval', `Function(): ${args.map(String).join(',').slice(0, 300)}`, { code: args.map(String).join(',').slice(0, 2000) });
    return Reflect.apply(target, thisArg, args);
  },
  construct(target, args) {
    emit('eval', `new Function(): ${args.map(String).join(',').slice(0, 300)}`, { code: args.map(String).join(',').slice(0, 2000) });
    return Reflect.construct(target, args);
  },
});

emit('harness', 'preload installed', {});

module.exports = { waitForChildren, reexecPlan, runReexec, registerChild };
