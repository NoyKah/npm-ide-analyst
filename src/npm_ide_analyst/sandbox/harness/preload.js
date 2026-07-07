// src/npm_ide_analyst/sandbox/harness/preload.js
'use strict';
const { emit } = require('./emit.js');
const { traceExec } = require('./trace.js');
const TRACE_NATIVE = process.env.ANALYST_TRACE_NATIVE === '1';

// When ANALYST_SINKHOLE is set, the detonation runs on an internet-less internal
// Docker network with a real sinkhole. Network hooks then LOG and DELEGATE to the
// real implementation so traffic reaches the sinkhole. Everything else stays neutered.
const SINKHOLE = !!process.env.ANALYST_SINKHOLE;

// --- child_process: log + neuter ---
const cp = require('child_process');
for (const fn of ['exec', 'execSync', 'spawn', 'spawnSync', 'execFile', 'execFileSync', 'fork']) {
  if (typeof cp[fn] !== 'function') continue;
  const orig = cp[fn];
  cp[fn] = function (...args) {
    emit('process', `${fn}: ${JSON.stringify(args[0])}`, { fn, args: args.slice(0, 2) });
    // Opt-in native tracing: actually run the exec under strace (except fork,
    // which re-execs node and is not a native drop). Default: log + neuter.
    if (TRACE_NATIVE && fn !== 'fork') {
      return traceExec(fn, args, orig);
    }
    // Neuter: do not actually spawn. Return a benign stub.
    if (fn.endsWith('Sync')) return Buffer.from('');
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
