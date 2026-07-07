// src/npm_ide_analyst/sandbox/harness/trace.js
'use strict';
// Runs an attempted child_process exec under strace (opt-in --trace-native
// mode only). Emits a `native` event (command + exit) and bounded `syscall`
// events. Uses the ORIGINAL, unhooked child_process fns passed in as origFn,
// and reads the strace output via unhooked fs.openSync/readSync/closeSync so
// the fs hooks in preload.js do not fire on our own trace file.
const fs = require('fs');
const { spawnSync } = require('child_process');
const { emit } = require('./emit.js');

const MAX_SYSCALL_EVENTS = 200;
const PER_NAME_CAP = 25;
// Syscalls worth surfacing for triage:
const NOTABLE = new Set([
  'execve', 'execveat', 'connect', 'socket', 'bind', 'sendto', 'sendmsg',
  'open', 'openat', 'unlink', 'unlinkat', 'chmod', 'fchmod', 'fchmodat',
  'rename', 'renameat', 'ptrace', 'clone', 'fork', 'vfork', 'kill',
]);
const SENSITIVE = /\.ssh|\.aws|\.npmrc|\.env|credentials|id_rsa|cookies|Login Data|\.docker/i;

let _seq = 0;

// argv reconstruction per child_process function shape.
function toArgv(fnName, args) {
  const a0 = args[0];
  // exec / execSync: single command string run via the shell.
  if (fnName === 'exec' || fnName === 'execSync') {
    return ['/bin/sh', '-c', String(a0)];
  }
  // spawn / spawnSync / execFile / execFileSync: (file, [args], ...)
  const file = String(a0);
  const rest = Array.isArray(args[1]) ? args[1].map(String) : [];
  return [file, ...rest];
}

function rawRead(path) {
  const fd = fs.openSync(path, 'r');
  try {
    const chunks = [];
    const buf = Buffer.alloc(65536);
    let n;
    while ((n = fs.readSync(fd, buf, 0, buf.length, null)) > 0) {
      chunks.push(Buffer.from(buf.slice(0, n)));
    }
    return Buffer.concat(chunks).toString('utf8');
  } finally {
    fs.closeSync(fd);
  }
}

function parseAndEmit(traceText, argv) {
  const lines = traceText.split('\n');
  const counts = Object.create(null);
  let emitted = 0;
  // strace -f prefixes lines with a pid; capture the syscall name.
  const re = /^(?:\[pid\s+\d+\]\s+|\d+\s+)?(\w+)\(/;
  for (const line of lines) {
    if (emitted >= MAX_SYSCALL_EVENTS) {
      emit('syscall', `[truncated: >${MAX_SYSCALL_EVENTS} notable syscalls]`, {});
      break;
    }
    const m = re.exec(line);
    if (!m) continue;
    const name = m[1];
    if (!NOTABLE.has(name)) continue;
    counts[name] = (counts[name] || 0) + 1;
    if (counts[name] > PER_NAME_CAP) continue;
    const sensitive = SENSITIVE.test(line);
    const detail = line.trim().slice(0, 300);
    emit('syscall', `${name}: ${detail}`, {
      syscall: name,
      sensitive,
      argv: argv.slice(0, 3),
    });
    emitted += 1;
  }
}

function traceExec(fnName, args, origFn) {
  _seq += 1;
  const tracePath = `/tmp/analyst-trace-${process.pid}-${_seq}.log`;
  const argv = toArgv(fnName, args);
  // strace -f (follow forks) -qq (quiet) -o file -- <argv>
  const straceArgs = ['-f', '-qq', '-o', tracePath, '--', ...argv];
  let result;
  try {
    result = spawnSync('strace', straceArgs, {
      encoding: 'buffer',
      timeout: 20000,
      maxBuffer: 8 * 1024 * 1024,
    });
  } catch (e) {
    emit('native', `strace failed to launch: ${e && e.message}`, { argv });
    result = { status: null, stdout: Buffer.from(''), stderr: Buffer.from('') };
  }

  const exit = result && result.status;
  emit('native', `strace ${argv.join(' ').slice(0, 200)} -> exit ${exit}`, {
    argv, exit,
  });

  try {
    const traceText = rawRead(tracePath);
    parseAndEmit(traceText, argv);
  } catch (_) { /* trace file may be absent if strace never wrote it */ }
  try { fs.unlinkSync(tracePath); } catch (_) {}

  const stdout = (result && result.stdout) || Buffer.from('');

  // Shape the return value like the original function.
  if (fnName.endsWith('Sync')) {
    return stdout; // execSync/spawnSync/execFileSync callers expect stdout buffer
  }
  const { EventEmitter } = require('events');
  const stub = new EventEmitter();
  stub.stdout = new EventEmitter();
  stub.stderr = new EventEmitter();
  stub.kill = () => {};
  const cb = args.find((a) => typeof a === 'function');
  process.nextTick(() => {
    const out = stdout.toString('utf8');
    if (out) stub.stdout.emit('data', stdout);
    stub.stdout.emit('end');
    if (cb) cb(null, out, (result && result.stderr || Buffer.from('')).toString('utf8'));
    stub.emit('close', typeof exit === 'number' ? exit : 0);
    stub.emit('exit', typeof exit === 'number' ? exit : 0);
  });
  return stub;
}

module.exports = { traceExec };
