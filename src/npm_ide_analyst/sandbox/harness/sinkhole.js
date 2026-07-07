// src/npm_ide_analyst/sandbox/harness/sinkhole.js
'use strict';
// Trusted sinkhole responder. Runs in its own container on an --internal Docker
// network. NO untrusted sample code runs here. Answers all DNS A queries with its
// own IP and all HTTP/HTTPS requests with a benign 200, logging each via emit.js.
const os = require('os');
const fs = require('fs');
const dgram = require('dgram');
const http = require('http');
const https = require('https');
const { emit } = require('./emit.js');

const DNS_PORT = parseInt(process.env.ANALYST_SINK_DNS_PORT || '53', 10);
const HTTP_PORT = parseInt(process.env.ANALYST_SINK_HTTP_PORT || '80', 10);
const HTTPS_PORT = parseInt(process.env.ANALYST_SINK_HTTPS_PORT || '443', 10);
const CERT = process.env.ANALYST_SINK_CERT || '/harness/sink-cert.pem';
const KEY = process.env.ANALYST_SINK_KEY || '/harness/sink-key.pem';

function ownIP() {
  const ifaces = os.networkInterfaces();
  for (const name of Object.keys(ifaces)) {
    for (const a of ifaces[name] || []) {
      if (a.family === 'IPv4' && !a.internal) return a.address;
    }
  }
  return '127.0.0.1';
}
const IP = ownIP();

// --- minimal DNS ---
function qname(msg) {
  let off = 12;
  const labels = [];
  while (off < msg.length && msg[off] !== 0) {
    const len = msg[off];
    labels.push(msg.slice(off + 1, off + 1 + len).toString('latin1'));
    off += len + 1;
  }
  return labels.join('.');
}

function dnsResponse(msg) {
  let off = 12;
  while (off < msg.length && msg[off] !== 0) off += msg[off] + 1;
  off += 1;                          // past the null terminator
  const qtype = msg.readUInt16BE(off);
  const qend = off + 4;              // qtype(2) + qclass(2)
  const question = msg.slice(12, qend);
  const header = Buffer.alloc(12);
  msg.copy(header, 0, 0, 2);         // echo transaction id
  header.writeUInt16BE(0x8180, 2);   // QR=1, RD=1, RA=1
  header.writeUInt16BE(1, 4);        // QDCOUNT
  const isA = qtype === 1;
  header.writeUInt16BE(isA ? 1 : 0, 6); // ANCOUNT
  if (!isA) return Buffer.concat([header, question]);
  const ans = Buffer.alloc(16);
  ans.writeUInt16BE(0xC00C, 0);      // name pointer -> offset 12
  ans.writeUInt16BE(1, 2);           // TYPE A
  ans.writeUInt16BE(1, 4);           // CLASS IN
  ans.writeUInt32BE(30, 6);          // TTL
  ans.writeUInt16BE(4, 10);          // RDLENGTH
  IP.split('.').forEach((o, i) => { ans[12 + i] = parseInt(o, 10) & 0xff; });
  return Buffer.concat([header, question, ans]);
}

function httpHandler(scheme) {
  return (req, res) => {
    const chunks = [];
    let size = 0;
    req.on('data', (c) => { size += c.length; if (size <= 65536) chunks.push(c); });
    req.on('end', () => {
      const body = Buffer.concat(chunks).toString('utf8').slice(0, 2000);
      const host = req.headers.host || '';
      emit('c2', `${scheme.toUpperCase()} ${req.method} ${host}${req.url}`, {
        scheme, method: req.method, host, path: req.url,
        headers: req.headers, body,
      });
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end('{"ok":true}');
    });
    req.on('error', () => { try { res.end(); } catch (_) {} });
  };
}

let pending = 0;
let done = 0;
let announced = false;
function announceIfReady() {
  if (!announced && done >= pending) {
    announced = true;
    process.stdout.write('SINKHOLE READY\n');
  }
}
function ready() {
  done += 1;
  announceIfReady();
}
function drop(what, e) {
  // A listener failed to bind (async 'error' or sync throw). Stop waiting on it,
  // and if the remaining listeners are already up, still signal readiness instead
  // of crashing (unhandled 'error') or hanging forever.
  process.stderr.write(`${what} disabled: ${(e && e.message) || e}\n`);
  pending -= 1;
  announceIfReady();
}

// DNS listener
pending += 1;
const udp = dgram.createSocket('udp4');
udp.on('message', (msg, rinfo) => {
  try {
    emit('dns', `query ${qname(msg)}`, { name: qname(msg), from: rinfo.address });
    udp.send(dnsResponse(msg), rinfo.port, rinfo.address);
  } catch (_) { /* never throw out of the responder */ }
});
udp.on('error', (e) => drop('dns', e));
udp.bind(DNS_PORT, () => ready());

// HTTP listener
pending += 1;
const httpSrv = http.createServer(httpHandler('http'));
httpSrv.on('error', (e) => drop('http', e));
httpSrv.listen(HTTP_PORT, () => ready());

// HTTPS listener (only if the baked cert is present)
if (fs.existsSync(CERT) && fs.existsSync(KEY)) {
  pending += 1;
  try {
    const opts = { cert: fs.readFileSync(CERT), key: fs.readFileSync(KEY) };
    const httpsSrv = https.createServer(opts, httpHandler('https'));
    httpsSrv.on('error', (e) => drop('https', e));
    httpsSrv.listen(HTTPS_PORT, () => ready());
  } catch (e) {
    drop('https', e);
  }
}
