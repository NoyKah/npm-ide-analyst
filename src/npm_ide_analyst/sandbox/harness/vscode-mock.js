// src/npm_ide_analyst/sandbox/harness/vscode-mock.js
'use strict';
const Module = require('module');
const { emit } = require('./emit.js');

const disposable = { dispose() {} };

const vscode = {
  commands: {
    registerCommand: (id, fn) => { emit('vscode', `registerCommand: ${id}`, { id }); return disposable; },
    executeCommand: (id, ...a) => { emit('vscode', `executeCommand: ${id}`, { id }); return Promise.resolve(); },
  },
  window: {
    showInformationMessage: (m) => { emit('vscode', `showInformationMessage: ${m}`, {}); return Promise.resolve(); },
    showErrorMessage: (m) => { emit('vscode', `showErrorMessage: ${m}`, {}); return Promise.resolve(); },
    createOutputChannel: () => ({ appendLine() {}, show() {}, dispose() {} }),
  },
  workspace: {
    getConfiguration: () => ({ get: () => undefined, update: () => Promise.resolve() }),
    workspaceFolders: [],
    onDidChangeTextDocument: () => disposable,
  },
  env: {
    machineId: 'mock-machine', sessionId: 'mock-session',
    openExternal: (u) => { emit('vscode', `openExternal: ${u}`, { url: String(u) }); return Promise.resolve(true); },
    clipboard: { writeText: () => Promise.resolve(), readText: () => Promise.resolve('') },
  },
  Uri: { parse: (s) => ({ toString: () => s }), file: (s) => ({ fsPath: s }) },
  ExtensionMode: { Production: 1, Development: 2, Test: 3 },
};

function makeContext() {
  return {
    subscriptions: [],
    extensionPath: process.env.ANALYST_SAMPLE_DIR || '/work/sample',
    globalState: { get: () => undefined, update: () => Promise.resolve(), keys: () => [] },
    workspaceState: { get: () => undefined, update: () => Promise.resolve() },
    secrets: {
      get: (k) => { emit('vscode', `secrets.get: ${k}`, { key: k }); return Promise.resolve('mock-secret'); },
      store: (k, v) => { emit('secret', `secrets.store: ${k}`, { key: k }); return Promise.resolve(); },
    },
    globalStorageUri: { fsPath: '/work/storage' },
  };
}

// Intercept require('vscode')
const origLoad = Module._load;
Module._load = function (request, parent, isMain) {
  if (request === 'vscode') return vscode;
  return origLoad.apply(this, arguments);
};

module.exports = { vscode, makeContext };
