// src/npm_ide_analyst/sandbox/harness/preload-bun.js
// Bun entrypoint (injected via `bun --preload`). Shares hooks-core.js;
// Bun-native hooks (Bun.spawn*, global fetch) are added in a later task.
'use strict';
require('./hooks-core.js');
