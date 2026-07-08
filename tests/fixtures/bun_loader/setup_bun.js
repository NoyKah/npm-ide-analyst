// LAB ARTIFACT — mirrors the tiaan family's evasion: hand the real payload to
// bun so a node-only sandbox never sees it. Not real malware.
'use strict';
const cp = require('child_process');
try { cp.execSync('which bun', { stdio: 'ignore' }); } catch (e) {}
cp.spawn('bun', ['payload.js'], { stdio: 'ignore' });
