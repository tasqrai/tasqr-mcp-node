#!/usr/bin/env node
import { readApiKey, writeApiKey } from '../src/credentials.js';
import { runDeviceFlow } from '../src/device_flow.js';
import { runProxy } from '../src/proxy.js';

if (process.argv[2] === '--version' || process.argv[2] === '-V') {
  const { createRequire } = await import('node:module');
  const require = createRequire(import.meta.url);
  const { version } = require('../package.json');
  console.log(`tasqr-mcp ${version}`);
  process.exit(0);
}

let apiKey = readApiKey();
if (!apiKey) {
  if (!process.stdin.isTTY) {
    process.stderr.write(
      'tasqr-mcp: No credentials found.\n' +
        'Run `npx tasqr-mcp` in your terminal to sign up, then restart your MCP client.\n',
    );
    process.exit(1);
  }
  apiKey = await runDeviceFlow();
  writeApiKey(apiKey);
}

runProxy(apiKey).catch((err) => {
  process.stderr.write(`tasqr-mcp: ${err.message}\n`);
  process.exit(1);
});
