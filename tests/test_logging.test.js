import { test, describe } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync, rmSync } from 'node:fs';
import { randomBytes } from 'node:crypto';
import { tmpdir } from 'node:os';
import { join, dirname } from 'node:path';

const DEK = randomBytes(32);

function readLogLines(path) {
  try {
    return readFileSync(path, 'utf8')
      .trim()
      .split('\n')
      .filter(Boolean)
      .map((l) => JSON.parse(l));
  } catch {
    return [];
  }
}

describe('logging', () => {
  test('logEvent writes JSON line with event and ts', async () => {
    const log = join(tmpdir(), `test-log-${Date.now()}.txt`);
    process.env.TASQR_LOG = log;
    process.env.TASQR_LOG_LEVEL = 'info'; // logging is off by default; opt in
    const { logEvent } = await import('../src/logging.js');
    logEvent('dek_loaded', { source: 'config' });
    const lines = readLogLines(log);
    assert.equal(lines.length, 1);
    assert.equal(lines[0].event, 'dek_loaded');
    assert.equal(lines[0].source, 'config');
    assert.ok('ts' in lines[0]);
    rmSync(log, { force: true });
    delete process.env.TASQR_LOG_LEVEL;
  });

  test('no plaintext task content in logs', async () => {
    // Pinned to debug — the most verbose setting is where a leak would surface, and
    // `encrypt` is a debug-level event so it is silent at the info default.
    const log = join(tmpdir(), `test-log-plaintext-${Date.now()}.txt`);
    process.env.TASQR_LOG = log;
    process.env.TASQR_LOG_LEVEL = 'debug';
    const { ClientCrypto } = await import('../src/crypto.js');
    const c = new ClientCrypto(DEK, 'org-log-test');
    c.encryptArgs('create_tasks', {
      tasks: [{ title: 'SECRET_NODE_CONTENT', description: 'PRIVATE_NODE_DATA' }],
    });
    const content = readFileSync(log, 'utf8');
    // The event must have been written, or "no plaintext" is trivially true.
    assert.ok(content.includes('"event":"encrypt"'));
    assert.ok(!content.includes('SECRET_NODE_CONTENT'));
    assert.ok(!content.includes('PRIVATE_NODE_DATA'));
    rmSync(log, { force: true });
    delete process.env.TASQR_LOG_LEVEL;
  });

  test('kms_decrypt fires exactly once in full session log', async (t) => {
    const log = join(tmpdir(), `test-session-log-${Date.now()}.txt`);
    process.env.TASQR_LOG = log;
    process.env.TASQR_LOG_LEVEL = 'debug'; // logging is off by default; opt in
    t.after(() => {
      delete process.env.TASQR_LOG_LEVEL;
    });

    const { logEvent } = await import('../src/logging.js');
    const { ClientCrypto } = await import('../src/crypto.js');
    const c = new ClientCrypto(DEK, 'org-log-test');

    // Simulate the one startup kms_decrypt (as credentials.js kmsDecrypt() would emit)
    logEvent('dek_loaded', { source: 'config' });
    logEvent('kms_decrypt', { profile: 'test' });

    // 5 tool calls — must not emit additional kms_decrypt events
    for (let i = 0; i < 5; i++) {
      c.encryptArgs('create_tasks', { tasks: [{ title: `t${i}`, description: 'd' }] });
      const result = {
        content: [
          {
            type: 'text',
            text: JSON.stringify({
              tasks: [
                {
                  task_id: 't1',
                  title: 'plain',
                  description: 'd',
                  metadata: null,
                  output: null,
                  status: 'p',
                  history: [],
                },
              ],
              count: 1,
              not_found: [],
            }),
          },
        ],
      };
      c.decryptResult('get_tasks', result);
    }

    const lines = readLogLines(log);
    const kmsLines = lines.filter((l) => l.event === 'kms_decrypt');
    assert.equal(kmsLines.length, 1);
    const nonStartup = lines.filter((l) => !['dek_loaded', 'kms_decrypt'].includes(l.event));
    assert.ok(nonStartup.every((l) => ['encrypt', 'decrypt'].includes(l.event)));
    rmSync(log, { force: true });
  });
});

describe('log path resolution', () => {
  test('configured log_path expands ~', async (t) => {
    // The README's own example is `log_path = ~/.config/tasqr/tasqr-mcp.log` — an
    // INI value gets no shell expansion, so an unexpanded `~` would silently create
    // a literal `./~/` directory relative to wherever the proxy happened to start.
    const { tempHome, writeCredentials } = await import('./helpers.js');
    const home = tempHome(t);
    writeCredentials(home, { log_path: '~/logs/tasqr.log' });
    const savedLog = process.env.TASQR_LOG;
    delete process.env.TASQR_LOG;
    process.env.TASQR_LOG_LEVEL = 'info';
    t.after(() => {
      if (savedLog !== undefined) process.env.TASQR_LOG = savedLog;
      delete process.env.TASQR_LOG_LEVEL;
    });
    const { logEvent } = await import('../src/logging.js');
    logEvent('dek_loaded', { source: 'config' });
    const { existsSync } = await import('node:fs');
    assert.ok(existsSync(join(home, 'logs', 'tasqr.log')), 'log must land under $HOME');
  });

  test('TASQR_LOG expands ~ too', async (t) => {
    // The env var can arrive without a shell (an MCP client's env block), so it
    // gets the same expansion as the credentials-file value.
    const { tempHome } = await import('./helpers.js');
    const home = tempHome(t);
    process.env.TASQR_LOG = '~/elogs/tasqr.log';
    process.env.TASQR_LOG_LEVEL = 'info';
    t.after(() => {
      delete process.env.TASQR_LOG_LEVEL;
    });
    const { logEvent } = await import('../src/logging.js');
    logEvent('dek_loaded', { source: 'config' });
    const { existsSync } = await import('node:fs');
    assert.ok(existsSync(join(home, 'elogs', 'tasqr.log')), 'log must land under $HOME');
  });

  test('a log directory log_event creates is owner-only (0700)', async (t) => {
    // The log shares the credential directory's sensitivity; when logEvent has to
    // create the directory itself, it must be 0700 like credentials' writes.
    const log = join(tmpdir(), `test-logdir-${Date.now()}`, 'tasqr.log');
    process.env.TASQR_LOG = log;
    process.env.TASQR_LOG_LEVEL = 'info';
    t.after(() => {
      delete process.env.TASQR_LOG_LEVEL;
      rmSync(dirname(log), { recursive: true, force: true });
    });
    const { logEvent } = await import('../src/logging.js');
    logEvent('dek_loaded', { source: 'config' });
    const { statSync } = await import('node:fs');
    assert.equal(statSync(dirname(log)).mode & 0o777, 0o700);
  });
});
