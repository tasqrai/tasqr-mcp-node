/**
 * log_level / log_path are configurable from the credentials file.
 *
 * These drive the real credentials file (via a temp HOME) rather than stubbing the
 * config reader, so the config-precedence path is exercised for real.
 */
import { test, describe, beforeEach, afterEach } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync, writeFileSync, mkdirSync, existsSync, mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import { logEvent } from '../src/logging.js';

let home;
const ENV_KEYS = ['TASQR_LOG', 'TASQR_LOG_LEVEL', 'HOME'];
const saved = {};

function events(path) {
  if (!existsSync(path)) return [];
  return readFileSync(path, 'utf8')
    .split('\n')
    .filter((l) => l.trim())
    .map((l) => JSON.parse(l).event);
}

/** Write a real ~/.config/tasqr/credentials with the given keys. */
function writeCreds(keys) {
  const dir = join(home, '.config', 'tasqr');
  mkdirSync(dir, { recursive: true });
  const body = [
    '[default]',
    'api_key = tasqr_test',
    ...Object.entries(keys).map(([k, v]) => `${k} = ${v}`),
  ];
  writeFileSync(join(dir, 'credentials'), body.join('\n') + '\n');
}

beforeEach(() => {
  for (const k of ENV_KEYS) saved[k] = process.env[k];
  home = mkdtempSync(join(tmpdir(), 'tasqr-home-'));
  process.env.HOME = home;
  delete process.env.TASQR_LOG;
  delete process.env.TASQR_LOG_LEVEL;
});

afterEach(() => {
  rmSync(home, { recursive: true, force: true });
  for (const k of ENV_KEYS) {
    if (saved[k] === undefined) delete process.env[k];
    else process.env[k] = saved[k];
  }
});

describe('log level', () => {
  test('off writes nothing', () => {
    const log = join(home, 'x.log');
    process.env.TASQR_LOG = log;
    writeCreds({ log_level: 'off' });

    logEvent('dek_loaded', { source: 'api' });
    logEvent('encrypt', { tool: 'create_tasks', fields: ['title'] });

    assert.deepEqual(events(log), []);
  });

  test('off is the default when unset', () => {
    // Logging is opt-in: with no log_level configured, nothing touches disk.
    const log = join(home, 'x.log');
    process.env.TASQR_LOG = log;
    writeCreds({}); // no log_level -> default

    logEvent('dek_loaded', { source: 'api' });
    logEvent('kms_decrypt', { profile: 'p' });
    logEvent('encrypt', { tool: 'create_tasks', fields: ['title'] });

    assert.deepEqual(events(log), []);
    assert.ok(!existsSync(log), 'no file should be created at all when logging is off');
  });

  test('info logs lifecycle but omits per-call events', () => {
    const log = join(home, 'x.log');
    process.env.TASQR_LOG = log;
    writeCreds({ log_level: 'info' });

    logEvent('dek_loaded', { source: 'api' });
    logEvent('kms_decrypt', { profile: 'p' });
    logEvent('encrypt', { tool: 'create_tasks', fields: ['title'] });
    logEvent('decrypt', { tool: 'get_tasks', fields: ['title'] });

    assert.deepEqual(events(log), ['dek_loaded', 'kms_decrypt']);
  });

  test('debug includes per-call events', () => {
    const log = join(home, 'x.log');
    process.env.TASQR_LOG = log;
    writeCreds({ log_level: 'debug' });

    logEvent('dek_loaded', { source: 'api' });
    logEvent('encrypt', { tool: 'create_tasks', fields: ['title'] });

    assert.deepEqual(events(log), ['dek_loaded', 'encrypt']);
  });

  test('log_path can come from the credentials file', () => {
    const log = join(home, 'from-config.log');
    writeCreds({ log_path: log, log_level: 'debug' }); // no TASQR_LOG env

    logEvent('dek_loaded', { source: 'api' });

    assert.deepEqual(events(log), ['dek_loaded']);
  });

  test('TASQR_LOG_LEVEL overrides the credentials file', () => {
    const log = join(home, 'x.log');
    process.env.TASQR_LOG = log;
    process.env.TASQR_LOG_LEVEL = 'off';
    writeCreds({ log_level: 'debug' }); // env must win

    logEvent('dek_loaded', { source: 'api' });

    assert.deepEqual(events(log), []);
  });

  test('an unknown level falls back to info, not silence', () => {
    const log = join(home, 'x.log');
    process.env.TASQR_LOG = log;
    writeCreds({ log_level: 'verbose' }); // not a real level

    logEvent('dek_loaded', { source: 'api' });
    logEvent('encrypt', { tool: 'create_tasks', fields: ['title'] });

    assert.deepEqual(events(log), ['dek_loaded']);
  });
});
