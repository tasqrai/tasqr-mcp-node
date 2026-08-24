// Canary for the fail-open crypto tables.
//
// ENCRYPT_LIST_TOOLS / DECRYPT_TOOLS are keyed by server tool name and encrypt or
// decrypt NOTHING for an unrecognized name — no error, no log. A server-side tool
// rename that isn't mirrored here therefore ships plaintext while every behavioral
// test still passes (it already happened once: the plural-forms rename left this
// port silently unencrypted until it was synced). This test pins the exact table
// contents against a fixture that is checked into BOTH repos byte-for-byte, so a
// rename can't land in one port without failing the other's CI too.
import { test, describe } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';

const fixture = JSON.parse(
  readFileSync(
    join(dirname(fileURLToPath(import.meta.url)), 'fixtures/crypto_tool_tables.json'),
    'utf8',
  ),
);

describe('crypto tool tables match the cross-repo fixture', () => {
  test('ENCRYPT_LIST_TOOLS pins the exact tools, list keys, and field lists', async () => {
    const { ENCRYPT_LIST_TOOLS } = await import('../src/crypto.js');
    const actual = Object.fromEntries(
      Object.entries(ENCRYPT_LIST_TOOLS).map(([tool, [listKey, fields]]) => [
        tool,
        { list_key: listKey, fields },
      ]),
    );
    assert.deepEqual(actual, fixture.encrypt_list_tools);
  });

  test('DECRYPT_TOOLS and TASK_DEC_FIELDS pin the exact names', async () => {
    const { DECRYPT_TOOLS, TASK_DEC_FIELDS } = await import('../src/crypto.js');
    assert.deepEqual([...DECRYPT_TOOLS].sort(), fixture.decrypt_tools);
    assert.deepEqual(TASK_DEC_FIELDS, fixture.task_dec_fields);
  });
});
