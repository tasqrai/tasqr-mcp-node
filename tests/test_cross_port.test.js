// Cross-port compatibility — the wire format is shared with tasqr-mcp-python.
//
// Two fixtures, one per generating port: cross_port_python.json was produced by
// the Python client, cross_port_node.json by this one, both with a fixed test
// DEK. Every case in both must decrypt here byte-for-byte — the Python fixture
// proves the ports haven't diverged (a task encrypted on one machine would be
// unreadable on a teammate's), and our own fixture proves this port still reads
// its own historical output. The Python suite runs the same two fixtures.
// Regenerate a fixture only from its generating repo on a legitimate format
// change — never hand-edit it.

import { test, describe } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';

const fixturesDir = join(dirname(fileURLToPath(import.meta.url)), 'fixtures');
const FIXTURES = ['cross_port_python.json', 'cross_port_node.json'].map((name) => [
  name,
  JSON.parse(readFileSync(join(fixturesDir, name), 'utf8')),
]);

describe('cross-port wire compatibility', () => {
  for (const [name, fixture] of FIXTURES) {
    test(`every blob in ${name} decrypts in the node port`, async () => {
      process.env.TASQR_LOG = join(tmpdir(), `test-xport-${Date.now()}.log`);
      const { ClientCrypto } = await import('../src/crypto.js');
      const c = new ClientCrypto(Buffer.from(fixture.dek_b64, 'base64'), fixture.org_id);
      for (const { task_id, field, plaintext, marker } of fixture.cases) {
        assert.equal(c._decryptStr(marker, task_id, field), plaintext, `case ${field}@${task_id}`);
      }
    });

    test(`blobs from ${name} refuse to decrypt in the wrong slot`, async () => {
      process.env.TASQR_LOG = join(tmpdir(), `test-xport-reloc-${Date.now()}.log`);
      const { ClientCrypto, ClientCryptoError } = await import('../src/crypto.js');
      const c = new ClientCrypto(Buffer.from(fixture.dek_b64, 'base64'), fixture.org_id);
      const { task_id, marker } = fixture.cases[0];
      assert.throws(
        () => c._decryptStr(marker, task_id, 'output'),
        (e) => e instanceof ClientCryptoError && /moved|tampered/.test(e.message),
      );
    });
  }
});
