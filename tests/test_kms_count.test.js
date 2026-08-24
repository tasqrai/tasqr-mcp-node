import { test, describe } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { randomBytes } from 'node:crypto';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

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

describe('KMS call count invariant', () => {
  test('kms.Decrypt not called after init — 50 tool calls', async () => {
    const logPath = join(tmpdir(), `test-kms-${Date.now()}.log`);
    process.env.TASQR_LOG = logPath;
    const { ClientCrypto } = await import('../src/crypto.js');
    const c = new ClientCrypto(DEK, 'org-kms-test');

    for (let i = 0; i < 50; i++) {
      const args = c.encryptArgs('create_tasks', {
        tasks: [{ title: `task ${i}`, description: 'desc' }],
      });
      const item = args.tasks[0];

      const envelopeJson = JSON.stringify({
        tasks: [
          {
            task_id: item.task_id,
            title: item.title,
            description: item.description,
            metadata: null,
            output: null,
            status: 'pending',
            history: [],
          },
        ],
        count: 1,
        not_found: [],
      });
      const result = { content: [{ type: 'text', text: envelopeJson }] };
      c.decryptResult('get_tasks', result);
    }

    const lines = readLogLines(logPath);
    const kmsLines = lines.filter((l) => l.event === 'kms_decrypt');
    assert.equal(kmsLines.length, 0, 'No KMS calls should appear in 50 encrypt/decrypt cycles');
  });
});
