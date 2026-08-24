import { test, describe } from 'node:test';
import assert from 'node:assert/strict';
import { randomBytes } from 'node:crypto';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

const DEK = randomBytes(32);
const ORG = 'org-proxy-test';

function makeResult(data) {
  return { content: [{ type: 'text', text: JSON.stringify(data) }] };
}

describe('proxy tool interception', () => {
  // Shared crypto instance — set log path before first import
  let crypto;
  test('setup', async () => {
    process.env.TASQR_LOG = join(tmpdir(), `test-proxy-log-${Date.now()}.txt`);
    const { ClientCrypto } = await import('../src/crypto.js');
    crypto = new ClientCrypto(DEK, ORG);
  });

  test('create_tasks encrypts title', () => {
    const args = crypto.encryptArgs('create_tasks', {
      tasks: [{ title: 'plaintext title', description: 'd' }],
    });
    const item = args.tasks[0];
    const marker = JSON.parse(item.title);
    assert.ok('__tasqr_enc__' in marker);
    assert.ok(!JSON.stringify(item.title).includes('plaintext title'));
  });

  test('create_tasks encrypts description and metadata', () => {
    const meta = { reason: 'urgent' };
    const args = crypto.encryptArgs('create_tasks', {
      tasks: [{ title: 't', description: 'secret', metadata: meta }],
    });
    const item = args.tasks[0];
    assert.ok(JSON.parse(item.description)['__tasqr_enc__']);
    // metadata is stored as an object marker (not a string)
    assert.ok(typeof item.metadata === 'object' && '__tasqr_enc__' in item.metadata);
  });

  test('update_tasks encrypts output and note', () => {
    const args = crypto.encryptArgs('update_tasks', {
      updates: [{ task_id: 't1', output: { r: 'done' }, note: 'All done' }],
    });
    const item = args.updates[0];
    assert.ok(JSON.parse(item.note)['__tasqr_enc__']);
    // output is stored as an object marker (not a string)
    assert.ok(typeof item.output === 'object' && '__tasqr_enc__' in item.output);
  });

  test('get_tasks decrypts response', () => {
    const encTitle = crypto._encryptStr('secret task title', 't1', 'title');
    // Real server returns {"tasks": [...], "count": N, "not_found": [...]}
    const task = {
      task_id: 't1',
      title: encTitle,
      description: 'plain',
      metadata: null,
      output: null,
      status: 'pending',
      history: [],
    };
    const result = makeResult({ tasks: [task], count: 1, not_found: [] });
    const decrypted = crypto.decryptResult('get_tasks', result);
    const data = JSON.parse(decrypted.content[0].text);
    assert.equal(data.tasks[0].title, 'secret task title');
  });

  test('list_tasks decrypts all items', () => {
    const tasks = Array.from({ length: 5 }, (_, i) => ({
      task_id: `t${i}`,
      title: crypto._encryptStr(`task ${i}`, `t${i}`, 'title'),
      description: 'd',
      metadata: null,
      output: null,
      status: 'pending',
      history: [],
    }));
    // Real server returns {"tasks": [...], "count": N, "cursor": null}
    const result = makeResult({ tasks, count: 5, cursor: null });
    const decrypted = crypto.decryptResult('list_tasks', result);
    const data = JSON.parse(decrypted.content[0].text);
    assert.ok('tasks' in data);
    assert.equal(data.count, 5);
    data.tasks.forEach((t, i) => assert.equal(t.title, `task ${i}`));
  });

  test('output dict roundtrip via encrypt/decrypt', () => {
    const outputData = { result: 'done', score: 42, nested: { key: 'val' } };
    const args = crypto.encryptArgs('update_tasks', {
      updates: [{ task_id: 't1', output: outputData }],
    });
    const item = args.updates[0];
    // encrypted output should be an object marker
    assert.ok(typeof item.output === 'object' && '__tasqr_enc__' in item.output);
    // decrypt via _decryptTask (AAD rebuilt from the task's own id)
    const task = { task_id: 't1', output: item.output };
    const decrypted = crypto._decryptTask(task);
    assert.deepEqual(decrypted.output, outputData);
  });

  test('claim_next_task decrypts nested task', () => {
    const encTitle = crypto._encryptStr('claimed task', 'c1', 'title');
    const result = makeResult({
      claimed: true,
      task: {
        task_id: 'c1',
        title: encTitle,
        description: 'd',
        metadata: null,
        output: null,
        status: 'in_progress',
        history: [],
      },
    });
    const decrypted = crypto.decryptResult('claim_next_task', result);
    const data = JSON.parse(decrypted.content[0].text);
    assert.equal(data.claimed, true);
    assert.equal(data.task.title, 'claimed task');
  });

  test('submit_feedback not encrypted', () => {
    const args = crypto.encryptArgs('submit_feedback', { message: 'great!', type: 'feature' });
    assert.equal(args.message, 'great!');
  });

  test('status priority assignee tags not encrypted', () => {
    const args = crypto.encryptArgs('create_tasks', {
      tasks: [
        {
          title: 't',
          description: 'd',
          status: 'pending',
          priority: 2,
          assignee: 'alice@example.com',
          tags: ['bug'],
        },
      ],
    });
    const item = args.tasks[0];
    assert.equal(item.status, 'pending');
    assert.equal(item.priority, 2);
    assert.equal(item.assignee, 'alice@example.com');
    assert.deepEqual(item.tags, ['bug']);
  });
});

describe('version', () => {
  test('the MCP handshake version comes from package.json', async () => {
    // A literal in proxy.js silently drifts on the first version bump — the bin
    // shim already reads package.json; the handshake must use the same source.
    const { readFileSync } = await import('node:fs');
    const pkg = JSON.parse(readFileSync(new URL('../package.json', import.meta.url), 'utf8'));
    const { VERSION } = await import('../src/proxy.js');
    assert.equal(VERSION, pkg.version);
  });
});
