// Crypto correctness — AES-256-GCM logic, no KMS needed.
//
// Wire format v2: every ciphertext carries GCM associated data binding it to
// `v2|{org_id}|{task_id}|{field}`. A blob only decrypts in the exact slot it was
// sealed for — relocation across fields, tasks, or orgs is a hard failure.
// There is no v1 read path: v1 was a dead pre-release format; any non-v2 marker
// throws the typed UnsupportedCiphertextError, never a bare GCM tag error.

import { test, describe } from 'node:test';
import assert from 'node:assert/strict';
import { randomBytes } from 'node:crypto';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

const DEK = randomBytes(32);
const ORG = '11111111-0000-4000-8000-000000000001';
const TID = '22222222-0000-4000-8000-000000000002';
const TID2 = '33333333-0000-4000-8000-000000000003';
const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;

async function makeCrypto(orgId = ORG) {
  const { ClientCrypto } = await import('../src/crypto.js');
  return new ClientCrypto(DEK, orgId);
}

describe('crypto correctness', () => {
  test('encrypt/decrypt roundtrip', async () => {
    process.env.TASQR_LOG = join(tmpdir(), `test-crypto-${Date.now()}.log`);
    const c = await makeCrypto();
    for (const plain of ['hello world', 'unicode: café', '{"nested": true}']) {
      assert.equal(c._decryptStr(c._encryptStr(plain, TID, 'title'), TID, 'title'), plain);
    }
  });

  test('marker format is v2', async () => {
    process.env.TASQR_LOG = join(tmpdir(), `test-marker-${Date.now()}.log`);
    const c = await makeCrypto();
    const enc = c._encryptStr('test', TID, 'title');
    const obj = JSON.parse(enc);
    assert.ok('n' in obj && 'ct' in obj);
    assert.equal(obj['__tasqr_enc__'], 2);
  });

  // ── AAD binding: relocation must fail ────────────────────────────────────
  // These are the tests that prove the AAD is actually wired in — a round-trip
  // alone passes even if no AAD is set on either side.

  // Raw GCM auth failures surface as the typed ClientCryptoError naming the
  // field and task — the rejection is a signal, not a mystery.

  test('relocated to another field fails', async () => {
    process.env.TASQR_LOG = join(tmpdir(), `test-reloc-field-${Date.now()}.log`);
    const { ClientCryptoError } = await import('../src/crypto.js');
    const c = await makeCrypto();
    const blob = c._encryptStr('secret', TID, 'title');
    assert.throws(
      () => c._decryptStr(blob, TID, 'description'),
      (e) => e instanceof ClientCryptoError && /description/.test(e.message),
    );
  });

  test('relocated to another task fails', async () => {
    process.env.TASQR_LOG = join(tmpdir(), `test-reloc-task-${Date.now()}.log`);
    const { ClientCryptoError } = await import('../src/crypto.js');
    const c = await makeCrypto();
    const blob = c._encryptStr('secret', TID, 'title');
    assert.throws(
      () => c._decryptStr(blob, TID2, 'title'),
      (e) => e instanceof ClientCryptoError && e.message.includes(TID2),
    );
  });

  test('relocated to another org fails', async () => {
    process.env.TASQR_LOG = join(tmpdir(), `test-reloc-org-${Date.now()}.log`);
    const { ClientCryptoError } = await import('../src/crypto.js');
    const cA = await makeCrypto('org-a');
    const cB = await makeCrypto('org-b'); // same DEK, different org
    const blob = cA._encryptStr('secret', TID, 'title');
    assert.throws(
      () => cB._decryptStr(blob, TID, 'title'),
      (e) => e instanceof ClientCryptoError && /moved|tampered/.test(e.message),
    );
  });

  // ── version handling ─────────────────────────────────────────────────────

  test('unknown version throws typed error, not a GCM failure', async () => {
    process.env.TASQR_LOG = join(tmpdir(), `test-ver-${Date.now()}.log`);
    const { UnsupportedCiphertextError } = await import('../src/crypto.js');
    const c = await makeCrypto();
    const obj = JSON.parse(c._encryptStr('x', TID, 'title'));
    obj['__tasqr_enc__'] = 99;
    assert.throws(
      () => c._decryptStr(JSON.stringify(obj), TID, 'title'),
      (e) => e instanceof UnsupportedCiphertextError && /99/.test(e.message),
    );
  });

  test('v1 is a dead format', async () => {
    process.env.TASQR_LOG = join(tmpdir(), `test-v1-${Date.now()}.log`);
    const { UnsupportedCiphertextError } = await import('../src/crypto.js');
    const c = await makeCrypto();
    const obj = JSON.parse(c._encryptStr('x', TID, 'title'));
    obj['__tasqr_enc__'] = 1;
    assert.throws(
      () => c._decryptStr(JSON.stringify(obj), TID, 'title'),
      (e) => e instanceof UnsupportedCiphertextError && /v1/.test(e.message),
    );
  });

  // ── encryptArgs ──────────────────────────────────────────────────────────

  test('create_tasks mints a task_id per item', async () => {
    process.env.TASQR_LOG = join(tmpdir(), `test-mint-${Date.now()}.log`);
    const c = await makeCrypto();
    const args = { tasks: [{ title: 't', description: 'd' }] };
    const result = c.encryptArgs('create_tasks', args);
    const item = result.tasks[0];
    assert.match(item.task_id, UUID_RE); // canonical lowercase form
    assert.equal(c._decryptStr(item.title, item.task_id, 'title'), 't');
    assert.equal(c._decryptStr(item.description, item.task_id, 'description'), 'd');
    // original args not mutated
    assert.ok(!('task_id' in args.tasks[0]));
  });

  test('create_tasks keeps a caller-supplied task_id', async () => {
    process.env.TASQR_LOG = join(tmpdir(), `test-keep-id-${Date.now()}.log`);
    const c = await makeCrypto();
    const result = c.encryptArgs('create_tasks', {
      tasks: [{ title: 't', description: 'd', task_id: TID }],
    });
    assert.equal(result.tasks[0].task_id, TID);
    assert.equal(c._decryptStr(result.tasks[0].title, TID, 'title'), 't');
  });

  test('update_tasks item without task_id throws instead of leaking plaintext', async () => {
    process.env.TASQR_LOG = join(tmpdir(), `test-no-id-${Date.now()}.log`);
    const { ClientCryptoError } = await import('../src/crypto.js');
    const c = await makeCrypto();
    assert.throws(
      () => c.encryptArgs('update_tasks', { updates: [{ title: 'no id' }] }),
      (e) => e instanceof ClientCryptoError && /task_id/.test(e.message),
    );
  });

  test('passthrough fields unchanged', async () => {
    process.env.TASQR_LOG = join(tmpdir(), `test-passthrough-${Date.now()}.log`);
    const c = await makeCrypto();
    const args = {
      tasks: [{ title: 't', status: 'pending', priority: 2, assignee: 'a@b.com', tags: ['x'] }],
    };
    const result = c.encryptArgs('create_tasks', args);
    const item = result.tasks[0];
    assert.equal(item.status, 'pending');
    assert.equal(item.priority, 2);
    assert.equal(item.assignee, 'a@b.com');
    assert.deepEqual(item.tags, ['x']);
  });

  test('metadata roundtrip as object', async () => {
    process.env.TASQR_LOG = join(tmpdir(), `test-meta-${Date.now()}.log`);
    const c = await makeCrypto();
    const meta = { key: 'value', count: 42 };
    const args = c.encryptArgs('create_tasks', {
      tasks: [{ title: 't', description: 'd', metadata: meta }],
    });
    const item = args.tasks[0];
    // metadata is now an object marker (not a string)
    assert.ok(typeof item.metadata === 'object' && '__tasqr_enc__' in item.metadata);
    // decrypt it back via _decryptTask (AAD rebuilt from the task's own id)
    const task = { task_id: item.task_id, metadata: item.metadata };
    const decrypted = c._decryptTask(task);
    assert.deepEqual(decrypted.metadata, meta);
  });

  test('submit_feedback not encrypted', async () => {
    process.env.TASQR_LOG = join(tmpdir(), `test-feedback-${Date.now()}.log`);
    const c = await makeCrypto();
    const args = c.encryptArgs('submit_feedback', { message: 'great product!', type: 'feature' });
    assert.equal(args.message, 'great product!');
  });

  test('create_tasks items encrypted', async () => {
    process.env.TASQR_LOG = join(tmpdir(), `test-create-tasks-${Date.now()}.log`);
    const { isEncMarker } = await import('../src/crypto.js');
    const c = await makeCrypto();
    const args = {
      tasks: [
        { ref: 'a', title: 'first', description: 'd1', metadata: { k: 1 } },
        { title: 'second', description: 'd2', blocked_by: ['ref:a'], priority: 2 },
      ],
    };
    const result = c.encryptArgs('create_tasks', args);
    for (const item of result.tasks) {
      assert.ok(isEncMarker(item.title));
      assert.ok(isEncMarker(item.description));
    }
    // non-sensitive fields pass through untouched
    assert.equal(result.tasks[0].ref, 'a');
    assert.deepEqual(result.tasks[1].blocked_by, ['ref:a']);
    assert.equal(result.tasks[1].priority, 2);
    // metadata marker stays an object for server-side validation
    assert.ok(
      typeof result.tasks[0].metadata === 'object' && isEncMarker(result.tasks[0].metadata),
    );
    // each item decrypts under its own minted id
    const t0 = result.tasks[0];
    assert.equal(c._decryptStr(t0.title, t0.task_id, 'title'), 'first');
    assert.deepEqual(
      JSON.parse(c._decryptStr(JSON.stringify(t0.metadata), t0.task_id, 'metadata')),
      { k: 1 },
    );
    // original args not mutated
    assert.equal(args.tasks[0].title, 'first');
  });

  test('create_tags not encrypted', async () => {
    process.env.TASQR_LOG = join(tmpdir(), `test-tags-${Date.now()}.log`);
    const c = await makeCrypto();
    // Tag names/descriptions are plaintext server-side, so no tag tool is in the
    // crypto tables — create_tags must pass through untouched.
    const args = { tags: [{ name: 'backend', strict: true }] };
    const result = c.encryptArgs('create_tags', args);
    assert.deepEqual(result, args);
  });

  test('update_tasks items encrypted under their own ids', async () => {
    process.env.TASQR_LOG = join(tmpdir(), `test-update-tasks-${Date.now()}.log`);
    const { isEncMarker } = await import('../src/crypto.js');
    const c = await makeCrypto();
    const args = {
      updates: [
        { task_id: TID, title: 'new title', note: 'done', status: 'completed' },
        { task_id: TID2, output: { ok: true }, metadata: { k: 1 } },
      ],
    };
    const result = c.encryptArgs('update_tasks', args);
    assert.ok(isEncMarker(result.updates[0].title));
    assert.ok(isEncMarker(result.updates[0].note));
    assert.equal(result.updates[0].task_id, TID);
    assert.equal(result.updates[0].status, 'completed');
    assert.equal(typeof result.updates[1].output, 'object');
    assert.ok(isEncMarker(result.updates[1].output));
    assert.equal(c._decryptStr(result.updates[0].title, TID, 'title'), 'new title');
    assert.deepEqual(
      JSON.parse(c._decryptStr(JSON.stringify(result.updates[1].output), TID2, 'output')),
      { ok: true },
    );
  });

  // ── decrypt paths ────────────────────────────────────────────────────────

  test('_decryptTask history notes bound to the task', async () => {
    process.env.TASQR_LOG = join(tmpdir(), `test-history-${Date.now()}.log`);
    const c = await makeCrypto();
    const task = {
      task_id: TID,
      title: 'plain',
      history: [{ to_status: 'completed', note: c._encryptStr('done', TID, 'note') }],
    };
    const result = c._decryptTask(task);
    assert.equal(result.history[0].note, 'done');
  });

  test('_decryptTask decrypts dependency titles under the blocker id', async () => {
    process.env.TASQR_LOG = join(tmpdir(), `test-deps-${Date.now()}.log`);
    const c = await makeCrypto();
    // The blob is the *blocker's* title ciphertext, sealed under the blocker's id —
    // the AAD must be rebuilt from dep.task_id, not the enclosing task's id.
    const encTitle = c._encryptStr("blocker's secret title", TID2, 'title');
    const task = {
      task_id: TID,
      title: 'plain dependent title',
      dependencies: [{ task_id: TID2, title: encTitle, status: 'pending' }],
    };
    const result = c._decryptTask(task);
    assert.equal(result.dependencies[0].title, "blocker's secret title");
  });

  test('get_tasks response decrypted', async () => {
    process.env.TASQR_LOG = join(tmpdir(), `test-get-tasks-${Date.now()}.log`);
    const c = await makeCrypto();
    const encTitle = c._encryptStr('secret title', TID, 'title');
    const payload = { tasks: [{ task_id: TID, title: encTitle }], count: 1, not_found: [] };
    const result = { content: [{ type: 'text', text: JSON.stringify(payload) }] };
    const out = c.decryptResult('get_tasks', result);
    const data = JSON.parse(out.content[0].text);
    assert.equal(data.tasks[0].title, 'secret title');
  });

  test('get_tasks decrypts structuredContent too', async () => {
    process.env.TASQR_LOG = join(tmpdir(), `test-structured-${Date.now()}.log`);
    const { isEncMarker } = await import('../src/crypto.js');
    const c = await makeCrypto();
    // Tools with an outputSchema return the payload twice: serialized JSON in `content`
    // and the same object in `structuredContent`. Both arrive encrypted; both must be
    // decrypted and left in agreement. Passing structuredContent through untouched
    // leaks ciphertext to any client that prefers the structured channel.
    const encTitle = c._encryptStr('secret title', TID, 'title');
    const payload = { tasks: [{ task_id: TID, title: encTitle }], count: 1, not_found: [] };
    const result = {
      content: [{ type: 'text', text: JSON.stringify(payload) }],
      structuredContent: structuredClone(payload),
    };
    const out = c.decryptResult('get_tasks', result);

    assert.ok(out.structuredContent, 'structuredContent was dropped');
    assert.equal(out.structuredContent.tasks[0].title, 'secret title');
    assert.ok(!isEncMarker(out.structuredContent.tasks[0].title));
    // the two channels must agree
    assert.equal(
      JSON.parse(out.content[0].text).tasks[0].title,
      out.structuredContent.tasks[0].title,
    );
  });

  test('decryptResult preserves isError', async () => {
    process.env.TASQR_LOG = join(tmpdir(), `test-iserror-${Date.now()}.log`);
    const c = await makeCrypto();
    const payload = { tasks: [], count: 0, not_found: [] };
    const result = {
      content: [{ type: 'text', text: JSON.stringify(payload) }],
      structuredContent: payload,
      isError: true,
    };
    assert.equal(c.decryptResult('get_tasks', result).isError, true);
  });
});

describe('DEK length', () => {
  test('rejects a non-256-bit DEK at construction', async () => {
    // AES-256-GCM is the wire contract. Without this check the failure surfaces
    // only at the first encrypt (createCipheriv throws), and the Python port
    // would silently produce AES-128 ciphertext — fail loudly and identically
    // in both ports at construction instead.
    const { ClientCrypto, ClientCryptoError } = await import('../src/crypto.js');
    assert.throws(
      () => new ClientCrypto(randomBytes(16), ORG),
      (e) => e instanceof ClientCryptoError && /32/.test(e.message),
    );
  });
});
