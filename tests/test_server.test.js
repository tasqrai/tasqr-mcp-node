// The local server the proxy serves (buildServer). What matters is what a
// connecting client receives, so these connect a real SDK Client over an
// in-memory transport rather than inspecting constructor options. Mirrors
// tests/test_server.py in the Python port.
import { test, describe } from 'node:test';
import assert from 'node:assert/strict';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { Client } from '@modelcontextprotocol/sdk/client/index.js';
import { InMemoryTransport } from '@modelcontextprotocol/sdk/inMemory.js';

process.env.TASQR_LOG = join(tmpdir(), `test-server-log-${Date.now()}.txt`);
const { buildServer } = await import('../src/proxy.js');

const UPSTREAM_TEXT =
  'Tasqr is a shared, durable task tracker.\n\nCore loop: create_tasks, update_tasks.';

function upstream(instructions) {
  return { getInstructions: () => instructions, callTool: async () => ({ content: [] }) };
}

async function connect(server) {
  const [clientSide, serverSide] = InMemoryTransport.createLinkedPair();
  const client = new Client({ name: 'test-client', version: '0.0.0' });
  await Promise.all([server.connect(serverSide), client.connect(clientSide)]);
  return client;
}

describe('buildServer', () => {
  test('relays the upstream instructions verbatim', async () => {
    const client = await connect(buildServer(upstream(UPSTREAM_TEXT), [], null));
    assert.equal(client.getInstructions(), UPSTREAM_TEXT);
    await client.close();
  });

  test('no upstream instructions advertises none', async () => {
    const client = await connect(buildServer(upstream(undefined), [], null));
    assert.equal(client.getInstructions(), undefined);
    await client.close();
  });

  test('still serves the upstream tool listing', async () => {
    const tools = [{ name: 'create_tasks', inputSchema: { type: 'object' } }];
    const client = await connect(buildServer(upstream(UPSTREAM_TEXT), tools, null));
    const listing = await client.listTools();
    assert.deepEqual(
      listing.tools.map((t) => t.name),
      ['create_tasks'],
    );
    await client.close();
  });
});
