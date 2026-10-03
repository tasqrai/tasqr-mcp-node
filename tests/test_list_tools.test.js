// listAllTools reads every page of the upstream tool list. The upstream here is a
// real SDK Server that paginates, reached by a real Client over an in-memory
// transport, so the cursor travels the same wire shape it does in production.
import { test, describe } from 'node:test';
import assert from 'node:assert/strict';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { Client } from '@modelcontextprotocol/sdk/client/index.js';
import { Server } from '@modelcontextprotocol/sdk/server/index.js';
import { InMemoryTransport } from '@modelcontextprotocol/sdk/inMemory.js';
import { ListToolsRequestSchema } from '@modelcontextprotocol/sdk/types.js';

process.env.TASQR_LOG = join(tmpdir(), `test-list-tools-log-${Date.now()}.txt`);
const { listAllTools } = await import('../src/proxy.js');

const tool = (name) => ({ name, inputSchema: { type: 'object' } });

// pages: arrays of tool names; nextCursor(i) decides the cursor after page i.
async function upstreamServing(
  pages,
  nextCursor = (i) => (i + 1 < pages.length ? `p${i + 1}` : undefined),
) {
  const server = new Server(
    { name: 'upstream', version: '0.0.0' },
    { capabilities: { tools: {} } },
  );
  const requested = [];
  server.setRequestHandler(ListToolsRequestSchema, async (req) => {
    const cursor = req.params?.cursor;
    requested.push(cursor);
    const i = cursor === undefined ? 0 : Number(cursor.slice(1));
    const next = nextCursor(i);
    return { tools: pages[i].map(tool), ...(next !== undefined && { nextCursor: next }) };
  });
  const [clientSide, serverSide] = InMemoryTransport.createLinkedPair();
  const client = new Client({ name: 'test-client', version: '0.0.0' });
  await Promise.all([server.connect(serverSide), client.connect(clientSide)]);
  return { client, requested };
}

describe('listAllTools', () => {
  test('a single page is fetched once', async () => {
    const { client, requested } = await upstreamServing([['create_tasks', 'get_tasks']]);
    const tools = await listAllTools(client);
    assert.deepEqual(
      tools.map((t) => t.name),
      ['create_tasks', 'get_tasks'],
    );
    assert.deepEqual(requested, [undefined]);
    await client.close();
  });

  test('follows every cursor and keeps upstream order', async () => {
    const { client, requested } = await upstreamServing([
      ['create_tasks', 'update_tasks'],
      ['get_tasks'],
      ['list_tasks', 'claim_next_task'],
    ]);
    const tools = await listAllTools(client);
    assert.deepEqual(
      tools.map((t) => t.name),
      ['create_tasks', 'update_tasks', 'get_tasks', 'list_tasks', 'claim_next_task'],
    );
    assert.deepEqual(requested, [undefined, 'p1', 'p2']);
    await client.close();
  });

  test('a repeated cursor is an error, not an endless loop', async () => {
    const { client } = await upstreamServing([['a'], ['b']], () => 'p1');
    await assert.rejects(listAllTools(client), /repeated cursor/);
    await client.close();
  });
});
