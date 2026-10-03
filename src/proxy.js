import { Client } from '@modelcontextprotocol/sdk/client/index.js';
import { StreamableHTTPClientTransport } from '@modelcontextprotocol/sdk/client/streamableHttp.js';
import { Server } from '@modelcontextprotocol/sdk/server/index.js';
import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js';
import { CallToolRequestSchema, ListToolsRequestSchema } from '@modelcontextprotocol/sdk/types.js';
import { readFileSync } from 'node:fs';
import { readConfig } from './credentials.js';

// Single source of truth for the version (bin/tasqr-mcp.js reads it the same way);
// a literal here would silently drift on the first version bump.
export const VERSION = JSON.parse(
  readFileSync(new URL('../package.json', import.meta.url), 'utf8'),
).version;

const DEFAULT_MCP_URL = 'https://mcp.tasqr.ai/mcp';

function mcpUrl() {
  return process.env.TASQR_MCP_URL || readConfig().mcp_url || DEFAULT_MCP_URL;
}

export async function runProxy(apiKey) {
  const cfg = readConfig();
  let crypto = null;
  if (cfg.kms_key_id) {
    const { ClientCrypto } = await import('./crypto.js');
    crypto = await ClientCrypto.init(cfg);
  }

  const upstream = new Client({ name: 'tasqr-mcp-proxy', version: VERSION });
  const transport = new StreamableHTTPClientTransport(new URL(mcpUrl()), {
    requestInit: { headers: { Authorization: `Bearer ${apiKey}` } },
  });

  await upstream.connect(transport);

  const { tools } = await upstream.listTools();

  const server = buildServer(upstream, tools, crypto);

  const stdio = new StdioServerTransport();
  await server.connect(stdio);
}

// The local stdio server, advertising what the upstream server advertises. Its
// `instructions` are relayed, not set here: with tool search on, a client sees
// only tool names and these instructions at session start, so they decide whether
// a model goes looking for the tools. Relaying keeps the server the one place that
// text is written — editing it ships with a server deploy, not a client release.
// Upstream sending none means we advertise none (the option is left out entirely).
export function buildServer(upstream, tools, crypto) {
  const instructions = upstream.getInstructions();
  const server = new Server(
    { name: 'tasqr-mcp', version: VERSION },
    { capabilities: { tools: {} }, ...(instructions !== undefined && { instructions }) },
  );

  server.setRequestHandler(ListToolsRequestSchema, async () => ({ tools }));

  server.setRequestHandler(CallToolRequestSchema, async (req) => {
    let params = req.params;
    if (crypto) {
      params = { ...params, arguments: crypto.encryptArgs(params.name, params.arguments ?? {}) };
    }
    const result = await upstream.callTool(params);
    if (crypto) return crypto.decryptResult(params.name, result);
    return result;
  });

  return server;
}
