# Contributing

Thanks for your interest in `tasqr-mcp`. This is the Node proxy; a line-for-line Python port lives in [tasqr-mcp-python](https://github.com/tasqrai/tasqr-mcp-python).

## Getting set up

Requires Node 22 or newer.

```bash
npm install
npm test                               # full suite, runs offline
node --test --experimental-test-module-mocks tests/test_crypto.test.js  # a single file
#            ^ lets tests stub the optional AWS SDK; without it those tests skip
npm run lint                           # ESLint
npm run format                         # Prettier
```

The suite uses Node's built-in test runner — no framework — and needs no network or AWS account; KMS is faked. Lint and formatting are handled by ESLint and Prettier; CI fails on violations. This is an ESM package: use `import`/`export`, not `require`.

To run against a local Tasqr server instead of production:

```bash
TASQR_MCP_URL=http://localhost:8000/mcp npx tasqr-mcp
```

## Three things to know before you change crypto

**Keep the two ports in sync.** The Python proxy is a port of this one: same module names, same behavior, same wire format. A task encrypted by one client must decrypt in the other. Any change to the protocol, the tool tables, or the crypto logic has to land in both repos, or clients silently disagree.

**The crypto tables fail open.** `ENCRYPT_LIST_TOOLS` / `DECRYPT_TOOLS` in `crypto.js` are keyed by server tool name, and an unrecognised name encrypts nothing, decrypts nothing, and raises no error. That makes a tool rename a silent-plaintext bug rather than a crash. Tests won't catch it on their own — a suite written against a stale tool name still passes, because "no plaintext" is trivially true when nothing was encrypted. Assert on the ciphertext (`isEncMarker`), not on the absence of plaintext. The exact table contents are pinned by `tests/test_tool_tables.test.js` against `tests/fixtures/crypto_tool_tables.json`, which is checked into both repos byte-for-byte — a rename must update the fixture and the tables in both repos in the same change.

**The AWS SDK is optional, so "not installed" is a supported state.** `fetchOrGenerateDek` loads the KMS SDK lazily, _after_ asking the server whether the org may be client-encrypted. Don't hoist that import: refusing to encrypt for a server-managed org must not depend on AWS being present. CI's `no-optional-deps` job keeps this honest by deleting `node_modules/@aws-sdk` after `npm ci` and re-running the suite (not via `npm ci --omit=optional` — npm 10 installs optional deps despite that flag, so the job would quietly test nothing).

## Pull requests

- Include a test. For a bug fix, write the failing test first.
- Run the full suite and the linter before pushing; CI runs the tests on Node 22, 24, and 26, plus once with the optional AWS SDK absent.
- Keep commits focused, and explain _why_ in the message rather than restating the diff.

## Security

Please don't open a public issue for a security problem. Use GitHub's private vulnerability reporting instead: **Security** tab → **Report a vulnerability**.
