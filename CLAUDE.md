# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What this is

`tasqr-mcp` is a thin local MCP proxy (Node/ESM port of the Python `tasqr-mcp-python` sibling repo — keep behavior in sync between the two when changing protocol/crypto logic). It runs as a stdio process, authenticates with a Tasqr API key, and forwards every `listTools`/`callTool` request to the remote Tasqr Lambda MCP server over streamable HTTP (`https://mcp.tasqr.ai/mcp` by default). The actual task-management logic (task storage, claiming, tags, etc.) lives server-side — this repo does not implement it. The only substantial local logic is credential/auth bootstrapping and optional client-side (BYOK) encryption of task fields before they leave the process.

## Commands

```bash
# Install for local dev
npm install

# Run the full test suite (node's built-in test runner, no framework dep)
npm test                       # node --test  (default discovery finds tests/*.test.js)

# Run a single test file
node --test tests/test_crypto.test.js

# Lint / format
npm run lint
npm run format

# Run against a local dev server instead of production
TASQR_MCP_URL=http://localhost:8000/mcp npx tasqr-mcp

# Check version / run the CLI directly
node bin/tasqr-mcp.js --version
```

Lint and format with `npm run lint` (ESLint, flat config in `eslint.config.js`) and `npm run format` (Prettier). CI fails on either. This is an ESM package (`"type": "module"`); use `import`/`export`, not `require`.

**The Node floor is 22** — the oldest release line still supported upstream (20 reached EOL on 2026-04-30). `@aws-sdk/client-kms` independently requires 20+. Keep `engines` and the CI matrix in step with the supported LTS lines.

**The AWS SDK is an optional dependency, so "not installed" is a supported state.** `fetchOrGenerateDek` loads the KMS SDK lazily, _after_ the org-state probe, so that refusing to encrypt for a server-managed org never depends on AWS being present or configured. Don't hoist that import to the top of the function: it would make the refusal unreachable whenever the SDK is missing. The `no-optional-deps` CI job pins this by deleting `node_modules/@aws-sdk` after `npm ci` and re-running the suite — deliberately not via `npm ci --omit=optional`, which npm 10 ignores for optional deps (the job would quietly test nothing). Tests that mock the SDK via `mock.module` skip in that job (`canMockKms` in `tests/helpers.js`): `mock.module` must resolve the specifier, so it can't stub a package that isn't on disk.

**The dependency tree is pinned for users by `npm-shrinkwrap.json`, not `package-lock.json`.** This is a CLI run via `npx`, so it ships a shrinkwrap — the only lockfile npm publishes and honours for consumers. A `package-lock.json` would do nothing here: npm never puts it in the tarball, and ignores a dependency's lockfile even when one is present. The two files are mutually exclusive; `npm shrinkwrap` renames one into the other, and `npm ci` reads either.

Two traps come with it. First, **the shrinkwrap only ships if it is named in `files`** — a restrictive `files` array drops it from the tarball silently, publishing a package that floats while the repo looks pinned. That is the same fail-open shape as the crypto tables, so the `build` CI job asserts the file is genuinely in `npm pack --json` output rather than trusting it. Second, pinning the tree means transitive security patches no longer reach users on their own: a `npm audit` fix now requires re-running `npm shrinkwrap` and cutting a release. Weekly Dependabot PRs cover the routine case; treat a high-severity advisory as a release trigger.

Runtime dependency ranges still carry an upper bound on top of the shrinkwrap (`tests/test_dependency_bounds.test.js`, mirroring `tests/test_dependency_bounds.py` in the Python port). The shrinkwrap governs `npx`; the ranges govern anyone installing this as a dependency, and they are what stops a new dep being added as `>=x` out of habit. `optionalDependencies` are covered too — they install by default and reach a user's launch like any other. Note the Python port has **no equivalent to the shrinkwrap**: `uvx --from git+…` ignores `uv.lock` and resolves fresh on every launch, so caps in `pyproject.toml` are its only defence. That asymmetry is a distribution-rail difference, not a behavioural divergence — it does not need syncing.

## Architecture

**Entry point** (`bin/tasqr-mcp.js`): reads the API key via `credentials.readApiKey()`. If missing and stdin is a TTY, runs the GitHub Device Flow signup (`src/device_flow.js`) and persists the resulting key; otherwise exits with an error telling the user to run `npx tasqr-mcp` interactively first. Then hands off to `proxy.runProxy(apiKey)`.

**Proxy loop** (`src/proxy.js`): connects an MCP SDK `Client` to the upstream Tasqr MCP server via `StreamableHTTPClientTransport`, then starts a local `Server` over `StdioServerTransport` that mirrors it — `ListToolsRequestSchema` returns the upstream tool list fetched once at startup, `CallToolRequestSchema` optionally encrypts args before forwarding and decrypts the result after. A `kms_key_id` in the credentials config is _necessary but not sufficient_ to encrypt: it only makes the proxy ask. The server has the final say (see BYOK below) and can refuse, in which case `ClientCrypto` is never constructed and the proxy exits with a `ManagedOrgError`. With no `kms_key_id`, calls pass straight through. (`crypto.js` is dynamically `import()`-ed only when a `kms_key_id` is set, since `@aws-sdk/client-kms` is an _optional_ dependency.)

**Credentials/config** (`src/credentials.js`): all local state lives in one hand-rolled INI file (`parseIni`/`serializeIni`, no library) — `~/.config/tasqr/credentials` (or `%APPDATA%\tasqr\credentials` on Windows), keyed by profile (`[default]`, overridable via `TASQR_PROFILE`). Holds `api_key`, and optionally `kms_key_id`, `aws_profile`, `mcp_url`, `auth_url`, `api_url`, and a cached `wrapped_dek`. Config precedence throughout the codebase is: env var → credentials file → hardcoded default (see `mcpUrl()` in `proxy.js` and `authUrl()` in `device_flow.js` for the pattern).

**Client-side encryption / BYOK** (`src/crypto.js` + `fetchOrGenerateDek` in `src/credentials.js`): when a `kms_key_id` is configured, `ClientCrypto.init()` runs once at proxy startup and resolves a single AES-256 data encryption key (DEK).

**The server decides whether we may encrypt at all — never local config.** `GET /org/dek` is consulted _first_, before any local state is touched:

1. **409** → the org is server-managed. Throw `ManagedOrgError`; do **not** construct `ClientCrypto`, even though `kms_key_id` is set. Client-encrypting here would corrupt the data for every other reader (dashboard, REST, other agents) and make it unrecoverable if the client key is lost.
2. **200** → the org is `client_byok`. Only now is the cached `wrapped_dek` safe to use: KMS `Decrypt` it (saving a round trip). If that fails (stale ciphertext), delete the cached value and fall back to the server's blob.
3. **404** → BYOK-eligible but unenrolled. Generate a DEK via KMS `GenerateDataKey`, `PUT /org/dek` to register it (racing PUTs resolve via a 409 → re-fetch-the-winner path), then cache the wrapped form locally.

This ordering is load-bearing. Never unwrap the cached `wrapped_dek` without first confirming with the server that the org is `client_byok` — a local short-circuit would client-encrypt against a managed org, and the server would then wrap that ciphertext again with the org DEK, leaving the data readable only by a key it has no record of.

KMS region is derived from the `kms_key_id` ARN itself (`arn:aws:kms:<region>:...`) rather than being separately configured, falling back to `AWS_DEFAULT_REGION`/`us-east-1` for non-ARN key ids; credentials come from `fromIni({ profile: aws_profile })` unless the profile is `default`. This is a hard invariant: exactly one KMS `Decrypt` per proxy session (at init), and zero further KMS calls no matter how many tool calls follow — all encrypt/decrypt after init is pure in-memory AES-256-GCM (`node:crypto`) using the resolved DEK. Don't add code paths that call KMS outside of `fetchOrGenerateDek`.

`tests/test_kms_count.test.js` itself only proves the _second_ half (it constructs `new ClientCrypto(dek, ...)` directly and never calls `ClientCrypto.init()`); the init half — exact KMS Decrypt/GenerateDataKey counts through `fetchOrGenerateDek` — is pinned by `tests/test_config_cache.test.js` and `tests/test_first_time.test.js`, which stub the dynamic `@aws-sdk/client-kms` import with `node:test`'s `mock.module` (hence `--experimental-test-module-mocks` in the npm test script; see `tests/helpers.js`).

Field-level encryption is declarative, driven by lookup tables in `crypto.js` that are **keyed by server tool name**. The server's task tools are all array-taking (`create_tasks`, `update_tasks`, `get_tasks`, plus `list_tasks` / `claim_next_task`) — a single task is just a list of one — so:

- `ENCRYPT_LIST_TOOLS` — outbound args holding a list of task-like objects, each item encrypted per the field list (`create_tasks`'s `tasks[]`, `update_tasks`'s `updates[]`). There is no single-object encrypt table — every task tool the server exposes is array-taking.
- `DECRYPT_TOOLS` / `TASK_DEC_FIELDS` — which inbound tool responses get decrypted, including nested shapes (`claim_next_task`'s `{"task": {...}}`, and the `{"tasks": [...]}` envelope returned by both `list_tasks` and `get_tasks`, which also carries `history[].note` and `dependencies[].title`).

Both lookups **fail open**: an unrecognized tool name encrypts/decrypts nothing and raises no error. So if the server renames a tool and these tables aren't updated, BYOK silently ships plaintext. A rename server-side is a breaking change here — grep the tables for the old name and sync both this repo and `tasqr-mcp-python` in the same change.

Encrypted values are JSON "marker" objects: `{"__tasqr_enc__": 2, "n": <base64 nonce>, "ct": <base64 ciphertext+authTag>}` (Node's GCM tag is appended to the ciphertext and split back off manually in `_decryptStr`, unlike the Python side where `cryptography`'s `AESGCM` handles that internally — keep this in mind if the wire format ever needs to change). Dict-typed fields (`metadata`, `output`) are JSON-serialized before encryption and the marker is embedded as an object (not a string) so the field still validates against the server's schema. When adding a new tool that should be encrypted, add it to the appropriate table rather than special-casing it in `encryptArgs`/`decryptResult`.

**AAD binding (format v2 — the only format).** Every ciphertext carries GCM associated data `v2|{org_id}|{task_id}|{field}` (`setAAD` on both cipher and decipher), so a blob only decrypts in the exact slot it was sealed for — relocating it across fields, tasks, or orgs is a hard auth failure. The pieces of that string are byte-exact contracts:

- `org_id` comes verbatim from `/org/dek` (the server added it to the 200 and PUT-201 bodies for exactly this purpose); `fetchOrGenerateDek` returns `[dek, source, orgId]` and refuses to run against a server that doesn't send it.
- `task_id`: on `create_tasks` the proxy **mints** each item's id (`randomUUID()`, canonical lowercase) before encrypting and sends it with the call — the server stores it as the primary key and rejects (never overwrites) an existing id. On `update_tasks` the item's own `task_id` is used; an update item with encryptable fields but no `task_id` throws `ClientCryptoError` rather than sending plaintext.
- Decrypt-side reconstruction: a task's fields and its `history[].note` were sealed under the task's own id; a `dependencies[].title` is the **blocker's** ciphertext, sealed under the blocker's id — rebuild from `dep.task_id`, never the enclosing task's.

Version handling: `_decryptStr` reads the marker's `__tasqr_enc__` value and throws the typed `UnsupportedCiphertextError` (naming the version) for anything ≠ 2. **There is no v1 read path** — v1 was a dead pre-release format (no AAD) that no released client ever wrote; do not add compatibility for it. The relocation-must-fail tests in `tests/test_crypto.test.js` prove the AAD is actually wired in on both sides, and `tests/test_cross_port.test.js` decrypts both checked-in fixtures — one generated by the Python port, one by this one (the Python suite runs the same pair) — regenerate a fixture from its generating repo on any legitimate format change, never hand-edit.

**The server uses this same binding.** Tasqr-managed (non-BYOK) orgs are encrypted server-side under the identical `v2|{org_id}|{task_id}|{field}` AAD (`services/shared/src/tasqr/crypto.py` in the `llm_task_tracker` repo), and the server likewise has no v1 reader. The two never decrypt each other's blobs — a managed org's data never passes through this proxy's crypto, and a BYOK org's never passes through the server's — so the formats can't break each other at runtime. Keep them identical anyway: one format, one mental model, and one thing to reason about when auditing.

**Device flow** (`src/device_flow.js`): GitHub OAuth Device Flow used only for first-time signup. Polls GitHub for a token, then exchanges it with the Tasqr auth service (`POST {auth_url}/device`), which may prompt the user to pick a workspace (`promptChoice`) if their GitHub account belongs to multiple.

**Logging** (`src/logging.js`): append-only JSON-lines event log. Only structured event metadata is ever logged (e.g. `kms_decrypt`, `dek_loaded`, `encrypt`/`decrypt` with field _names_, never values) — never log plaintext DEK material or task content.

Level and path are configurable, both following the usual env var → credentials file → default precedence: `log_level` (`TASQR_LOG_LEVEL`) and `log_path` (`TASQR_LOG`, default `~/.config/tasqr/tasqr-mcp.log`). Levels are `off` (**default** — logging is opt-in; nothing touches disk unless asked for) / `info` / `debug`, and each event is assigned a level in `EVENT_LEVEL`: lifecycle events (`dek_loaded`, `kms_decrypt`, ~once per session) are `info`; per-tool-call events (`encrypt`, `decrypt`) are `debug`. An event missing from the table defaults to `info` so a new event stays visible rather than silently vanishing. An _absent_ level means `off`, but a level that is set-but-unrecognised (`debbug`) falls back to `info` rather than `off` — the user plainly wanted logging, so a typo must not silently give them none.

`logging.js` imports `readConfig` from `credentials.js`, which imports `logEvent` back — a genuine ESM import cycle. It works because both are hoisted `function` declarations; if either is ever converted to a `const` arrow function, the cycle will break at load time.

When adding an event, add it to `EVENT_LEVEL` (in **both** ports). Note that any test asserting "no plaintext in the log" must pin `TASQR_LOG_LEVEL=debug` **and** assert the event was actually written — otherwise the assertion is trivially true when nothing is logged, which is the same fail-open trap as the crypto tables.
