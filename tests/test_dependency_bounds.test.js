// Every runtime dependency must carry an upper bound.
//
// THE SHRINKWRAP DOES NOT SAVE US ON THE PATH WE ACTUALLY USE — measured
// 2026-08-12, and it is the whole reason these ranges are the real control.
// This package ships npm-shrinkwrap.json in `files` (the publishable lockfile,
// unlike package-lock.json) so that the tree users get is pinned. But
// `.mcp.json` invokes this proxy as `npx -y --package git+ssh://…#tag`, and a
// git-URL install resolves the manifest ranges fresh instead: of the 117
// top-level packages in the shrinkwrap, 32 came out at a DIFFERENT version than
// it pins (@aws-sdk/client-kms 3.1085.0 -> 3.1109.0, and so on down the tree).
// Do not reason about this package's dependencies from the shrinkwrap; check
// what a git install actually produces.
//
// So an unbounded range like `>=1.0.0` ships the next major to every user the
// day it lands. The Python port learned this the hard way — mcp 2.0 renamed
// `streamablehttp_client` and broke every `uvx` launch, which is why
// tests/test_dependency_bounds.py exists there. This is the mirror of it.
//
// Caret and tilde ranges already bound at the next major/minor, so today's manifest
// passes untouched. The test is here for the dependency added later out of habit as
// `>=x` or `*`, which reads as harmless and isn't. devDependencies are exempt: they
// never reach a user's launch.
import { test, describe } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';

const manifest = JSON.parse(
  readFileSync(join(dirname(fileURLToPath(import.meta.url)), '../package.json'), 'utf8'),
);

// An npm range is a set of `||`-separated comparator branches; the range is bounded
// only if every branch is. A branch is bounded when it pins an explicit ceiling
// (`<`), uses caret/tilde, or starts from a concrete version (`1`, `1.2.3`, `1.x`).
// `*`, `latest`, and a bare `>=`/`>` floor are not.
function isBounded(range) {
  return range
    .split('||')
    .map((branch) => branch.trim())
    .every((branch) => branch.includes('<') || /^[~^]|^\d/.test(branch));
}

function unboundedIn(field) {
  return Object.entries(manifest[field] ?? {}).filter(([, range]) => !isBounded(range));
}

describe('runtime dependency bounds', () => {
  test('every entry in dependencies has an upper bound', () => {
    const unbounded = unboundedIn('dependencies');
    assert.deepEqual(
      unbounded,
      [],
      'These ranges would let the next major version install itself on every `npx` ' +
        `launch — bound them at the next major: ${JSON.stringify(unbounded)}`,
    );
  });

  test('every entry in optionalDependencies has an upper bound', () => {
    const unbounded = unboundedIn('optionalDependencies');
    assert.deepEqual(
      unbounded,
      [],
      'Optional deps install by default and reach a user launch just like required ' +
        `ones — bound them at the next major: ${JSON.stringify(unbounded)}`,
    );
  });
});

// The MCP SDK needs a TIGHTER bound than the rest, and the reason is specific to
// it: the JS SDK ships PROTOCOL REVISIONS IN MINOR VERSIONS. The 1.x line has
// carried 2024-11-05, 2025-03-26, 2025-06-18 and now 2025-11-25 (1.30.0), and
// there is no 2.x — majors are only 0 and 1. So `^1.0.0` bounds the API surface
// but NOT the protocol era, which is the thing that actually breaks us: a client
// that starts speaking 2026-07-28 against our legacy server scores "Fails" on the
// spec's own compatibility matrix, at process startup, with no partial degradation.
//
// This port has no era negotiation of its own (the Python port gets it free from
// mcp 2.x's mode='auto'), so the manifest is the only place the era is decided.
// Pin at the minor: patches are fine, a new minor is a deliberate commit with the
// migration in it.
//
// npm-shrinkwrap.json pins 1.30.0 exactly, but see the header: it is not applied
// on the git-URL install path `.mcp.json` uses, so this range is the only thing
// standing between a user and a new protocol era.
test('the MCP SDK is pinned at the minor, not just the major', () => {
  const range = manifest.dependencies['@modelcontextprotocol/sdk'];
  assert.match(
    range,
    /^~\d+\.\d+\.\d+$/,
    `The JS MCP SDK ships protocol revisions in minor versions, so a caret range ` +
      `does not bound the protocol era. Pin it as ~<major>.<minor>.<patch>; got "${range}".`,
  );
});
