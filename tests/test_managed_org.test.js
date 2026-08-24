/**
 * A managed org must never be client-encrypted, even if the profile is set up for BYOK.
 *
 * The server is authoritative: GET /org/dek returns 200 (client_byok), 409 (server-managed),
 * or 404 (BYOK-eligible but unenrolled). The proxy used to decide purely from local config,
 * which double-wrapped every write to a managed org.
 *
 * Node port of the Python repo's tests/test_managed_org.py; keep the two in step.
 * (Python's error-reporting tests for anyio ExceptionGroups and the CLI exit path
 * are runtime-specific and have no Node counterpart.)
 */
import { test, describe } from 'node:test';
import assert from 'node:assert/strict';
import { randomBytes } from 'node:crypto';
import {
  tempHome,
  writeCredentials,
  readCredentials,
  stubFetch,
  installKmsMock,
  canMockKms,
  KMS_SKIP_REASON,
} from './helpers.js';

const DEK = randomBytes(32);
const KMS_KEY = 'arn:aws:kms:us-east-1:123:key/test';
const WRAPPED = Buffer.from('fake-wrapped').toString('base64');

const MANAGED_BODY = {
  error: 'org uses server-managed encryption; do not client-encrypt',
  key_provider: 'managed',
};

// The KMS mock is installed whenever it can be; the refusal tests must pass with
// or without it (in the no-optional-deps CI job the SDK is genuinely absent, which
// is an even stronger version of "KMS must never be reached").
const kms = canMockKms ? installKmsMock() : null;

const CFG = { api_key: 'k', kms_key_id: KMS_KEY, aws_profile: 'default' };

describe('managed org must not be client-encrypted', () => {
  test('409 -> refuses, even though kms_key_id is configured', async (t) => {
    const home = tempHome(t);
    writeCredentials(home, { api_key: 'k', kms_key_id: KMS_KEY });
    kms?.reset();
    const calls = stubFetch(t, () => ({ status: 409, body: MANAGED_BODY }));

    const { fetchOrGenerateDek, ManagedOrgError } = await import('../src/credentials.js');
    await assert.rejects(
      () => fetchOrGenerateDek(CFG),
      (err) => {
        assert.ok(
          err instanceof ManagedOrgError,
          `expected ManagedOrgError, got ${err.constructor.name}`,
        );
        // The message must tell the user how to fix it.
        assert.match(err.message, /server-managed/);
        assert.match(err.message, /kms_key_id/);
        return true;
      },
    );
    assert.equal(calls.length, 1, 'server must have been consulted');
    // And we must not have touched KMS at all.
    if (kms) assert.equal(kms.constructions, 0);
  });

  test('409 -> refuses even when a wrapped_dek is cached locally', async (t) => {
    // The regression that caused the corruption: the cached DEK used to short-circuit
    // before any server call, so a profile pointed at a managed org silently encrypted.
    // The cache lives in the credentials *file* (readConfig()), so it must be planted
    // there — a wrapped_dek on the cfg argument alone never reaches the cache path.
    const home = tempHome(t);
    writeCredentials(home, { api_key: 'k', kms_key_id: KMS_KEY, wrapped_dek: WRAPPED });
    kms?.reset();
    const calls = stubFetch(t, () => ({ status: 409, body: MANAGED_BODY }));

    const { fetchOrGenerateDek, ManagedOrgError } = await import('../src/credentials.js');
    await assert.rejects(
      () => fetchOrGenerateDek({ ...CFG, wrapped_dek: WRAPPED }),
      (err) => {
        // Assert the concrete type — passing a bare (possibly undefined) class to
        // assert.rejects would accept ANY rejection and pass for the wrong reason.
        assert.ok(
          err instanceof ManagedOrgError,
          `expected ManagedOrgError, got ${err.constructor.name}: ${err.message}`,
        );
        return true;
      },
    );
    assert.equal(calls.length, 1, 'cache must not win over the server');
    // The cached DEK must never have been unwrapped.
    if (kms) assert.equal(kms.decryptCalls, 0);
  });

  test(
    '409 -> refuses even when AWS is unusable',
    { skip: canMockKms ? false : KMS_SKIP_REASON },
    async (t) => {
      // The refusal must not depend on AWS being installed or configured — the KMS
      // client is built only after the probe, so a broken profile can't mask the 409.
      const home = tempHome(t);
      writeCredentials(home, { api_key: 'k', kms_key_id: KMS_KEY });
      kms.reset();
      kms.constructorError = new Error('ProfileNotFound: the AWS profile does not exist');
      stubFetch(t, () => ({ status: 409, body: MANAGED_BODY }));

      const { fetchOrGenerateDek, ManagedOrgError } = await import('../src/credentials.js');
      await assert.rejects(
        () => fetchOrGenerateDek({ ...CFG, aws_profile: 'does-not-exist' }),
        (err) => err instanceof ManagedOrgError,
      );
      assert.equal(kms.constructions, 0);
    },
  );

  test(
    '200 -> the BYOK path is unchanged',
    { skip: canMockKms ? false : KMS_SKIP_REASON },
    async (t) => {
      const home = tempHome(t);
      writeCredentials(home, { api_key: 'k', kms_key_id: KMS_KEY });
      kms.reset();
      kms.decryptImpl = () => ({ Plaintext: DEK });
      stubFetch(t, () => ({
        status: 200,
        body: {
          wrapped_dek: WRAPPED,
          kms_key_id: KMS_KEY,
          key_provider: 'client_byok',
          org_id: 'org-managed-test',
        },
      }));

      const { fetchOrGenerateDek } = await import('../src/credentials.js');
      const [dek, source, orgId] = await fetchOrGenerateDek(CFG);

      assert.ok(dek.equals(DEK));
      assert.equal(source, 'api');
      assert.equal(orgId, 'org-managed-test');
      assert.equal(readCredentials(home).wrapped_dek, WRAPPED);
    },
  );

  test('runProxy surfaces the refusal instead of silently double-encrypting', async (t) => {
    // End-to-end through the real proxy entry point: kms_key_id in the credentials
    // file makes runProxy build ClientCrypto, whose init hits the 409 — the error
    // must escape before any upstream MCP connection is attempted.
    const home = tempHome(t);
    writeCredentials(home, { api_key: 'k', kms_key_id: KMS_KEY });
    kms?.reset();
    stubFetch(t, () => ({ status: 409, body: MANAGED_BODY }));

    const { ManagedOrgError } = await import('../src/credentials.js');
    const { runProxy } = await import('../src/proxy.js');
    await assert.rejects(
      () => runProxy('api-key'),
      (err) => err instanceof ManagedOrgError,
    );
  });
});
