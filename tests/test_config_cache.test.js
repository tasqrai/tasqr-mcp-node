// Config cache behaviour: wrapped_dek read/write lifecycle.
// Node port of the Python repo's tests/test_config_cache.py; keep the two in step.
import { test, describe } from 'node:test';
import assert from 'node:assert/strict';
import { randomBytes } from 'node:crypto';
import {
  tempHome,
  writeCredentials,
  readCredentials,
  stubFetch,
  installKmsMock,
  kmsServiceError,
  canMockKms,
  KMS_SKIP_REASON,
} from './helpers.js';

const DEK = randomBytes(32);
const KMS_KEY = 'arn:aws:kms:us-east-1:123:key/test';
const WRAPPED = Buffer.from('fake-wrapped').toString('base64');
const NEW_WRAPPED = Buffer.from('new-wrapped').toString('base64');

const kms = canMockKms ? installKmsMock() : null;
const skip = canMockKms ? false : KMS_SKIP_REASON;

const CFG = { api_key: 'tasqr_test', kms_key_id: KMS_KEY, aws_profile: 'default' };

function byokBody(wrapped, orgId = 'org-cache') {
  return { wrapped_dek: wrapped, kms_key_id: KMS_KEY, key_provider: 'client_byok', org_id: orgId };
}

describe('wrapped_dek config cache', () => {
  test('no cache → API fetch result is written to config', { skip }, async (t) => {
    const home = tempHome(t);
    writeCredentials(home, { api_key: 'tasqr_test', kms_key_id: KMS_KEY });
    stubFetch(t, () => ({ status: 200, body: byokBody(WRAPPED) }));
    kms.reset();
    kms.decryptImpl = () => ({ Plaintext: DEK });

    const { fetchOrGenerateDek } = await import('../src/credentials.js');
    const [, source] = await fetchOrGenerateDek(CFG);

    assert.equal(source, 'api');
    assert.equal(readCredentials(home).wrapped_dek, WRAPPED);
  });

  test('cached wrapped_dek spares the KMS unwrap, not the server probe', { skip }, async (t) => {
    const home = tempHome(t);
    writeCredentials(home, { api_key: 'tasqr_test', kms_key_id: KMS_KEY, wrapped_dek: WRAPPED });
    const calls = stubFetch(t, () => ({ status: 200, body: byokBody(WRAPPED) }));
    kms.reset();
    kms.decryptImpl = () => ({ Plaintext: DEK });

    const { fetchOrGenerateDek } = await import('../src/credentials.js');
    const [dek, source] = await fetchOrGenerateDek({ ...CFG, wrapped_dek: WRAPPED });

    assert.equal(source, 'config'); // cached DEK was used...
    assert.equal(calls.length, 1); // ...but only after asking the server
    assert.equal(kms.decryptCalls, 1);
    assert.ok(dek.equals(DEK));
  });

  test(
    'stale cache: KMS rejects the blob → drop it, fall back to the server blob',
    { skip },
    async (t) => {
      const home = tempHome(t);
      writeCredentials(home, { api_key: 'tasqr_test', kms_key_id: KMS_KEY, wrapped_dek: WRAPPED });
      stubFetch(t, () => ({ status: 200, body: byokBody(NEW_WRAPPED) }));
      kms.reset();
      kms.decryptImpl = (input) => {
        if (input.CiphertextBlob.equals(Buffer.from(WRAPPED, 'base64'))) {
          throw kmsServiceError('InvalidCiphertextException', 'stale');
        }
        return { Plaintext: DEK };
      };

      const { fetchOrGenerateDek } = await import('../src/credentials.js');
      const [dek, source] = await fetchOrGenerateDek({ ...CFG, wrapped_dek: WRAPPED });

      assert.equal(source, 'api');
      assert.equal(kms.decryptCalls, 2);
      assert.ok(dek.equals(DEK));
      assert.equal(readCredentials(home).wrapped_dek, NEW_WRAPPED); // stale value replaced
    },
  );

  // Only "KMS looked at the blob and said no" means stale. Anything else —
  // network down, credentials unresolvable, SDK missing — must leave the cache
  // alone and surface as-is, exactly like the Python port's BotoClientError-only
  // handling. Deleting the cache on a transient failure costs the user a KMS
  // round trip on every retry and masks the real error.
  test('a non-KMS failure must not delete the cached wrapped_dek', { skip }, async (t) => {
    const home = tempHome(t);
    writeCredentials(home, { api_key: 'tasqr_test', kms_key_id: KMS_KEY, wrapped_dek: WRAPPED });
    stubFetch(t, () => ({ status: 200, body: byokBody(WRAPPED) }));
    kms.reset();
    kms.decryptImpl = () => {
      throw new Error('getaddrinfo ENOTFOUND kms.us-east-1.amazonaws.com'); // no $metadata
    };

    const { fetchOrGenerateDek } = await import('../src/credentials.js');
    await assert.rejects(
      () => fetchOrGenerateDek({ ...CFG, wrapped_dek: WRAPPED }),
      /ENOTFOUND/, // the real error, not a wrapped "check your config" one
    );
    assert.equal(readCredentials(home).wrapped_dek, WRAPPED, 'cache must survive');
  });

  test(
    'a non-KMS failure on the API blob propagates raw, not as ConfigurationError',
    { skip },
    async (t) => {
      const home = tempHome(t);
      writeCredentials(home, { api_key: 'tasqr_test', kms_key_id: KMS_KEY });
      stubFetch(t, () => ({ status: 200, body: byokBody(WRAPPED) }));
      kms.reset();
      kms.decryptImpl = () => {
        throw new Error('getaddrinfo ENOTFOUND kms.us-east-1.amazonaws.com');
      };

      const { fetchOrGenerateDek, ConfigurationError } = await import('../src/credentials.js');
      await assert.rejects(
        () => fetchOrGenerateDek(CFG),
        (err) => {
          assert.ok(!(err instanceof ConfigurationError), 'must not be wrapped');
          assert.match(err.message, /ENOTFOUND/);
          return true;
        },
      );
    },
  );

  test('a KMS rejection of the API blob is wrapped with config guidance', { skip }, async (t) => {
    const home = tempHome(t);
    writeCredentials(home, { api_key: 'tasqr_test', kms_key_id: KMS_KEY });
    stubFetch(t, () => ({ status: 200, body: byokBody(WRAPPED) }));
    kms.reset();
    kms.decryptImpl = () => {
      throw kmsServiceError('AccessDeniedException', 'not authorized');
    };

    const { fetchOrGenerateDek, ConfigurationError } = await import('../src/credentials.js');
    await assert.rejects(
      () => fetchOrGenerateDek(CFG),
      (err) => {
        assert.ok(err instanceof ConfigurationError);
        assert.match(err.message, /aws_profile|kms_key_id/);
        return true;
      },
    );
  });
});
