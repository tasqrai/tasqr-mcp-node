// First-time DEK setup — GenerateDataKey path and concurrent loser race.
// Node port of the Python repo's tests/test_first_time.py; keep the two in step.
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
const WINNER_WRAPPED = Buffer.from('winner-wrapped').toString('base64');

const kms = canMockKms ? installKmsMock() : null;
const skip = canMockKms ? false : KMS_SKIP_REASON;

describe('first-time DEK setup', () => {
  test(
    'GET 404 → GenerateDataKey → PUT 201 → wrapped_dek cached, source is api',
    { skip },
    async (t) => {
      const home = tempHome(t);
      writeCredentials(home, { api_key: 'tasqr_test', kms_key_id: KMS_KEY });
      const calls = stubFetch(t, (call) =>
        call.method === 'PUT'
          ? { status: 201, body: { status: 'created', org_id: 'org-first' } }
          : { status: 404, body: {} },
      );
      kms.reset();
      kms.generateImpl = () => ({
        Plaintext: DEK,
        CiphertextBlob: Buffer.from('kms-generated-wrapped'),
      });

      const { fetchOrGenerateDek } = await import('../src/credentials.js');
      const [dek, source, orgId] = await fetchOrGenerateDek({
        api_key: 'tasqr_test',
        kms_key_id: KMS_KEY,
        aws_profile: 'default',
      });

      // The DEK came from the enrollment round-trip with the API, and the label
      // must say so — the Python port never emits anything else here.
      assert.equal(source, 'api');
      assert.equal(orgId, 'org-first');
      assert.ok(dek.equals(DEK));
      assert.equal(kms.generateCalls, 1);
      assert.deepEqual(
        calls.map((c) => c.method),
        ['GET', 'PUT'],
      );
      assert.equal(
        readCredentials(home).wrapped_dek,
        Buffer.from('kms-generated-wrapped').toString('base64'),
      );
    },
  );

  test(
    'concurrent loser: PUT 409 → re-fetch → decrypt and cache the winner blob',
    { skip },
    async (t) => {
      const home = tempHome(t);
      writeCredentials(home, { api_key: 'tasqr_test', kms_key_id: KMS_KEY });
      let gets = 0;
      stubFetch(t, (call) => {
        if (call.method === 'PUT') return { status: 409, body: {} };
        gets += 1;
        return gets === 1
          ? { status: 404, body: {} }
          : {
              status: 200,
              body: { wrapped_dek: WINNER_WRAPPED, kms_key_id: KMS_KEY, org_id: 'org-win' },
            };
      });
      kms.reset();
      kms.generateImpl = () => ({
        Plaintext: randomBytes(32), // our losing DEK — must not be the one returned
        CiphertextBlob: Buffer.from('my-wrapped'),
      });
      kms.decryptImpl = () => ({ Plaintext: DEK });

      const { fetchOrGenerateDek } = await import('../src/credentials.js');
      const [dek, source, orgId] = await fetchOrGenerateDek({
        api_key: 'tasqr_test',
        kms_key_id: KMS_KEY,
        aws_profile: 'default',
      });

      assert.equal(orgId, 'org-win');
      assert.equal(gets, 2); // first 404, second 200 (winner's blob)
      assert.equal(kms.decryptCalls, 1);
      assert.ok(dek.equals(DEK));
      assert.equal(source, 'api');
      assert.equal(readCredentials(home).wrapped_dek, WINNER_WRAPPED);
    },
  );
});
