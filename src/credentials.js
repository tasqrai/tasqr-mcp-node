import { readFileSync, writeFileSync, mkdirSync, existsSync, chmodSync } from 'node:fs';
import { homedir } from 'node:os';
import { join, dirname } from 'node:path';
import { logEvent } from './logging.js';

function credentialsPath() {
  if (process.platform === 'win32') {
    const appdata = process.env.APPDATA ?? homedir();
    return join(appdata, 'tasqr', 'credentials');
  }
  return join(homedir(), '.config', 'tasqr', 'credentials');
}

function profile() {
  return process.env.TASQR_PROFILE ?? 'default';
}

function parseIni(content) {
  const sections = {};
  let current = null;
  for (const line of content.split('\n')) {
    const trimmed = line.trim();
    const m = trimmed.match(/^\[(.+)]$/);
    if (m) {
      current = m[1];
      sections[current] = {};
    } else if (current && trimmed.includes('=')) {
      const eq = trimmed.indexOf('=');
      sections[current][trimmed.slice(0, eq).trim()] = trimmed.slice(eq + 1).trim();
    }
  }
  return sections;
}

function serializeIni(sections) {
  return (
    Object.entries(sections)
      .map(
        ([name, vals]) =>
          `[${name}]\n${Object.entries(vals)
            .map(([k, v]) => `${k} = ${v}`)
            .join('\n')}`,
      )
      .join('\n\n') + '\n'
  );
}

export function readConfig() {
  const path = credentialsPath();
  if (!existsSync(path)) return {};
  try {
    return parseIni(readFileSync(path, 'utf8'))[profile()] ?? {};
  } catch {
    return {};
  }
}

export function readApiKey() {
  const path = credentialsPath();
  if (!existsSync(path)) return null;
  try {
    return parseIni(readFileSync(path, 'utf8'))[profile()]?.api_key ?? null;
  } catch {
    return null;
  }
}

// Persist the credentials file restricted to the owner. The `mode` on writeFileSync
// only applies when *creating* the file; the trailing chmod also tightens a
// pre-existing looser file (e.g. one a user created by hand as 0644).
function writeSecret(path, data) {
  mkdirSync(dirname(path), { recursive: true, mode: 0o700 });
  writeFileSync(path, data, { mode: 0o600 });
  try {
    chmodSync(path, 0o600);
  } catch {}
}

export function writeApiKey(apiKey) {
  const path = credentialsPath();
  let sections = {};
  if (existsSync(path)) {
    try {
      sections = parseIni(readFileSync(path, 'utf8'));
    } catch {}
  }
  const p = profile();
  if (!sections[p]) sections[p] = {};
  sections[p].api_key = apiKey;
  writeSecret(path, serializeIni(sections));
}

export function writeConfigValue(key, value) {
  const path = credentialsPath();
  let sections = {};
  if (existsSync(path)) {
    try {
      sections = parseIni(readFileSync(path, 'utf8'));
    } catch {}
  }
  const p = profile();
  if (!sections[p]) sections[p] = {};
  sections[p][key] = value;
  writeSecret(path, serializeIni(sections));
}

function deleteConfigValue(key) {
  const path = credentialsPath();
  if (!existsSync(path)) return;
  let sections;
  try {
    sections = parseIni(readFileSync(path, 'utf8'));
  } catch {
    return;
  }
  const p = profile();
  if (sections[p]) {
    delete sections[p][key];
    writeSecret(path, serializeIni(sections));
  }
}

export class ConfigurationError extends Error {}

/**
 * The org is server-managed, so client-side encryption must not run.
 *
 * Encrypting anyway would double-wrap: the server would encrypt our ciphertext again
 * with the org DEK, leaving data readable only by a key it has no record of.
 */
export class ManagedOrgError extends ConfigurationError {}

export async function fetchOrGenerateDek(cfg) {
  const apiKey = cfg.api_key ?? '';
  const kmsKeyId = cfg.kms_key_id ?? '';
  const apiUrl = cfg.api_url ?? 'https://api.tasqr.ai';
  const awsProfile = cfg.aws_profile ?? 'default';

  // The KMS SDK is loaded lazily, *after* the org-state probe below. @aws-sdk/client-kms
  // is an optional dependency, and refusing to encrypt for a managed org must not depend
  // on AWS being installed or configured — so don't hoist this import.
  let kms, DecryptCommand, GenerateDataKeyCommand;
  async function initKms() {
    if (kms) return;
    const sdk = await import('@aws-sdk/client-kms');
    ({ DecryptCommand, GenerateDataKeyCommand } = sdk);
    const { fromIni } = await import('@aws-sdk/credential-providers');
    const region = kmsKeyId.startsWith('arn:aws:kms:')
      ? kmsKeyId.split(':')[3]
      : (process.env.AWS_DEFAULT_REGION ?? 'us-east-1');
    const kmsConfig = { region };
    if (awsProfile && awsProfile !== 'default') {
      kmsConfig.credentials = fromIni({ profile: awsProfile });
    }
    kms = new sdk.KMSClient(kmsConfig);
  }

  async function kmsDecrypt(wrappedB64) {
    await initKms();
    const blob = Buffer.from(wrappedB64, 'base64');
    const resp = await kms.send(new DecryptCommand({ CiphertextBlob: blob, KeyId: kmsKeyId }));
    logEvent('kms_decrypt', { profile: awsProfile });
    return Buffer.from(resp.Plaintext);
  }

  // The analogue of boto3's ClientError: KMS answered with an error response
  // (stale ciphertext, access denied, ...). Transport failures, unresolvable
  // credentials, and a missing SDK carry no HTTP status and are NOT the blob's
  // fault — they must propagate untouched.
  function isKmsServiceError(err) {
    return err?.$metadata?.httpStatusCode !== undefined;
  }

  function orgIdOrThrow(body) {
    if (!body.org_id) {
      throw new ConfigurationError(
        "The server's /org/dek response carried no org_id — the proxy needs it to " +
          'bind ciphertext AAD. The Tasqr server is older than this client.',
      );
    }
    return body.org_id;
  }

  /**
   * Ask the server what this org is. Returns [keyProvider, wrappedDek, orgId].
   *   200 -> ['client_byok', <wrapped>, orgId]  encrypt with it
   *   409 -> throws ManagedOrgError              server-managed; must not client-encrypt
   *   404 -> ['unenrolled', null, null]          BYOK-eligible, no DEK yet
   */
  async function fetchDekFromApi() {
    const r = await fetch(`${apiUrl}/org/dek`, {
      headers: { 'X-Api-Key': apiKey },
    });
    if (r.status === 409) {
      throw new ManagedOrgError(
        'This org uses server-managed encryption, so the proxy must not client-encrypt ' +
          '(doing so would double-wrap your data and make it unreadable to everything ' +
          'except this machine).\n' +
          `Remove kms_key_id and wrapped_dek from profile [${profile()}] in ` +
          `${credentialsPath()}, or enroll the org in client-side BYOK.`,
      );
    }
    if (r.status === 404) return ['unenrolled', null, null];
    if (!r.ok) throw new Error(`GET /org/dek failed: ${r.status}`);
    const body = await r.json();
    return ['client_byok', body.wrapped_dek, orgIdOrThrow(body)];
  }

  /** PUT wrapped DEK. Returns orgId on 201, null on 409 (already set). */
  async function putDekToApi(wrappedB64) {
    const r = await fetch(`${apiUrl}/org/dek`, {
      method: 'PUT',
      headers: { 'X-Api-Key': apiKey, 'Content-Type': 'application/json' },
      body: JSON.stringify({ wrapped_dek: wrappedB64, kms_key_id: kmsKeyId }),
    });
    if (r.status === 409) return null;
    if (!r.ok) throw new Error(`PUT /org/dek failed: ${r.status}`);
    return orgIdOrThrow(await r.json());
  }

  // Step 1: The server is authoritative about whether this org may be client-encrypted.
  // This MUST happen before any use of a locally cached wrapped_dek — a managed org must
  // never be client-encrypted, and only the server knows. Throws ManagedOrgError on 409.
  const [keyProvider, wrappedFromApi, orgIdFromApi] = await fetchDekFromApi();
  let wrappedB64 = wrappedFromApi;
  let orgId = orgIdFromApi;

  // Step 2: BYOK confirmed — now the local cache is safe to use, and saves a KMS round trip.
  if (keyProvider === 'client_byok') {
    const cached = readConfig().wrapped_dek;
    if (cached) {
      try {
        return [await kmsDecrypt(cached), 'config', orgId];
      } catch (e) {
        if (!isKmsServiceError(e)) throw e;
        // Stale — drop it and fall back to the server's blob.
        deleteConfigValue('wrapped_dek');
      }
    }
  }

  if (wrappedB64 === null) {
    // Step 3: Generate
    await initKms();
    const resp = await kms.send(
      new GenerateDataKeyCommand({ KeyId: kmsKeyId, KeySpec: 'AES_256' }),
    );
    const plaintextDek = Buffer.from(resp.Plaintext);
    wrappedB64 = Buffer.from(resp.CiphertextBlob).toString('base64');
    orgId = await putDekToApi(wrappedB64);
    if (orgId === null) {
      // Lost the race — fetch the winner's blob.
      [, wrappedB64, orgId] = await fetchDekFromApi();
      if (!wrappedB64)
        throw new ConfigurationError(
          'Failed to set up encryption key. Check kms_key_id in config.',
        );
      const dek = await kmsDecrypt(wrappedB64);
      writeConfigValue('wrapped_dek', wrappedB64);
      return [dek, 'api', orgId];
    }
    writeConfigValue('wrapped_dek', wrappedB64);
    return [plaintextDek, 'api', orgId];
  }

  try {
    const dek = await kmsDecrypt(wrappedB64);
    writeConfigValue('wrapped_dek', wrappedB64);
    return [dek, 'api', orgId];
  } catch (e) {
    if (!isKmsServiceError(e)) throw e;
    throw new ConfigurationError(
      `KMS Decrypt failed after API fetch. Check aws_profile and kms_key_id. Error: ${e.message}`,
    );
  }
}
