// Shared plumbing for tests that exercise src/credentials.js for real:
// a throwaway $HOME so readConfig()/writeConfigValue() hit a real INI file,
// a recording fetch stub, and a mocked @aws-sdk/client-kms.
//
// The KMS mock uses node:test's mock.module (registered before credentials.js
// dynamically imports the SDK), which needs two preconditions:
//   - --experimental-test-module-mocks (set in the npm test script), and
//   - the optional @aws-sdk packages actually installed — mock.module still
//     resolves the specifier, so the no-optional-deps CI job can't use it.
// Tests that need the mock must skip when `canMockKms` is false. That skip is
// sound: the paths those tests cover (GenerateDataKey, Decrypt) cannot run
// without the SDK in production either, and the SDK-absent behavior has its
// own tests that don't touch KMS.
import { mock } from 'node:test';
import { mkdtempSync, mkdirSync, writeFileSync, readFileSync, existsSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';

const repoRoot = join(dirname(fileURLToPath(import.meta.url)), '..');

export const sdkPresent = existsSync(join(repoRoot, 'node_modules', '@aws-sdk', 'client-kms'));

function moduleMocksAvailable() {
  try {
    // Probe with a harmless builtin; restore immediately.
    mock.module('node:querystring', { namedExports: {} }).restore();
    return true;
  } catch {
    return false;
  }
}

export const canMockKms = sdkPresent && moduleMocksAvailable();
export const KMS_SKIP_REASON =
  'needs the optional @aws-sdk packages installed and --experimental-test-module-mocks';

/**
 * Point $HOME (and therefore the credentials file and default log path) at a
 * fresh temp dir for the duration of the test. POSIX-only, like CI.
 */
export function tempHome(t) {
  const home = mkdtempSync(join(tmpdir(), 'tasqr-test-home-'));
  const saved = { HOME: process.env.HOME, TASQR_PROFILE: process.env.TASQR_PROFILE };
  process.env.HOME = home;
  delete process.env.TASQR_PROFILE;
  t.after(() => {
    process.env.HOME = saved.HOME;
    if (saved.TASQR_PROFILE !== undefined) process.env.TASQR_PROFILE = saved.TASQR_PROFILE;
    rmSync(home, { recursive: true, force: true });
  });
  return home;
}

export function writeCredentials(home, values) {
  const dir = join(home, '.config', 'tasqr');
  mkdirSync(dir, { recursive: true });
  const body =
    '[default]\n' +
    Object.entries(values)
      .map(([k, v]) => `${k} = ${v}`)
      .join('\n') +
    '\n';
  writeFileSync(join(dir, 'credentials'), body);
}

/** Read the [default] section back out of the temp credentials file. */
export function readCredentials(home) {
  const path = join(home, '.config', 'tasqr', 'credentials');
  if (!existsSync(path)) return {};
  const out = {};
  let section = null;
  for (const line of readFileSync(path, 'utf8').split('\n')) {
    const trimmed = line.trim();
    const m = trimmed.match(/^\[(.+)]$/);
    if (m) {
      section = m[1];
    } else if (section === 'default' && trimmed.includes('=')) {
      const eq = trimmed.indexOf('=');
      out[trimmed.slice(0, eq).trim()] = trimmed.slice(eq + 1).trim();
    }
  }
  return out;
}

/**
 * Replace globalThis.fetch with a recording stub for the duration of the test.
 * `handler(call, n)` returns {status, body} for the n-th call (1-based).
 */
export function stubFetch(t, handler) {
  const calls = [];
  const saved = globalThis.fetch;
  globalThis.fetch = async (url, opts) => {
    const call = { url: String(url), method: opts?.method ?? 'GET' };
    calls.push(call);
    const { status, body } = handler(call, calls.length);
    return { status, ok: status >= 200 && status < 300, json: async () => body };
  };
  t.after(() => {
    globalThis.fetch = saved;
  });
  return calls;
}

/**
 * Mock @aws-sdk/client-kms (and credential-providers) for this whole test file.
 * Call once at module load, only when `canMockKms`; set the per-test behavior
 * via the returned state object and call state.reset() at the top of each test.
 */
export function installKmsMock() {
  const state = {
    decryptImpl: null, // (input) => ({ Plaintext: Buffer })
    generateImpl: null, // (input) => ({ Plaintext: Buffer, CiphertextBlob: Buffer })
    constructorError: null, // set to make `new KMSClient()` throw
    decryptCalls: 0,
    generateCalls: 0,
    constructions: 0,
    reset() {
      this.decryptImpl = null;
      this.generateImpl = null;
      this.constructorError = null;
      this.decryptCalls = 0;
      this.generateCalls = 0;
      this.constructions = 0;
    },
  };

  class DecryptCommand {
    constructor(input) {
      this.input = input;
    }
  }
  class GenerateDataKeyCommand {
    constructor(input) {
      this.input = input;
    }
  }
  class KMSClient {
    constructor() {
      state.constructions += 1;
      if (state.constructorError) throw state.constructorError;
    }
    async send(cmd) {
      if (cmd instanceof DecryptCommand) {
        state.decryptCalls += 1;
        return state.decryptImpl(cmd.input);
      }
      state.generateCalls += 1;
      return state.generateImpl(cmd.input);
    }
  }

  mock.module('@aws-sdk/client-kms', {
    namedExports: { KMSClient, DecryptCommand, GenerateDataKeyCommand },
  });
  mock.module('@aws-sdk/credential-providers', {
    namedExports: { fromIni: () => async () => ({}) },
  });
  return state;
}

/** An error shaped like an AWS SDK v3 service response error (boto ClientError's analogue). */
export function kmsServiceError(name, message) {
  return Object.assign(new Error(`${name}: ${message}`), {
    name,
    $metadata: { httpStatusCode: 400 },
  });
}
