// Public client ID for the Tasqr GitHub OAuth App.
// Find it at: github.com → Settings → Developer settings → OAuth Apps → Tasqr
// Device Flow must be enabled on the app.
import { execFile, spawnSync } from 'node:child_process';
import { createInterface } from 'node:readline/promises';
import { readConfig } from './credentials.js';

const GITHUB_CLIENT_ID = process.env.TASQR_GITHUB_CLIENT_ID ?? 'Ov23liHc2GB3yXBniiy1';
const DEFAULT_AUTH_URL = 'https://auth.tasqr.ai';

function authUrl() {
  return process.env.TASQR_AUTH_URL || readConfig().auth_url || DEFAULT_AUTH_URL;
}

export async function runDeviceFlow() {
  process.stderr.write('\nNo Tasqr credentials found. Starting signup...\n');

  // Step 1: request device + user codes from GitHub
  const codeResp = await fetch('https://github.com/login/device/code', {
    method: 'POST',
    headers: { Accept: 'application/json', 'Content-Type': 'application/x-www-form-urlencoded' },
    body: new URLSearchParams({ client_id: GITHUB_CLIENT_ID, scope: 'user:email,read:org' }),
  });
  if (!codeResp.ok) {
    process.stderr.write(`GitHub error: ${codeResp.status}\n`);
    process.exit(1);
  }
  const {
    device_code,
    user_code,
    verification_uri,
    interval = 5,
    expires_in = 900,
  } = await codeResp.json();

  // Step 2: open browser and copy code to clipboard (URL pre-fill doesn't survive
  // GitHub's account-picker redirect added Jan 2024)
  openBrowser(verification_uri);
  const copied = copyToClipboard(user_code);
  process.stderr.write(
    `\n  Opening browser for GitHub authorization...\n` +
      (copied
        ? `  Code copied to clipboard — paste it in the browser: ${user_code}\n`
        : `  Enter code: ${user_code}\n`) +
      `Waiting for authorization...\n`,
  );

  // Step 3: poll GitHub until authorized or expired
  const deadline = Date.now() + expires_in * 1000;
  let pollMs = interval * 1000;
  let github_token = null;

  while (Date.now() < deadline) {
    await sleep(pollMs);
    const pollResp = await fetch('https://github.com/login/oauth/access_token', {
      method: 'POST',
      headers: { Accept: 'application/json', 'Content-Type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({
        client_id: GITHUB_CLIENT_ID,
        device_code,
        grant_type: 'urn:ietf:params:oauth:grant-type:device_code',
      }),
    });
    const poll = await pollResp.json();
    if (!poll.error) {
      github_token = poll.access_token;
      break;
    }
    if (poll.error === 'authorization_pending') continue;
    if (poll.error === 'slow_down') {
      pollMs += 5000;
      continue;
    }
    if (poll.error === 'expired_token') {
      process.stderr.write('\nCode expired. Run tasqr-mcp again.\n');
      process.exit(1);
    }
    if (poll.error === 'access_denied') {
      process.stderr.write('\nAuthorization denied.\n');
      process.exit(1);
    }
    process.stderr.write(`\nGitHub error: ${poll.error}\n`);
    process.exit(1);
  }

  if (!github_token) {
    process.stderr.write('\nTimed out waiting for authorization.\n');
    process.exit(1);
  }

  // Step 4: exchange for Tasqr API key
  return exchange(github_token);
}

async function exchange(github_token, choice = null) {
  const payload = { github_token };
  if (choice) payload.choice = choice;

  let resp;
  try {
    resp = await fetch(`${authUrl()}/device`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(payload),
    });
  } catch (err) {
    process.stderr.write(`\nCould not reach Tasqr: ${err.message}\n`);
    process.exit(1);
  }

  const data = await resp.json();
  if (resp.status === 429) {
    process.stderr.write(`\n${data.error ?? 'Capacity limit reached.'}\n`);
    process.exit(1);
  }
  if (!resp.ok) {
    process.stderr.write(`\nTasqr error: ${data.error ?? resp.status}\n`);
    process.exit(1);
  }

  if (data.choose) return promptChoice(github_token, data.choose, data.email ?? '');

  const apiKey = data.api_key;
  if (!apiKey) {
    process.stderr.write(`\nUnexpected response: ${JSON.stringify(data)}\n`);
    process.exit(1);
  }
  const action = data.reissued ? 'Key reissued' : 'Signup complete';
  process.stderr.write(`\n${action}! Signed in as ${data.email ?? ''}.\n`);
  return apiKey;
}

async function promptChoice(github_token, options, email) {
  const all = [...options, { value: 'personal', label: 'Personal workspace', action: 'create' }];
  process.stderr.write(`\nSigned in as ${email}. Choose a workspace:\n\n`);
  all.forEach((opt, i) => {
    const action = opt.action === 'join' ? 'Join' : 'Create';
    process.stderr.write(`  ${i + 1}. ${opt.label}  (${action})\n`);
  });
  process.stderr.write('\n');

  const rl = createInterface({ input: process.stdin, output: process.stderr });
  while (true) {
    const raw = await rl.question('Enter number: ');
    const n = parseInt(raw, 10);
    if (n >= 1 && n <= all.length) {
      rl.close();
      return exchange(github_token, all[n - 1].value);
    }
    process.stderr.write(`  Please enter 1–${all.length}.\n`);
  }
}

function copyToClipboard(text) {
  try {
    const [cmd, args] =
      process.platform === 'win32'
        ? ['clip', []]
        : process.platform === 'darwin'
          ? ['pbcopy', []]
          : ['xclip', ['-selection', 'clipboard']];
    return spawnSync(cmd, args, { input: text }).status === 0;
  } catch {
    return false;
  }
}

function openBrowser(url) {
  // execFile with an argv array (no shell) so a crafted verification_uri can't inject
  // a command. On Windows `start` is a cmd builtin, so route through cmd explicitly.
  if (process.platform === 'win32') {
    execFile('cmd', ['/c', 'start', '', url]);
  } else {
    execFile(process.platform === 'darwin' ? 'open' : 'xdg-open', [url]);
  }
}

function sleep(ms) {
  return new Promise((r) => setTimeout(r, ms));
}
