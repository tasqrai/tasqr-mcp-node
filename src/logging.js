import { appendFileSync, mkdirSync } from 'node:fs';
import { homedir } from 'node:os';
import { join, dirname } from 'node:path';

import { readConfig } from './credentials.js';

// Levels, coarsest first. 'off' silences the log entirely, and is the default:
// nothing touches disk unless the user opts in.
const OFF = 0,
  INFO = 1,
  DEBUG = 2;
const LEVELS = { off: OFF, info: INFO, debug: DEBUG };

// What each event costs you. Lifecycle events fire about once per session; the
// per-call ones fire on every tool call, so they only appear at debug.
const EVENT_LEVEL = {
  dek_loaded: INFO,
  kms_decrypt: INFO,
  encrypt: DEBUG,
  decrypt: DEBUG,
};
const DEFAULT_EVENT_LEVEL = INFO; // an unmapped event stays visible rather than vanishing

function config() {
  try {
    return readConfig();
  } catch {
    return {};
  }
}

/**
 * Resolved log level. Precedence: env var -> credentials file -> default (off).
 *
 * Logging is opt-in: unset means off, so nothing is written to disk unless asked for.
 * But a value that is *set* and unrecognised (a typo like 'debbug') falls back to info
 * rather than off — the user plainly wanted logging, and silently giving them none
 * would hide the mistake.
 */
function level() {
  const raw = process.env.TASQR_LOG_LEVEL || config().log_level;
  if (!raw) return OFF;
  return LEVELS[String(raw).trim().toLowerCase()] ?? INFO;
}

// Neither an INI value nor an env var set from an MCP client's config passes
// through a shell, so a literal `~/...` (the README's own example) would
// otherwise create a `./~/` directory. (`~user` is not supported, as in the
// Python port's expanduser on platforms without pwd.)
function expandTilde(p) {
  if (p === '~') return homedir();
  if (p.startsWith('~/')) return join(homedir(), p.slice(2));
  return p;
}

/** Resolved log path. Precedence: env var -> credentials file -> default. */
function logPath() {
  if (process.env.TASQR_LOG) return expandTilde(process.env.TASQR_LOG);
  const configured = config().log_path;
  if (configured) return expandTilde(configured);
  if (process.platform === 'win32') {
    const appdata = process.env.APPDATA ?? homedir();
    return join(appdata, 'tasqr', 'tasqr-mcp.log');
  }
  return join(homedir(), '.config', 'tasqr', 'tasqr-mcp.log');
}

export function logEvent(event, fields = {}) {
  const lvl = level();
  if (lvl === OFF || (EVENT_LEVEL[event] ?? DEFAULT_EVENT_LEVEL) > lvl) return;

  const record = { event, ts: new Date().toISOString(), ...fields };
  const path = logPath();
  try {
    // 0700 like credentials' writeSecret — the default path shares the credential
    // dir. Applies only to directories this call creates.
    mkdirSync(dirname(path), { recursive: true, mode: 0o700 });
    // 0600: the log shares the credential directory; a future logEvent mistake
    // shouldn't be world-readable. Mode applies only when creating the file.
    appendFileSync(path, JSON.stringify(record) + '\n', { mode: 0o600 });
  } catch {
    // Never crash the proxy because of logging
  }
}
