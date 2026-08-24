import { createCipheriv, createDecipheriv, randomBytes, randomUUID } from 'node:crypto';
import { logEvent } from './logging.js';

const ENC_MARKER = '__tasqr_enc__';
const ENC_VERSION = 2;

// Tools whose args hold a list of task-like objects; each item is encrypted with the
// given field list. A single task is just a list of one. (Every task tool the server
// exposes is array-taking — there is no single-object encrypt table.)
export const ENCRYPT_LIST_TOOLS = {
  create_tasks: ['tasks', ['title', 'description', 'metadata']],
  update_tasks: ['updates', ['title', 'description', 'metadata', 'output', 'note']],
};

// Tools whose responses need decryption. get_tasks and list_tasks both return a
// {tasks:[...]} envelope, handled by the tasks-list branch in decryptResult (which
// also covers history notes and dependency titles).
// Exported (like ENCRYPT_LIST_TOOLS) so tests can pin the exact contents against
// tests/fixtures/crypto_tool_tables.json — both lookups fail open, so a stale
// table is a silent-plaintext bug, not a test failure.
export const DECRYPT_TOOLS = new Set(['get_tasks', 'list_tasks', 'claim_next_task']);
export const TASK_DEC_FIELDS = ['title', 'description', 'metadata', 'output'];

/** A client-side crypto invariant was violated (not a GCM tag failure). */
export class ClientCryptoError extends Error {}

/**
 * The marker's version is not the one this client speaks.
 *
 * v2 is the only format ever published. v1 was a dead pre-release format;
 * nothing reads or writes it.
 */
export class UnsupportedCiphertextError extends ClientCryptoError {}

export function isEncMarker(value) {
  if (typeof value === 'object' && value !== null && !Array.isArray(value)) {
    return ENC_MARKER in value && 'n' in value && 'ct' in value;
  }
  if (typeof value !== 'string') return false;
  try {
    const obj = JSON.parse(value);
    return (
      typeof obj === 'object' && obj !== null && ENC_MARKER in obj && 'n' in obj && 'ct' in obj
    );
  } catch {
    return false;
  }
}

export class ClientCrypto {
  #dek;
  #orgId;

  constructor(dek, orgId) {
    if (!orgId) {
      throw new ClientCryptoError('org_id is required — the AAD binds every ciphertext to it');
    }
    if (dek?.length !== 32) {
      // createCipheriv would throw at the first encrypt anyway; fail here so a
      // malformed DEK is caught at init, identically to the Python port.
      throw new ClientCryptoError(`DEK must be 32 bytes (AES-256), got ${dek?.length}`);
    }
    this.#dek = dek; // Buffer (32 bytes)
    this.#orgId = orgId;
  }

  static async init(cfg, { _fetchDek } = {}) {
    const fetchOrGenerateDek = _fetchDek ?? (await import('./credentials.js')).fetchOrGenerateDek;
    const [dek, source, orgId] = await fetchOrGenerateDek(cfg);
    logEvent('dek_loaded', { source });
    return new ClientCrypto(dek, orgId);
  }

  /**
   * The associated data that binds a ciphertext to its slot.
   *
   * Must be reconstructible byte-for-byte at decrypt time: org_id comes from
   * /org/dek verbatim, task_id from the record the blob arrived in (for
   * dependency titles, the *blocker's* id), field is the fixed field name.
   */
  _aad(taskId, field) {
    return Buffer.from(`v${ENC_VERSION}|${this.#orgId}|${taskId}|${field}`, 'utf8');
  }

  _encryptStr(plaintext, taskId, field) {
    const nonce = randomBytes(12);
    const cipher = createCipheriv('aes-256-gcm', this.#dek, nonce);
    cipher.setAAD(this._aad(taskId, field));
    const ct = Buffer.concat([
      cipher.update(plaintext, 'utf8'),
      cipher.final(),
      cipher.getAuthTag(),
    ]);
    const marker = {
      [ENC_MARKER]: ENC_VERSION,
      n: nonce.toString('base64'),
      ct: ct.toString('base64'),
    };
    return JSON.stringify(marker);
  }

  _decryptStr(markerOrObj, taskId, field) {
    const markerStr =
      typeof markerOrObj === 'object' && markerOrObj !== null
        ? JSON.stringify(markerOrObj)
        : markerOrObj;
    const marker = JSON.parse(markerStr);
    const version = marker[ENC_MARKER];
    if (version !== ENC_VERSION) {
      throw new UnsupportedCiphertextError(
        `This value was encrypted with tasqr-mcp ciphertext format v${version}; ` +
          `this client only reads v${ENC_VERSION}. Upgrade tasqr-mcp on every ` +
          'machine in your org (v1 was a pre-release format that no released ' +
          'client reads or writes).',
      );
    }
    const nonce = Buffer.from(marker.n, 'base64');
    const ctWithTag = Buffer.from(marker.ct, 'base64');
    const authTag = ctWithTag.slice(ctWithTag.length - 16);
    const ct = ctWithTag.slice(0, ctWithTag.length - 16);
    const decipher = createDecipheriv('aes-256-gcm', this.#dek, nonce);
    decipher.setAAD(this._aad(taskId, field));
    decipher.setAuthTag(authTag);
    try {
      return decipher.update(ct) + decipher.final('utf8');
    } catch {
      // Node's GCM failure ("Unsupported state or unable to authenticate data")
      // names neither the field nor the task — and the rejection is meant to be
      // a *signal*, so say what actually happened.
      throw new ClientCryptoError(
        `Failed to authenticate the encrypted '${field}' of task ${taskId} — the ` +
          'ciphertext was moved, tampered with, or sealed for a different slot. ' +
          'Refusing to decrypt.',
      );
    }
  }

  _encryptFields(d, fields, taskId) {
    d = { ...d };
    const encrypted = [];
    for (const field of fields) {
      if (!(field in d) || d[field] == null) continue;
      const plaintext =
        field === 'metadata' || field === 'output' ? JSON.stringify(d[field]) : String(d[field]);
      const encStr = this._encryptStr(plaintext, taskId, field);
      d[field] = field === 'metadata' || field === 'output' ? JSON.parse(encStr) : encStr;
      encrypted.push(field);
    }
    return [d, encrypted];
  }

  /**
   * Return a copy of args with sensitive fields encrypted.
   *
   * create_tasks items get a client-minted task_id (canonical UUID) if they don't
   * already carry one — the id must exist at encrypt time for the AAD to bind it,
   * so the proxy mints it and the server stores it as the task's primary key.
   * update_tasks items bind to the task_id they already carry.
   */
  encryptArgs(toolName, args) {
    if (!(toolName in ENCRYPT_LIST_TOOLS)) return args;
    const [listKey, fields] = ENCRYPT_LIST_TOOLS[toolName];
    const items = args[listKey];
    if (!Array.isArray(items)) return args;
    args = { ...args };
    const touched = new Set();
    args[listKey] = items.map((item, i) => {
      if (item == null || typeof item !== 'object' || Array.isArray(item)) return item;
      item = { ...item };
      if (toolName === 'create_tasks' && !item.task_id) {
        item.task_id = randomUUID();
      }
      if (!item.task_id || typeof item.task_id !== 'string') {
        throw new ClientCryptoError(
          `${listKey}[${i}] has no task_id — cannot bind its ciphertext. ` +
            'Include the task_id in every update item.',
        );
      }
      const [encItem, encrypted] = this._encryptFields(item, fields, item.task_id);
      encrypted.forEach((f) => touched.add(f));
      return encItem;
    });
    if (touched.size) logEvent('encrypt', { tool: toolName, fields: [...touched].sort() });
    return args;
  }

  static #requireId(taskId, what) {
    if (!taskId || typeof taskId !== 'string') {
      throw new ClientCryptoError(
        `Response carries an encrypted ${what} but no task_id to rebuild its AAD from — ` +
          'refusing to guess.',
      );
    }
    return taskId;
  }

  /**
   * Decrypt encrypted fields in a task object. Safe to run on any object.
   *
   * AAD reconstruction: the task's own fields and its history notes were sealed
   * under the task's id; a dependency summary's title is the *blocker's*
   * ciphertext, sealed under the blocker's id (dep.task_id).
   */
  _decryptTask(task) {
    task = { ...task };
    const taskId = task.task_id;
    for (const field of TASK_DEC_FIELDS) {
      if (isEncMarker(task[field])) {
        const plain = this._decryptStr(task[field], ClientCrypto.#requireId(taskId, field), field);
        task[field] = field === 'metadata' || field === 'output' ? JSON.parse(plain) : plain;
      }
    }
    if (Array.isArray(task.history)) {
      task.history = task.history.map((ev) => {
        if (isEncMarker(ev.note)) {
          return {
            ...ev,
            note: this._decryptStr(ev.note, ClientCrypto.#requireId(taskId, 'note'), 'note'),
          };
        }
        return ev;
      });
    }
    if (Array.isArray(task.dependencies)) {
      task.dependencies = task.dependencies.map((dep) => {
        if (isEncMarker(dep.title)) {
          return {
            ...dep,
            title: this._decryptStr(
              dep.title,
              ClientCrypto.#requireId(dep.task_id, 'dependency title'),
              'title',
            ),
          };
        }
        return dep;
      });
    }
    return task;
  }

  _decryptPayload(data) {
    if (Array.isArray(data)) return data.map((t) => this._decryptTask(t));
    if (!data || typeof data !== 'object') return data;
    if (data.task && typeof data.task === 'object') {
      // claim_next_task: {"claimed": true, "task": {...}}
      return { ...data, task: this._decryptTask(data.task) };
    }
    if (Array.isArray(data.tasks)) {
      // list_tasks: {"tasks": [...], "count": N, "cursor": ...} and
      // get_tasks: {"tasks": [...], "count": N, "not_found": [...]}
      // (a single-id get_tasks task carries its history in that object).
      return { ...data, tasks: data.tasks.map((t) => this._decryptTask(t)) };
    }
    // Defensive fallback for a bare task object (no current tool returns one).
    return this._decryptTask(data);
  }

  /**
   * Decrypt a CallToolResult.
   *
   * Tools that declare an outputSchema return the payload TWICE — serialized JSON in
   * `content` and the same object in `structuredContent` (MCP spec: a tool returning
   * structured content SHOULD also return the serialized JSON in a TextContent block).
   * Both carry ciphertext, so both must be decrypted and left in agreement. Passing
   * structuredContent through untouched leaks ciphertext to any client that prefers
   * the structured channel — and the outputSchema still validates, because an
   * encrypted marker serialized into a string field is still a string.
   */
  decryptResult(toolName, result) {
    if (!DECRYPT_TOOLS.has(toolName)) return result;
    const out = { ...result };
    let touched = false;

    // Structured channel (already-decoded object — no JSON parsing needed).
    const structured = result?.structuredContent;
    if (structured && typeof structured === 'object') {
      out.structuredContent = this._decryptPayload(structured);
      touched = true;
    }

    // Text channel (serialized JSON). Leave non-text/unparseable content untouched.
    const item = result?.content?.[0];
    if (item?.type === 'text') {
      let data;
      try {
        data = JSON.parse(item.text);
      } catch {
        data = undefined;
      }
      if (data !== undefined) {
        out.content = [{ type: 'text', text: JSON.stringify(this._decryptPayload(data)) }];
        touched = true;
      }
    }

    if (!touched) return result;
    logEvent('decrypt', { tool: toolName, fields: TASK_DEC_FIELDS });
    return out;
  }
}
