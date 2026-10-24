#!/usr/bin/env node
// PreToolUse hook: redact .env file values, expose only keys (PowerShell treated like Bash).
// On Read of a .env file, denies the read but returns KEY=<REDACTED> contents
// via permissionDecisionReason so the model still sees variable names.
'use strict';
const fs = require('fs');
const path = require('path');

const ENV_NAME = /^(\.env(\..+)?|.+\.env)$/i;
// Optional `#`/`export` prefix, key, `=` or `:` separator, value.
const KEY_LINE = /^(\s*(?:#\s*)?(?:export\s+)?)([A-Za-z_][A-Za-z0-9_.-]*)\s*([=:])\s*(.*)$/;
// `.env`/`.env.x` anywhere (incl. ./ ~/ .\ C:\x\), or `name.env` as a whole token (not my.env.ts, .envrc).
const BASH_ENV_REF = /(?<![A-Za-z0-9_.-])(?:\.env(?:\.[\w-]+)?\b|[\w.-]+\.env(?![\w.-]))/i;

const isEnvFile = (p) => ENV_NAME.test(path.win32.basename(p));

// Fail closed: every non-blank line is redacted except key prefixes and pure comments.
// Lines inside a quoted value opened on a key line (multiline PEM etc.) are fully redacted.
function redact(text) {
  const lines = text.replace(/^\uFEFF/, '').split(/\r?\n|\r/);
  if (lines[lines.length - 1] === '') lines.pop(); // no extra line for a trailing newline
  let open = null; // quote char of an unterminated value
  return lines.map((l) => {
    if (open) {
      if (l.includes(open)) open = null;
      return l.trim() ? '<REDACTED>' : l;
    }
    if (!l.trim()) return l;
    const m = KEY_LINE.exec(l);
    if (m) {
      const q = m[4][0];
      if ((q === '"' || q === "'") && !m[4].slice(1).includes(q)) open = q;
      return `${m[1]}${m[2]}${m[3] === ':' ? ': ' : '='}<REDACTED>`;
    }
    return /^\s*#/.test(l) ? l : '<REDACTED>';
  }).join('\n');
}

const deny = (reason) => ({ decision: 'deny', reason });

function decide(data) {
  const tool = data?.tool_name;
  const ti = data?.tool_input;

  if (tool === 'Bash' || tool === 'PowerShell') {
    if (typeof ti?.command === 'string' && BASH_ENV_REF.test(ti.command)) {
      return deny(
        'env-redact hook: shell access to .env files is blocked. ' +
          'Use the Read tool on the .env path instead — the hook will ' +
          'return the file with values redacted but keys visible.'
      );
    }
    return null;
  }

  if (tool === 'Grep') {
    // ponytail: directory-wide grep with no glob still reaches .env files; would need a post-tool filter.
    const p = ti?.path, g = ti?.glob;
    if ((typeof p === 'string' && isEnvFile(p)) || (typeof g === 'string' && BASH_ENV_REF.test(g))) {
      return deny('env-redact hook: Grep on .env files is blocked. Use the Read tool on the .env path to see its keys (values redacted).');
    }
    return null;
  }

  const filePath = ti?.file_path;
  if (typeof filePath !== 'string' || !isEnvFile(filePath)) return null;

  let content;
  try {
    content = fs.readFileSync(filePath, 'utf8');
  } catch (e) {
    if (e.code === 'ENOENT' || e.code === 'EISDIR') return deny(`env-redact hook: file not found at ${filePath}`);
    return deny(`env-redact hook: read error: ${e.message}`);
  }

  return deny(
    '.env access intercepted by global redact hook. ' +
      'Values hidden, keys preserved. ' +
      `Redacted contents of ${filePath}:\n\n${redact(content)}`
  );
}

function main() {
  try {
    const r = decide(JSON.parse(fs.readFileSync(0, 'utf8')));
    if (r) {
      process.stdout.write(
        JSON.stringify({
          hookSpecificOutput: {
            hookEventName: 'PreToolUse',
            permissionDecision: r.decision,
            permissionDecisionReason: r.reason,
          },
        })
      );
    }
  } catch {
    // Malformed/empty stdin or any failure: never block Claude.
  }
}

module.exports = { isEnvFile, redact, decide };

if (require.main === module) main();
