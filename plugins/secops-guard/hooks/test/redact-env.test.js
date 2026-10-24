const test = require('node:test');
const assert = require('node:assert');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { spawnSync } = require('node:child_process');
const { isEnvFile, redact, decide } = require('../redact-env.js');

const SCRIPT = path.join(__dirname, '..', 'redact-env.js');
const run = (input) => spawnSync(process.execPath, [SCRIPT], { input, encoding: 'utf8' });

test('Read of .env redacts values, keeps keys and comments', () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'redact-env-'));
  const file = path.join(dir, '.env');
  fs.writeFileSync(file, 'A=1\n# c\nexport B=two');
  const r = decide({ tool_name: 'Read', tool_input: { file_path: file } });
  assert.strictEqual(r.decision, 'deny');
  assert.match(r.reason, /A=<REDACTED>/);
  assert.match(r.reason, /# c/);
  assert.match(r.reason, /export B=<REDACTED>/);
  assert.doesNotMatch(r.reason, /two/);
  fs.rmSync(dir, { recursive: true, force: true });
});

test('isEnvFile handles Windows paths, casing, and non-env names', () => {
  assert.strictEqual(isEnvFile('C:\\proj\\.ENV.local'), true);
  assert.strictEqual(isEnvFile('config\\prod.env'), true);
  assert.strictEqual(isEnvFile('/a/b/.env'), true);
  assert.strictEqual(isEnvFile('envoy.yaml'), false);
  assert.strictEqual(isEnvFile('.envrc'), false);
});

test('redact handles CRLF, indentation, blanks, non-kv lines, trailing newline', () => {
  assert.strictEqual(redact('A=1\r\n  B = x\n\nnot kv\n'), 'A=<REDACTED>\n  B=<REDACTED>\n\n<REDACTED>');
  assert.strictEqual(redact('A=1\r\nB=2\r\n'), 'A=<REDACTED>\nB=<REDACTED>');
  assert.strictEqual(redact(''), '');
});

test('redact hides value on BOM-prefixed first line', () => {
  const out = redact('﻿SECRET=abc\nB=2');
  assert.match(out, /SECRET=<REDACTED>/);
  assert.doesNotMatch(out, /abc/);
});

test('Bash .env references are denied, lookalikes allowed', () => {
  assert.strictEqual(decide({ tool_name: 'Bash', tool_input: { command: 'cat .env.production' } }).decision, 'deny');
  assert.strictEqual(decide({ tool_name: 'Bash', tool_input: { command: 'cat src/my.env.ts' } }), null);
});

test('redact hides commented keys, colon separators, dashed keys', () => {
  assert.strictEqual(redact('# OLD_KEY=secret\nKEY: value\nmy-key=v'), '# OLD_KEY=<REDACTED>\nKEY: <REDACTED>\nmy-key=<REDACTED>');
});

test('redact hides multiline quoted PEM including comment-like lines', () => {
  const out = redact('K="-----BEGIN KEY-----\nMIIsecretbody\n# notacomment\n-----END KEY-----"\nB=2');
  assert.strictEqual(out, 'K=<REDACTED>\n<REDACTED>\n<REDACTED>\n<REDACTED>\nB=<REDACTED>');
  for (const s of ['BEGIN', 'MIIsecretbody', 'notacomment', 'END']) assert.ok(!out.includes(s), s);
});

test('path-qualified and name.env shell refs are denied', () => {
  const E = '.' + 'env';
  for (const command of [`cat ./${E}`, `cat config/${E}`, `cat ~/${E}`, `type C:\\proj\\${E}`, `cat prod${E}`, `type config\\prod${E}`]) {
    assert.strictEqual(decide({ tool_name: 'Bash', tool_input: { command } })?.decision, 'deny', command);
  }
  assert.strictEqual(decide({ tool_name: 'PowerShell', tool_input: { command: `Get-Content .\\${E}` } })?.decision, 'deny');
  for (const command of ['cat envoy.yaml', `cat ${E}rc`, `cat src/my${E}.ts`]) {
    assert.strictEqual(decide({ tool_name: 'Bash', tool_input: { command } }), null, command);
  }
});

test('Grep on env path or glob denied, normal grep allowed', () => {
  const E = '.' + 'env';
  for (const ti of [{ pattern: 'x', path: `/p/${E}` }, { pattern: 'x', path: `prod${E}` }, { pattern: 'x', glob: `${E}*` }, { pattern: 'x', glob: `**/*${E}` }]) {
    const r = decide({ tool_name: 'Grep', tool_input: ti });
    assert.strictEqual(r?.decision, 'deny', JSON.stringify(ti));
    assert.match(r.reason, /blocked/);
  }
  assert.strictEqual(decide({ tool_name: 'Grep', tool_input: { pattern: 'x', path: 'src/app.js' } }), null);
  assert.strictEqual(decide({ tool_name: 'Grep', tool_input: { pattern: 'x', glob: '*.ts' } }), null);
});

test('PowerShell treated like Bash', () => {
  assert.strictEqual(decide({ tool_name: 'PowerShell', tool_input: { command: 'Get-Content .env' } }).decision, 'deny');
});

test('Read of missing .env is denied with file not found', () => {
  const missing = path.join(os.tmpdir(), 'redact-env-missing-' + process.pid, '.env');
  const r = decide({ tool_name: 'Read', tool_input: { file_path: missing } });
  assert.strictEqual(r.decision, 'deny');
  assert.match(r.reason, /file not found/);
});

test('non-env Read is allowed', () => {
  assert.strictEqual(decide({ tool_name: 'Read', tool_input: { file_path: 'README.md' } }), null);
});

for (const input of ['not json', '', '[1]', '{"tool_input":"x"}']) {
  test(`script with stdin ${JSON.stringify(input)} exits 0 silently`, () => {
    const r = run(input);
    assert.strictEqual(r.status, 0);
    assert.strictEqual(r.stdout, '');
  });
}

test('script prints deny JSON for Bash .env access', () => {
  const input = JSON.stringify({ tool_name: 'Bash', tool_input: { command: 'cat .env' } });
  const r = run(input);
  assert.strictEqual(r.status, 0);
  const out = JSON.parse(r.stdout).hookSpecificOutput;
  assert.strictEqual(out.hookEventName, 'PreToolUse');
  assert.strictEqual(out.permissionDecision, 'deny');
  assert.match(out.permissionDecisionReason, /shell access to \.env files is blocked/);
});
