'use strict';
// config.js, io.js, cache.js
const test = require('node:test');
const assert = require('node:assert');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { spawnSync } = require('node:child_process');
const { Readable } = require('node:stream');
const { loadConfig, isAllowed } = require('../lib/config');
const { readStdin } = require('../lib/io');
const { cached } = require('../lib/cache');

const ENV = ['SECOPS_STATE_DIR', 'SECOPS_COOLDOWN_DAYS', 'SECOPS_FAIL_OPEN'];
let dir;
test.beforeEach(() => {
  for (const k of ENV) delete process.env[k];
  dir = fs.mkdtempSync(path.join(os.tmpdir(), 'sg-cfg-'));
  process.env.SECOPS_STATE_DIR = dir;
});
const writeCfg = (obj) => fs.writeFileSync(path.join(dir, 'config.json'), typeof obj === 'string' ? obj : JSON.stringify(obj));

test('defaults when config.json missing', () => {
  const c = loadConfig();
  assert.strictEqual(c.cooldownDays, 7);
  assert.strictEqual(c.packageSeverityBlock, 'ANY');
  assert.strictEqual(c.lockfileSeverityBlock, 'HIGH');
  assert.strictEqual(c.imageSeverityBlock, 'HIGH');
  assert.strictEqual(c.failOpen, false);
  assert.ok(c.allow instanceof Set && c.allow.size === 0);
  assert.ok(c.allowRegistries.includes('registry.npmjs.org'));
  assert.strictEqual(c.stateDir, dir);
});

test('stateDir defaults to ~/.claude/secops-guard', () => {
  delete process.env.SECOPS_STATE_DIR;
  assert.strictEqual(loadConfig().stateDir, path.join(os.homedir(), '.claude', 'secops-guard'));
});

test('user values override; invalid values fall back per key', () => {
  writeCfg({ cooldownDays: 14, packageSeverityBlock: 'HIGH', lockfileSeverityBlock: 'bogus', failOpen: 'yes', allow: ['npm:left-pad'], allowRegistries: 'nope' });
  const c = loadConfig();
  assert.strictEqual(c.cooldownDays, 14);
  assert.strictEqual(c.packageSeverityBlock, 'HIGH');
  assert.strictEqual(c.lockfileSeverityBlock, 'HIGH');
  assert.strictEqual(c.failOpen, false);
  assert.ok(c.allow.has('npm:left-pad'));
  assert.ok(Array.isArray(c.allowRegistries));
});

test('malformed config.json -> defaults + stderr warning (subprocess)', () => {
  writeCfg('{not json');
  const r = spawnSync(process.execPath, ['-e', `console.log(JSON.stringify(require(${JSON.stringify(path.join(__dirname, '..', 'lib', 'config.js'))}).loadConfig().cooldownDays))`], {
    env: { ...process.env, SECOPS_STATE_DIR: dir }, encoding: 'utf8',
  });
  assert.strictEqual(r.stdout.trim(), '7');
  assert.match(r.stderr, /malformed config\.json/);
  writeCfg('[1,2]');
  assert.strictEqual(loadConfig().cooldownDays, 7);
});

test('env overrides', () => {
  writeCfg({ cooldownDays: 3 });
  process.env.SECOPS_COOLDOWN_DAYS = '10';
  process.env.SECOPS_FAIL_OPEN = '1';
  const c = loadConfig();
  assert.strictEqual(c.cooldownDays, 10);
  assert.strictEqual(c.failOpen, true);
  process.env.SECOPS_COOLDOWN_DAYS = 'abc';
  assert.strictEqual(loadConfig().cooldownDays, 3);
});

test('isAllowed: name-wide, versioned, scoped, PEP 503 normalised', () => {
  writeCfg({ allow: ['npm:some-pkg', 'pypi:Some_Pkg@1.2.3', 'npm:@scope/x@2.0.0', 'image:nginx:1.27', 'garbage', 42] });
  const c = loadConfig();
  assert.ok(isAllowed(c, 'npm', 'some-pkg'));
  assert.ok(isAllowed(c, 'npm', 'some-pkg', '9.9.9'));
  assert.ok(!isAllowed(c, 'npm', 'other'));
  assert.ok(isAllowed(c, 'pypi', 'some-pkg', '1.2.3'));
  assert.ok(isAllowed(c, 'pypi', 'some.pkg', '1.2.3'));
  assert.ok(!isAllowed(c, 'pypi', 'some-pkg', '1.2.4'));
  assert.ok(!isAllowed(c, 'pypi', 'some-pkg'));
  assert.ok(isAllowed(c, 'npm', '@scope/x', '2.0.0'));
  assert.ok(!isAllowed(c, 'npm', '@scope/x'));
  assert.ok(isAllowed(c, 'image', 'nginx:1.27'));
  assert.ok(!isAllowed(c, 'crates', 'some-pkg'));
});

test('readStdin: object, malformed, non-object', async () => {
  assert.deepStrictEqual(await readStdin(Readable.from(['{"a":', '1}'])), { a: 1 });
  assert.strictEqual(await readStdin(Readable.from(['{nope'])), null);
  assert.strictEqual(await readStdin(Readable.from([''])), null);
  assert.strictEqual(await readStdin(Readable.from(['42'])), null);
});

test('emit helpers write exactly one JSON object', () => {
  const lib = JSON.stringify(path.join(__dirname, '..', 'lib', 'io.js'));
  const run = (expr) => {
    const r = spawnSync(process.execPath, ['-e', `const io=require(${lib}); ${expr}`], { encoding: 'utf8' });
    return JSON.parse(r.stdout);
  };
  assert.deepStrictEqual(run('io.preDeny("secops-guard: no")'), { hookSpecificOutput: { hookEventName: 'PreToolUse', permissionDecision: 'deny', permissionDecisionReason: 'secops-guard: no' } });
  assert.deepStrictEqual(run('io.preAllowWithInput({command:"npm i x@1"}, "pinned")').hookSpecificOutput,
    { hookEventName: 'PreToolUse', permissionDecision: 'allow', updatedInput: { command: 'npm i x@1' }, additionalContext: 'pinned' });
  assert.ok(!('additionalContext' in run('io.preAllowWithInput({command:"x"})').hookSpecificOutput));
  assert.deepStrictEqual(run('io.preContext("c")'), { hookSpecificOutput: { hookEventName: 'PreToolUse', additionalContext: 'c' } });
  const pb = run('io.postBlock("r")');
  assert.strictEqual(pb.decision, 'block');
  assert.strictEqual(pb.reason, 'r');
  assert.strictEqual(pb.hookSpecificOutput.hookEventName, 'PostToolUse');
  assert.deepStrictEqual(run('io.postContext("c")'), { hookSpecificOutput: { hookEventName: 'PostToolUse', additionalContext: 'c' } });
  assert.deepStrictEqual(run('io.sessionMessage("u","c")'), { systemMessage: 'u', hookSpecificOutput: { hookEventName: 'SessionStart', additionalContext: 'c' } });
  assert.deepStrictEqual(run('io.sessionMessage("u")'), { systemMessage: 'u' });
});

test('cache: hit within TTL, miss after expiry, survives unwritable dir', async () => {
  let n = 0;
  const fn = async () => ++n;
  assert.strictEqual(await cached('k', 1000, fn), 1);
  assert.strictEqual(await cached('k', 1000, fn), 1);
  assert.strictEqual(fs.readdirSync(path.join(dir, 'cache')).length, 1);
  assert.strictEqual(await cached('k', 1000, fn, Date.now() + 5000), 2); // expired
  assert.strictEqual(await cached('other', 1000, fn), 3);
  // corrupt entry -> recompute
  for (const f of fs.readdirSync(path.join(dir, 'cache'))) fs.writeFileSync(path.join(dir, 'cache', f), 'garbage');
  assert.strictEqual(await cached('k', 1000, fn), 4);
  // state dir is a file -> mkdir fails -> still returns value
  const fileAsDir = path.join(dir, 'blocker');
  fs.writeFileSync(fileAsDir, 'x');
  process.env.SECOPS_STATE_DIR = fileAsDir;
  assert.strictEqual(await cached('k', 1000, fn), 5);
  // errors from fn propagate and are not cached
  process.env.SECOPS_STATE_DIR = dir;
  await assert.rejects(cached('boom', 1000, async () => { throw new Error('x'); }));
  assert.strictEqual(await cached('boom', 1000, async () => 'ok'), 'ok');
});
