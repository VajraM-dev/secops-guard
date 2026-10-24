'use strict';
const test = require('node:test');
const assert = require('node:assert');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { spawnSync } = require('node:child_process');
const P = require('../post-install-scan.js');
const { fakes, throwing } = require('./helpers/fakes.js');

const SCRIPT = path.join(__dirname, '..', 'post-install-scan.js');
const tmp = () => fs.mkdtempSync(path.join(os.tmpdir(), 'secops-post-'));
const post = (command, cwd, tool_response = { stdout: '', stderr: '', interrupted: false }) => ({ tool_name: 'Bash', tool_input: { command }, tool_response, cwd });

function lockDir() {
  const dir = tmp();
  fs.writeFileSync(path.join(dir, 'package-lock.json'), '{}');
  return dir;
}
const LOCK = { 'package-lock.json': [{ ecosystem: 'npm', name: 'minimist', version: '1.2.0' }, { ecosystem: 'npm', name: 'a', version: '1.0.0' }] };

test('blocking vuln after install -> block with rollback and fix hints, cache bypassed', async () => {
  const { deps, calls } = fakes({ lockfiles: LOCK, vulns: { 'npm:minimist@1.2.0': [{ id: 'GHSA-vh95', severity: 'CRITICAL', fixed: '1.2.6' }] } });
  const r = await P.decide(post('npm i foo@1.0.0 bar', lockDir()), deps);
  assert.strictEqual(r.decision, 'block');
  assert.match(r.reason, /^secops-guard: the install left vulnerable packages/);
  assert.match(r.reason, /Roll back with `npm uninstall foo bar`/);
  assert.match(r.reason, /minimist -> 1\.2\.6/);
  assert.strictEqual(calls.cached.length, 0);
});

test('lower severity -> context summary', async () => {
  const { deps } = fakes({ lockfiles: LOCK, vulns: { 'npm:a@1.0.0': [{ id: 'GHSA-low', severity: 'MODERATE', fixed: null }] } });
  const r = await P.decide(post('npm ci', lockDir()), deps);
  assert.strictEqual(r.decision, 'context');
  assert.match(r.context, /GHSA-low/);
});

test('clean scan -> null', async () => {
  const { deps } = fakes({ lockfiles: LOCK });
  assert.strictEqual(await P.decide(post('pnpm add zod', lockDir()), deps), null);
});

test('failed or non-install commands -> null', async () => {
  assert.strictEqual(await P.decide(post('npm i foo', tmp(), { interrupted: true }), throwing), null);
  assert.strictEqual(await P.decide(post('npm i foo', tmp(), { exitCode: 1 }), throwing), null);
  assert.strictEqual(await P.decide(post('ls', tmp()), throwing), null);
  assert.strictEqual(await P.decide(post('npx cowsay hi', tmp()), throwing), null);
});

test('pip uninstall hint for pypi installs', () => {
  const { parseInstallIntents } = require('../lib/parse-command.js');
  assert.deepStrictEqual(P.rollbackHint(parseInstallIntents('pip install "x[y]==1" && npm i -g z')), ['pip uninstall -y x', 'npm uninstall -g z']);
});

test('docker build -t -> scan the built tag', async () => {
  const { deps, calls } = fakes({ scanner: () => ({ scanner: 'trivy', vulns: [{ id: 'CVE-9', severity: 'HIGH', pkg: 'glibc' }] }) });
  const r = await P.decide(post('docker build -t app:dev .', tmp()), deps);
  assert.strictEqual(r.decision, 'block');
  assert.match(r.reason, /built image app:dev .*CVE-9/);
  assert.deepStrictEqual(calls.scan, ['app:dev']);
});

test('docker build without a scanner -> null', async () => {
  const { deps } = fakes();
  assert.strictEqual(await P.decide(post('docker build -t app .', tmp()), deps), null);
});

test('OSV failure after install -> context, never throws', async () => {
  const { deps } = fakes({ lockfiles: LOCK, osvError: new Error('offline') });
  const r = await P.decide(post('npm ci', lockDir()), deps);
  assert.match(r.context, /post-install scan of package-lock\.json failed \(offline\)/);
});

const run = (input, env = {}) => spawnSync(process.execPath, [SCRIPT], { input, encoding: 'utf8', env: { ...process.env, SECOPS_STATE_DIR: tmp(), ...env } });

test('spawn: non-install and SECOPS_DISABLE -> no output', () => {
  let r = run(JSON.stringify(post('git status', tmp())));
  assert.strictEqual(r.status, 0);
  assert.strictEqual(r.stdout, '');
  r = run(JSON.stringify(post('npm ci', tmp())), { SECOPS_DISABLE: '1' });
  assert.strictEqual(r.stdout, '');
});
