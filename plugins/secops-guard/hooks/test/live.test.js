'use strict';
// Real network. Run with SECOPS_LIVE=1; skipped otherwise.
const test = require('node:test');
const assert = require('node:assert');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { resolveVersion, getPackageVersions } = require('../lib/registries');
const { queryPackages } = require('../lib/osv');

const skip = process.env.SECOPS_LIVE !== '1' && 'set SECOPS_LIVE=1 to hit real APIs';
const opts = { timeoutMs: 30000 };

test.before(() => { process.env.SECOPS_STATE_DIR = fs.mkdtempSync(path.join(os.tmpdir(), 'sg-live-')); });

test('npm: resolve lodash with 7-day cooldown', { skip }, async () => {
  const r = await resolveVersion('npm', 'lodash', '', 7, opts);
  assert.ok(r.version, JSON.stringify(r));
  assert.ok(r.publishedAt.getTime() <= Date.now() - 7 * 86400000);
  assert.strictEqual((await resolveVersion('npm', 'lodash', '4.17.15', 7, opts)).version, '4.17.15');
  assert.strictEqual((await resolveVersion('npm', '@types/node', '^20.0.0', 7, opts)).version.split('.')[0], '20');
});

test('npm: nonexistent package -> null / not_found', { skip }, async () => {
  const name = 'secops-guard-definitely-not-a-real-pkg-7f3a9c';
  assert.strictEqual(await getPackageVersions('npm', name, opts), null);
  assert.strictEqual((await resolveVersion('npm', name, '', 7, opts)).error, 'not_found');
});

test('crates: resolve serde', { skip }, async () => {
  const r = await resolveVersion('crates', 'serde', '1', 7, opts);
  assert.match(r.version, /^1\.\d+\.\d+$/);
});

test('pypi: resolve requests', { skip }, async () => {
  const r = await resolveVersion('pypi', 'requests', '', 7, opts);
  assert.match(r.version, /^2\./);
});

test('osv: lodash@4.17.15, requests==2.19.0, flatmap-stream (malicious)', { skip }, async () => {
  const res = await queryPackages([
    { ecosystem: 'npm', name: 'lodash', version: '4.17.15' },
    { ecosystem: 'pypi', name: 'requests', version: '2.19.0' },
    { ecosystem: 'npm', name: 'flatmap-stream', version: '0.1.1' },
  ], opts);
  const lodash = res.get('npm:lodash@4.17.15');
  const cve = lodash.find((v) => v.id === 'GHSA-p6mc-m468-83gw' || v.aliases.includes('CVE-2020-8203'));
  assert.ok(cve, lodash.map((v) => v.id).join(','));
  assert.strictEqual(cve.fixed, '4.17.19');
  assert.ok(['HIGH', 'CRITICAL', 'MODERATE'].includes(cve.severity));
  assert.ok(res.get('pypi:requests@2.19.0').length > 0);
  assert.ok(res.get('npm:flatmap-stream@0.1.1').some((v) => v.severity === 'MALICIOUS'));
});
