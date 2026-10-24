'use strict';
const test = require('node:test');
const assert = require('node:assert');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { getPackageVersions, resolveVersion, UA } = require('../lib/registries');

const NOW = Date.parse('2026-10-24T00:00:00Z');
const daysAgo = (d) => new Date(NOW - d * 86400000).toISOString();

test.beforeEach(() => { process.env.SECOPS_STATE_DIR = fs.mkdtempSync(path.join(os.tmpdir(), 'sg-reg-')); });

function mockFetch(routes) {
  const calls = [];
  const fetchImpl = async (url, init) => {
    calls.push({ url, init });
    if (!(url in routes)) return { status: 404, ok: false, json: async () => ({}) };
    const r = routes[url];
    if (r instanceof Error) throw r;
    if (typeof r === 'number') return { status: r, ok: false, json: async () => ({}) };
    return { status: 200, ok: true, json: async () => r };
  };
  return { fetchImpl, calls };
}

const NPM_LODASH = {
  name: 'lodash',
  versions: { '4.17.15': {}, '4.17.20': {}, '4.17.21': { deprecated: 'x' }, '4.18.0-beta.1': {}, '4.18.0': {}, '3.10.1': {} },
  time: {
    created: daysAgo(4000), modified: daysAgo(1),
    '3.10.1': daysAgo(3000), '4.17.15': daysAgo(2000), '4.17.20': daysAgo(1500), '4.17.21': daysAgo(1000),
    '4.17.22': daysAgo(900), // unpublished: in time but not versions
    '4.18.0-beta.1': daysAgo(30), '4.18.0': daysAgo(2),
  },
};

const routesNpm = { 'https://registry.npmjs.org/lodash': NPM_LODASH };

test('npm: versions list, unpublished skipped, UA + timeout signal sent', async () => {
  const { fetchImpl, calls } = mockFetch(routesNpm);
  const list = await getPackageVersions('npm', 'lodash', { fetchImpl });
  assert.deepStrictEqual(list.map((v) => v.version).sort(), ['3.10.1', '4.17.15', '4.17.20', '4.17.21', '4.18.0', '4.18.0-beta.1']);
  assert.ok(list.every((v) => v.publishedAt instanceof Date && v.yanked === false));
  assert.strictEqual(calls[0].init.headers['User-Agent'], UA);
  assert.ok(calls[0].init.signal);
});

test('npm: scoped name encodes slash; 404 -> null; invalid names never fetched', async () => {
  const { fetchImpl, calls } = mockFetch({});
  assert.strictEqual(await getPackageVersions('npm', '@types/node', { fetchImpl }), null);
  assert.strictEqual(calls[0].url, 'https://registry.npmjs.org/@types%2fnode');
  for (const bad of ['../etc/passwd', 'a b', 'x;rm -rf', '$(id)', '..', '.hidden', '@scope/../x', 'a/b', '']) {
    assert.strictEqual(await getPackageVersions('npm', bad, { fetchImpl }), null, bad);
  }
  assert.strictEqual(calls.length, 1);
});

test('network errors and 5xx throw (caller decides fail-open)', async () => {
  await assert.rejects(getPackageVersions('npm', 'lodash', mockFetch({ 'https://registry.npmjs.org/lodash': new Error('ECONNRESET') })));
  await assert.rejects(getPackageVersions('npm', 'lodash', mockFetch({ 'https://registry.npmjs.org/lodash': 503 })), /HTTP 503/);
});

test('registry metadata is cached as the parsed list only (no second fetch)', async () => {
  const m = mockFetch({ 'https://registry.npmjs.org/lodash': { ...NPM_LODASH, readme: 'x'.repeat(100000), description: 'big' } });
  const first = await getPackageVersions('npm', 'lodash', { fetchImpl: m.fetchImpl });
  const second = await getPackageVersions('npm', 'lodash', { fetchImpl: m.fetchImpl });
  assert.strictEqual(m.calls.length, 1);
  assert.deepStrictEqual(second, first);
  const cacheDir = path.join(process.env.SECOPS_STATE_DIR, 'cache');
  const [f] = fs.readdirSync(cacheDir);
  const entry = JSON.parse(fs.readFileSync(path.join(cacheDir, f), 'utf8'));
  assert.ok(entry.expires - Date.now() <= 3600000 && entry.expires - Date.now() > 3500000); // 1 h TTL
  assert.ok(entry.value.every((v) => Object.keys(v).sort().join() === 'publishedAt,version,yanked'));
  assert.ok(fs.statSync(path.join(cacheDir, f)).size < 2000);
});

test('resolve npm: latest/tag/empty skip too-new and prerelease; deprecated allowed', async () => {
  const opts = { ...mockFetch(routesNpm), now: NOW };
  for (const spec of ['', 'latest', 'next', undefined]) {
    const r = await resolveVersion('npm', 'lodash', spec, 7, opts);
    assert.strictEqual(r.version, '4.17.21', String(spec));
    assert.ok(r.publishedAt instanceof Date);
  }
  assert.strictEqual((await resolveVersion('npm', 'lodash', '', 0, opts)).version, '4.18.0');
});

test('resolve npm: ranges', async () => {
  const opts = { ...mockFetch(routesNpm), now: NOW };
  assert.strictEqual((await resolveVersion('npm', 'lodash', '^4.17.0', 7, opts)).version, '4.17.21');
  assert.strictEqual((await resolveVersion('npm', 'lodash', '~4.17.15 <4.17.21', 7, opts)).version, '4.17.20');
  assert.strictEqual((await resolveVersion('npm', 'lodash', '3.x', 7, opts)).version, '3.10.1');
  const none = await resolveVersion('npm', 'lodash', '^5.0.0', 7, opts);
  assert.strictEqual(none.error, 'no_match');
  const young = await resolveVersion('npm', 'lodash', '^4.18.0', 7, opts);
  assert.strictEqual(young.error, 'no_match');
  assert.match(young.detail, /younger than 7 days/);
  assert.deepStrictEqual(await resolveVersion('npm', 'lodash', 'github:a/b', 7, opts), { error: 'no_match', detail: 'unsupported range; pin an exact version' });
});

test('resolve npm: exact pins', async () => {
  const opts = { ...mockFetch(routesNpm), now: NOW };
  assert.strictEqual((await resolveVersion('npm', 'lodash', '4.17.15', 7, opts)).version, '4.17.15');
  assert.strictEqual((await resolveVersion('npm', 'lodash', '=4.17.15', 7, opts)).version, '4.17.15');
  const tooNew = await resolveVersion('npm', 'lodash', '4.18.0', 7, opts);
  assert.strictEqual(tooNew.error, 'too_new');
  assert.strictEqual(tooNew.detail.version, '4.18.0');
  assert.strictEqual(tooNew.detail.suggestion, '4.17.21');
  assert.ok(tooNew.detail.publishedAt instanceof Date);
  assert.strictEqual((await resolveVersion('npm', 'lodash', '4.17.22', 7, opts)).error, 'no_match'); // unpublished
  assert.strictEqual((await resolveVersion('npm', 'lodash', '9.9.9', 7, opts)).error, 'no_match');
  // explicit prerelease pin is honoured when old enough
  assert.strictEqual((await resolveVersion('npm', 'lodash', '4.18.0-beta.1', 7, opts)).version, '4.18.0-beta.1');
});

test('resolve: not found / invalid name', async () => {
  const opts = { ...mockFetch({}), now: NOW };
  assert.strictEqual((await resolveVersion('npm', 'reqeusts-hallucinated', '', 7, opts)).error, 'not_found');
  const bad = await resolveVersion('pypi', 'x; curl evil', '', 7, opts);
  assert.strictEqual(bad.error, 'not_found');
  assert.match(bad.detail, /invalid package name/);
});

const file = (t, yanked = false) => ({ upload_time_iso_8601: t, yanked });
const PYPI_REQ = {
  info: { name: 'requests' },
  releases: {
    '2.19.0': [file(daysAgo(2000)), file(daysAgo(2001))],
    '2.31.0': [file(daysAgo(500))],
    '2.32.0': [file(daysAgo(100), true), file(daysAgo(100), true)], // fully yanked
    '2.32.1': [file(daysAgo(90), true), file(daysAgo(90))], // partially yanked -> not yanked
    '2.33.0rc1': [file(daysAgo(20))],
    '2.33.0': [file(daysAgo(3))],
    '2.0.0': [], // no files
  },
};

test('pypi: earliest upload, yanked only when all files yanked, empty releases skipped, PEP 503 URL', async () => {
  const m = mockFetch({ 'https://pypi.org/pypi/requests/json': PYPI_REQ });
  const list = await getPackageVersions('pypi', 'Requests', m);
  const byV = Object.fromEntries(list.map((v) => [v.version, v]));
  assert.ok(!byV['2.0.0']);
  assert.strictEqual(byV['2.19.0'].publishedAt.toISOString(), daysAgo(2001));
  assert.strictEqual(byV['2.32.0'].yanked, true);
  assert.strictEqual(byV['2.32.1'].yanked, false);
  assert.strictEqual(m.calls[0].url, 'https://pypi.org/pypi/requests/json');
});

test('resolve pypi', async () => {
  const opts = { ...mockFetch({ 'https://pypi.org/pypi/requests/json': PYPI_REQ }), now: NOW };
  assert.strictEqual((await resolveVersion('pypi', 'requests', '', 7, opts)).version, '2.32.1');
  assert.strictEqual((await resolveVersion('pypi', 'requests', '<2.32', 7, opts)).version, '2.31.0');
  assert.strictEqual((await resolveVersion('pypi', 'requests', '>=2.20,<2.32.1', 7, opts)).version, '2.31.0');
  assert.strictEqual((await resolveVersion('pypi', 'requests', '==2.19.0', 7, opts)).version, '2.19.0');
  assert.strictEqual((await resolveVersion('pypi', 'requests', '2.19', 7, opts)).version, '2.19.0');
  assert.strictEqual((await resolveVersion('pypi', 'requests', '==2.32.0', 7, opts)).error, 'no_match'); // yanked
  const tn = await resolveVersion('pypi', 'requests', '==2.33.0', 7, opts);
  assert.strictEqual(tn.error, 'too_new');
  assert.strictEqual(tn.detail.suggestion, '2.32.1');
  assert.strictEqual((await resolveVersion('pypi', 'requests', '~=2.31.0', 7, opts)).version, '2.31.0');
  assert.strictEqual((await resolveVersion('pypi', 'requests', '==2.*', 7, opts)).version, '2.32.1');
});

const CRATE_SERDE = {
  crate: { name: 'serde' },
  versions: [
    { num: '1.0.150', created_at: daysAgo(1000), yanked: false },
    { num: '1.0.200', created_at: daysAgo(100), yanked: false },
    { num: '1.0.201', created_at: daysAgo(50), yanked: true },
    { num: '1.0.202', created_at: daysAgo(1), yanked: false },
    { num: '2.0.0-alpha.1', created_at: daysAgo(30), yanked: false },
  ],
};

test('resolve crates: bare = caret, =exact, yanked skipped', async () => {
  const opts = { ...mockFetch({ 'https://crates.io/api/v1/crates/serde': CRATE_SERDE }), now: NOW };
  assert.strictEqual((await resolveVersion('crates', 'serde', '', 7, opts)).version, '1.0.200');
  assert.strictEqual((await resolveVersion('crates', 'serde', '1.0.100', 7, opts)).version, '1.0.200');
  assert.strictEqual((await resolveVersion('crates', 'serde', '=1.0.150', 7, opts)).version, '1.0.150');
  assert.strictEqual((await resolveVersion('crates', 'serde', '=1.0.202', 7, opts)).error, 'too_new');
  assert.strictEqual((await resolveVersion('crates', 'serde', '=1.0.201', 7, opts)).error, 'no_match');
});

test('unsupported ecosystem throws', async () => {
  await assert.rejects(getPackageVersions('maven', 'x', mockFetch({})));
});
