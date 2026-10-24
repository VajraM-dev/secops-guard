'use strict';
const test = require('node:test');
const assert = require('node:assert');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { queryPackages, atLeast, severityOf, cvss3Score } = require('../lib/osv');

test.beforeEach(() => { process.env.SECOPS_STATE_DIR = fs.mkdtempSync(path.join(os.tmpdir(), 'sg-osv-')); });

const VULNS = {
  'GHSA-p6mc-m468-83gw': {
    id: 'GHSA-p6mc-m468-83gw', aliases: ['CVE-2020-8203'], summary: 'Prototype Pollution in lodash',
    database_specific: { severity: 'HIGH' },
    affected: [
      { package: { ecosystem: 'npm', name: 'lodash' }, ranges: [{ type: 'SEMVER', events: [{ introduced: '3.7.0' }, { fixed: '4.17.19' }] }] },
      { package: { ecosystem: 'npm', name: 'lodash-es' }, ranges: [{ type: 'SEMVER', events: [{ introduced: '0' }, { fixed: '9.9.9' }] }] },
    ],
  },
  'GHSA-medium': { id: 'GHSA-medium', summary: 'meh', database_specific: { severity: 'MEDIUM' }, affected: [] },
  'MAL-2025-1': { id: 'MAL-2025-1', summary: 'Malicious code in evil (npm)', affected: [] },
  'GHSA-malware': { id: 'GHSA-malware', aliases: [], summary: 'Malicious code in bad-pkg', database_specific: { severity: 'CRITICAL' } },
  'PYSEC-cvss': {
    id: 'PYSEC-cvss', details: 'long details text', aliases: ['CVE-2018-18074'],
    severity: [{ type: 'CVSS_V3', score: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N' }],
    affected: [{ package: { ecosystem: 'PyPI', name: 'Requests' }, ranges: [{ type: 'ECOSYSTEM', events: [{ introduced: '0' }, { fixed: '2.20.0' }] }] }],
  },
  'OSV-unknown': {
    id: 'OSV-unknown', summary: 'a malicious user could do things',
    severity: [{ type: 'CVSS_V4', score: 'CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:L/VI:N/VA:N/SC:N/SI:N/SA:N' }],
    affected: [{ package: { ecosystem: 'crates.io', name: 'smallvec' }, ranges: [{ type: 'SEMVER', events: [{ introduced: '0' }, { fixed: '0.6.14' }, { introduced: '1.0.0' }, { fixed: '1.6.1' }] }] }],
  },
};

function osvMock({ pages } = {}) {
  const calls = [];
  const fetchImpl = async (url, init) => {
    calls.push({ url, init });
    if (url === 'https://api.osv.dev/v1/querybatch') {
      const body = JSON.parse(init.body);
      const results = body.queries.map((q) => {
        const k = `${q.package.ecosystem}:${q.package.name}@${q.version}`;
        if (k === 'npm:lodash@4.17.15') {
          if (pages && !q.page_token) return { vulns: [{ id: 'GHSA-p6mc-m468-83gw' }], next_page_token: 'tok1' };
          return { vulns: [{ id: pages ? 'GHSA-medium' : 'GHSA-p6mc-m468-83gw' }, ...(pages ? [] : [{ id: 'GHSA-medium' }])] };
        }
        if (k === 'npm:evil@1.0.0') return { vulns: [{ id: 'MAL-2025-1' }] };
        if (k === 'PyPI:requests@2.19.0') return { vulns: [{ id: 'PYSEC-cvss' }] };
        if (k === 'crates.io:smallvec@1.6.0') return { vulns: [{ id: 'OSV-unknown' }] };
        return {};
      });
      return { status: 200, ok: true, json: async () => ({ results }) };
    }
    const id = decodeURIComponent(url.split('/vulns/')[1] || '');
    if (VULNS[id]) return { status: 200, ok: true, json: async () => VULNS[id] };
    return { status: 404, ok: false, json: async () => ({}) };
  };
  return { fetchImpl, calls };
}

const PKGS = [
  { ecosystem: 'npm', name: 'lodash', version: '4.17.15' },
  { ecosystem: 'npm', name: 'lodash', version: '4.17.15' }, // dup
  { ecosystem: 'npm', name: 'evil', version: '1.0.0' },
  { ecosystem: 'npm', name: 'clean', version: '1.0.0' },
  { ecosystem: 'pypi', name: 'requests', version: '2.19.0' },
  { ecosystem: 'crates', name: 'smallvec', version: '1.6.0' },
];

test('queryPackages: batch ids -> details, normalised Vulns, every key present', async () => {
  const m = osvMock();
  const res = await queryPackages(PKGS, m);
  assert.deepStrictEqual([...res.keys()].sort(), ['crates:smallvec@1.6.0', 'npm:clean@1.0.0', 'npm:evil@1.0.0', 'npm:lodash@4.17.15', 'pypi:requests@2.19.0']);
  assert.deepStrictEqual(res.get('npm:clean@1.0.0'), []);
  const lodash = res.get('npm:lodash@4.17.15');
  assert.deepStrictEqual(lodash[0], { id: 'GHSA-p6mc-m468-83gw', aliases: ['CVE-2020-8203'], summary: 'Prototype Pollution in lodash', severity: 'HIGH', fixed: '4.17.19' });
  assert.strictEqual(lodash[1].severity, 'MODERATE');
  assert.strictEqual(res.get('npm:evil@1.0.0')[0].severity, 'MALICIOUS');
  const req = res.get('pypi:requests@2.19.0')[0];
  assert.strictEqual(req.severity, 'HIGH'); // CVSS 7.5
  assert.strictEqual(req.fixed, '2.20.0'); // PyPI name matched case-insensitively
  assert.strictEqual(req.summary, 'long details text');
  const sv = res.get('crates:smallvec@1.6.0')[0];
  assert.strictEqual(sv.fixed, '1.6.1'); // lowest fix above installed version, not first listed
  assert.strictEqual(sv.severity, 'HIGH'); // v4-only -> unknown -> HIGH; "a malicious user" is not malware

  const batch = m.calls.filter((c) => c.url.endsWith('querybatch'));
  assert.strictEqual(batch.length, 1);
  const q = JSON.parse(batch[0].init.body).queries;
  assert.strictEqual(q.length, 5);
  assert.deepStrictEqual(q.find((x) => x.package.name === 'requests').package, { ecosystem: 'PyPI', name: 'requests' });
  assert.ok(q.some((x) => x.package.ecosystem === 'crates.io'));
  assert.strictEqual(m.calls.filter((c) => c.url.includes('/vulns/')).length, 5); // 5 distinct ids, none fetched twice
});

test('queryPackages: follows next_page_token', async () => {
  const m = osvMock({ pages: true });
  const res = await queryPackages([PKGS[0]], m);
  assert.deepStrictEqual(res.get('npm:lodash@4.17.15').map((v) => v.id).sort(), ['GHSA-medium', 'GHSA-p6mc-m468-83gw']);
  const second = JSON.parse(m.calls.filter((c) => c.url.endsWith('querybatch'))[1].init.body);
  assert.strictEqual(second.queries[0].page_token, 'tok1');
});

test('queryPackages: chunks of 500', async () => {
  const m = osvMock();
  const many = Array.from({ length: 1201 }, (_, i) => ({ ecosystem: 'npm', name: `p${i}`, version: '1.0.0' }));
  const res = await queryPackages(many, m);
  assert.strictEqual(res.size, 1201);
  assert.deepStrictEqual(m.calls.map((c) => JSON.parse(c.init.body).queries.length), [500, 500, 201]);
});

test('queryPackages: details cached across calls; empty input makes no requests', async () => {
  const m = osvMock();
  await queryPackages([PKGS[2]], m);
  await queryPackages([PKGS[2]], m);
  assert.strictEqual(m.calls.filter((c) => c.url.includes('/vulns/')).length, 1);
  const e = osvMock();
  assert.strictEqual((await queryPackages([], e)).size, 0);
  assert.strictEqual(e.calls.length, 0);
});

test('queryPackages: querybatch result cached per exact package set (order-independent)', async () => {
  const m = osvMock();
  await queryPackages([PKGS[0], PKGS[2]], m);
  const batches = () => m.calls.filter((c) => c.url.endsWith('querybatch')).length;
  assert.strictEqual(batches(), 1);
  const again = await queryPackages([PKGS[2], PKGS[0], PKGS[0]], m);
  assert.strictEqual(batches(), 1);
  assert.strictEqual(again.get('npm:evil@1.0.0')[0].severity, 'MALICIOUS');
  await queryPackages([PKGS[0]], m); // different set -> new batch
  assert.strictEqual(batches(), 2);
});

test('queryPackages: network failure and malformed responses throw', async () => {
  await assert.rejects(queryPackages([PKGS[0]], { fetchImpl: async () => { throw new Error('offline'); } }));
  await assert.rejects(queryPackages([PKGS[0]], { fetchImpl: async () => ({ status: 200, ok: true, json: async () => ({ results: [] }) }) }));
  await assert.rejects(queryPackages([PKGS[0]], { fetchImpl: async () => ({ status: 500, ok: false, json: async () => ({}) }) }));
});

test('severityOf', () => {
  assert.strictEqual(severityOf({ id: 'GHSA-x', aliases: ['MAL-2024-9'] }), 'MALICIOUS');
  assert.strictEqual(severityOf({ id: 'GHSA-malware', summary: 'Malicious code in bad-pkg', database_specific: { severity: 'CRITICAL' } }), 'MALICIOUS');
  assert.strictEqual(severityOf({ id: 'GHSA-y', summary: 'Critical severity vulnerability', database_specific: { severity: 'CRITICAL', cwe_ids: ['CWE-506'] } }), 'MALICIOUS');
  assert.strictEqual(severityOf({ id: 'X', database_specific: { severity: 'low' } }), 'LOW');
  assert.strictEqual(severityOf({ id: 'X', affected: [{ ecosystem_specific: { severity: 'CRITICAL' } }] }), 'CRITICAL');
  assert.strictEqual(severityOf({ id: 'X', severity: [{ type: 'CVSS_V3', score: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H' }] }), 'CRITICAL');
  assert.strictEqual(severityOf({ id: 'X', severity: [{ type: 'CVSS_V3', score: 'CVSS:3.1/AV:L/AC:H/PR:H/UI:R/S:U/C:L/I:N/A:N' }] }), 'LOW');
  assert.strictEqual(severityOf({ id: 'X' }), 'HIGH');
});

test('cvss3Score matches reference scores', () => {
  assert.strictEqual(cvss3Score('CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H'), 9.8);
  assert.strictEqual(cvss3Score('CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H'), 10);
  assert.strictEqual(cvss3Score('CVSS:3.1/AV:N/AC:L/PR:L/UI:R/S:C/C:L/I:L/A:N'), 5.4);
  assert.strictEqual(cvss3Score('CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N'), 5.9);
  assert.strictEqual(cvss3Score('CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N'), 0);
  assert.strictEqual(cvss3Score('CVSS:3.1/AV:Q/AC:L'), null);
  assert.strictEqual(cvss3Score('AV:N/AC:L/Au:N/C:P/I:P/A:P'), null);
});

test('atLeast', () => {
  assert.ok(atLeast('LOW', 'ANY'));
  assert.ok(atLeast('MALICIOUS', 'CRITICAL'));
  assert.ok(atLeast('HIGH', 'HIGH'));
  assert.ok(atLeast('CRITICAL', 'HIGH'));
  assert.ok(!atLeast('MODERATE', 'HIGH'));
  assert.ok(!atLeast('LOW', 'MODERATE'));
  assert.ok(atLeast('WEIRD', 'HIGH')); // unknown counts as HIGH
});
