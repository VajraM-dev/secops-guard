'use strict';
const test = require('node:test');
const assert = require('node:assert');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const D = require('../lib/docker.js');

const GRYPE = JSON.stringify({ matches: [
  { vulnerability: { id: 'CVE-2024-1', severity: 'Critical' }, artifact: { name: 'openssl', version: '3.0.0' } },
  { vulnerability: { id: 'CVE-2024-2', severity: 'Medium' }, artifact: { name: 'zlib' } },
  { vulnerability: { id: 'CVE-2024-3', severity: 'Negligible' }, artifact: { name: 'bash' } },
  { vulnerability: { id: 'CVE-2024-1', severity: 'Critical' }, artifact: { name: 'openssl', version: '3.0.0' } },
] });
const TRIVY = JSON.stringify({ Results: [
  { Target: 'x', Vulnerabilities: [{ VulnerabilityID: 'CVE-1', Severity: 'HIGH', PkgName: 'libc' }, { VulnerabilityID: 'CVE-2', Severity: 'UNKNOWN', PkgName: 'y' }] },
  { Target: 'y', Vulnerabilities: null },
] });
const SCOUT = JSON.stringify({ version: '15.0.0', vulnerabilities: [
  { id: 'uuid-1', name: 'CVE-3', severity: 'Low', identifiers: [{ type: 'cve', value: 'CVE-3' }], location: { dependency: { package: { name: 'curl' } } } },
] });

test('parseReport: grype (dedupes, maps Medium/Negligible)', () => {
  assert.deepStrictEqual(D.parseReport('grype', GRYPE), [
    { id: 'CVE-2024-1', severity: 'CRITICAL', pkg: 'openssl' },
    { id: 'CVE-2024-2', severity: 'MODERATE', pkg: 'zlib' },
    { id: 'CVE-2024-3', severity: 'LOW', pkg: 'bash' },
  ]);
});

test('parseReport: trivy (null Vulnerabilities, UNKNOWN -> HIGH)', () => {
  assert.deepStrictEqual(D.parseReport('trivy', TRIVY), [
    { id: 'CVE-1', severity: 'HIGH', pkg: 'libc' },
    { id: 'CVE-2', severity: 'HIGH', pkg: 'y' },
  ]);
});

test('parseReport: docker scout gitlab format', () => {
  assert.deepStrictEqual(D.parseReport('docker-scout', SCOUT), [{ id: 'CVE-3', severity: 'LOW', pkg: 'curl' }]);
});

test('scanImage: arg arrays per scanner, parses stdout', () => {
  const seen = [];
  const spawn = (bin, args) => { seen.push([bin, args]); return { status: 0, stdout: GRYPE, stderr: '' }; };
  const r = D.scanImage('nginx:1.27', { scanner: { name: 'grype', bin: '/x/grype' }, spawn });
  assert.strictEqual(r.scanner, 'grype');
  assert.strictEqual(r.vulns.length, 3);
  assert.deepStrictEqual(seen[0], ['/x/grype', ['nginx:1.27', '-o', 'json', '-q']]);
  D.scanImage('a', { scanner: { name: 'trivy', bin: 't' }, spawn: (b, a) => { seen.push(a); return { status: 0, stdout: TRIVY }; } });
  assert.deepStrictEqual(seen[1], ['image', '--quiet', '--format', 'json', 'a']);
  D.scanImage('a', { scanner: { name: 'docker-scout', bin: 'd' }, spawn: (b, a) => { seen.push(a); return { status: 0, stdout: SCOUT }; } });
  assert.deepStrictEqual(seen[2], ['scout', 'cves', '--format', 'gitlab', 'a']);
});

test('scanImage: null without scanner; throws on failure / bad ref', () => {
  assert.strictEqual(D.scanImage('a', { scanner: null }), null);
  const sc = { name: 'grype', bin: 'g' };
  assert.throws(() => D.scanImage('a', { scanner: sc, spawn: () => ({ status: 1, stderr: 'boom' }) }), /grype exited 1: boom/);
  assert.throws(() => D.scanImage('a', { scanner: sc, spawn: () => ({ error: Object.assign(new Error('t'), { code: 'ETIMEDOUT' }) }) }), /ETIMEDOUT/);
  assert.strictEqual(D.scanImage('a', { scanner: { name: 'docker-scout', bin: 'd' }, spawn: () => ({ status: 1, stderr: 'Log in with your Docker ID\n to create one' }) }), null);
  assert.throws(() => D.scanImage('--help', { scanner: sc, spawn: () => ({ status: 0, stdout: '{}' }) }), /invalid image/);
});

test('isFloatingTag', () => {
  for (const img of ['nginx', 'nginx:latest', 'ghcr.io/org/app', 'localhost:5000/app', 'localhost:5000/app:latest']) assert.ok(D.isFloatingTag(img), img);
  for (const img of ['nginx:1.27', 'localhost:5000/app:v1', 'app@sha256:abc', 'app:latest@sha256:abc']) assert.ok(!D.isFloatingTag(img), img);
});

test('findScanner: PATH lookup prefers grype over trivy, else null', () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'secops-bin-'));
  const ext = process.platform === 'win32' ? '.exe' : '';
  const env = { PATH: dir };
  assert.strictEqual(D.findScanner({ env, spawn: () => ({ status: 1 }) }), null);
  fs.writeFileSync(path.join(dir, `trivy${ext}`), '');
  assert.strictEqual(D.findScanner({ env }).name, 'trivy');
  fs.writeFileSync(path.join(dir, `grype${ext}`), '');
  assert.deepStrictEqual(D.findScanner({ env }), { name: 'grype', bin: path.join(dir, `grype${ext}`) });
});

test('findScanner: docker counts only when the scout plugin answers', () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'secops-bin-'));
  fs.writeFileSync(path.join(dir, `docker${process.platform === 'win32' ? '.exe' : ''}`), '');
  assert.strictEqual(D.findScanner({ env: { PATH: dir }, spawn: () => ({ status: 1 }) }), null);
  assert.strictEqual(D.findScanner({ env: { PATH: dir }, spawn: (b, a) => ({ status: a[0] === 'scout' ? 0 : 1 }) }).name, 'docker-scout');
});

test('composeImages: image lines from the default compose file, skips variables', () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'secops-compose-'));
  fs.writeFileSync(path.join(dir, 'compose.yaml'), 'services:\n  db:\n    image: postgres:16 # pinned\n  web:\n    image: "ghcr.io/org/web:${TAG}"\n  cache:\n    image: \'redis:7\'\n');
  fs.writeFileSync(path.join(dir, 'other.yml'), 'services:\n  x:\n    image: alpine:3.20\n');
  assert.deepStrictEqual(D.composeImages(dir), ['postgres:16', 'redis:7']);
  assert.deepStrictEqual(D.composeImages(dir, ['other.yml']), ['alpine:3.20']);
  assert.deepStrictEqual(D.composeImages(path.join(dir, 'missing')), []);
});
