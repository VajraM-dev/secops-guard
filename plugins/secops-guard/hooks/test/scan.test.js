'use strict';
const test = require('node:test');
const assert = require('node:assert');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const S = require('../lib/scan.js');

const tmp = () => fs.mkdtempSync(path.join(os.tmpdir(), 'secops-scan-'));
const CANARY = 'CANARYSECRETVALUE0123';

// Shape taken verbatim from `trivy fs --format json --scanners secret,vuln` (v0.76.1).
const REPORT = {
  SchemaVersion: 2,
  ArtifactName: 'proj',
  Results: [
    {
      Target: 'package-lock.json',
      Class: 'lang-pkgs',
      Type: 'npm',
      Vulnerabilities: [
        { VulnerabilityID: 'CVE-2021-23337', PkgName: 'lodash', InstalledVersion: '4.17.19', FixedVersion: '4.17.21', Severity: 'HIGH' },
        { VulnerabilityID: 'CVE-2020-8203', PkgName: 'lodash', Severity: 'MEDIUM' },
      ],
    },
    {
      Target: 'dist/bundle.js',
      Class: 'secret',
      Secrets: [
        {
          RuleID: 'github-pat',
          Category: 'GitHub',
          Severity: 'CRITICAL',
          Title: 'GitHub Personal Access Token',
          StartLine: 1,
          EndLine: 1,
          Code: { Lines: [{ Number: 1, Content: `const T="${CANARY}";`, IsCause: true, Highlighted: `const T="${CANARY}";` }] },
          Match: `const T="${CANARY}";`,
          Offset: 9,
        },
        // duplicate rule+line: trivy can emit the same hit from two sources
        { RuleID: 'github-pat', Severity: 'CRITICAL', Title: 'GitHub Personal Access Token', StartLine: 1, Match: CANARY },
      ],
    },
  ],
};
const TEXT = JSON.stringify(REPORT);

const fakeSpawn = (out, rest = {}) => {
  const calls = [];
  const spawn = (bin, args) => { calls.push({ bin, args }); return { status: 0, stdout: out, stderr: '', ...rest }; };
  return { spawn, calls };
};
const TRIVY = { name: 'trivy', bin: '/x/trivy' };

test('parseSecrets: real trivy shape, deduped, never carries the matched value', () => {
  const got = S.parseSecrets(REPORT);
  assert.deepStrictEqual(got, [{ rule: 'github-pat', severity: 'CRITICAL', title: 'GitHub Personal Access Token', target: 'dist/bundle.js', line: 1 }]);
  assert.ok(!JSON.stringify(got).includes(CANARY));
});

test('parseSecrets: missing fields degrade, unknown severity -> HIGH', () => {
  assert.deepStrictEqual(S.parseSecrets({ Results: [{ Target: 'a', Secrets: [{}] }] }), [{ rule: 'unknown', severity: 'HIGH', title: '', target: 'a', line: 0 }]);
  assert.deepStrictEqual(S.parseSecrets({}), []);
});

test('redact: long token-shaped runs are stripped, short words survive', () => {
  assert.strictEqual(S.redact(`key ${CANARY} end`), 'key *** end');
  assert.strictEqual(S.redact('GitHub Personal Access Token'), 'GitHub Personal Access Token');
  assert.strictEqual(S.redact(null), '');
});

test('scanFs: argument array, scanners and skip-dirs, parses both halves', () => {
  const { spawn, calls } = fakeSpawn(TEXT);
  const r = S.scanFs('/proj/dist', { scanners: 'secret,vuln', skipDirs: ['node_modules', '.git'], scanner: TRIVY, spawn });
  assert.deepStrictEqual(calls[0].args, ['fs', '--quiet', '--format', 'json', '--scanners', 'secret,vuln', '--skip-dirs', 'node_modules', '--skip-dirs', '.git', '/proj/dist']);
  assert.strictEqual(r.scanner, 'trivy');
  assert.deepStrictEqual(r.vulns, [{ id: 'CVE-2021-23337', severity: 'HIGH', pkg: 'lodash' }, { id: 'CVE-2020-8203', severity: 'MODERATE', pkg: 'lodash' }]);
  assert.strictEqual(r.secrets.length, 1);
});

test('scanFs: rejects flag-shaped paths and skip-dirs, never shells out', () => {
  const { spawn, calls } = fakeSpawn(TEXT);
  assert.throws(() => S.scanFs('--output=/etc/x', { scanner: TRIVY, spawn }), /invalid scan path/);
  assert.throws(() => S.scanFs('/d', { skipDirs: ['-rf'], scanner: TRIVY, spawn }), /invalid skip-dir/);
  assert.throws(() => S.scanFs('', { scanner: TRIVY, spawn }), /invalid scan path/);
  assert.strictEqual(calls.length, 0);
});

test('scanFs: no trivy -> null (grype cannot do fs secrets)', () => {
  assert.strictEqual(S.scanFs('/d', { scanner: null }), null);
  assert.strictEqual(S.scanFs('/d', { scanner: { name: 'grype', bin: '/x/grype' } }), null);
});

test('scanFs: scanner failure throws with the stderr tail', () => {
  const { spawn } = fakeSpawn('', { status: 1, stderr: 'boom\n  happened' });
  assert.throws(() => S.scanFs('/d', { scanner: TRIVY, spawn }), /trivy exited 1: boom happened/);
  const timeout = () => ({ error: { code: 'ETIMEDOUT' } });
  assert.throws(() => S.scanFs('/d', { scanner: TRIVY, spawn: timeout }), /trivy failed: ETIMEDOUT/);
});

test('scanImage: trivy asks for secrets too; grype path still works and reports none', () => {
  const { spawn, calls } = fakeSpawn(TEXT);
  const r = S.scanImage('app:dev', { scanner: TRIVY, spawn });
  assert.deepStrictEqual(calls[0].args, ['image', '--quiet', '--format', 'json', '--scanners', 'vuln,secret', 'app:dev']);
  assert.strictEqual(r.secrets.length, 1);

  const grype = fakeSpawn(JSON.stringify({ matches: [{ vulnerability: { id: 'CVE-1', severity: 'High' }, artifact: { name: 'libc' } }] }));
  const g = S.scanImage('app:dev', { scanner: { name: 'grype', bin: '/x/grype' }, spawn: grype.spawn });
  assert.deepStrictEqual(g, { scanner: 'grype', vulns: [{ id: 'CVE-1', severity: 'HIGH', pkg: 'libc' }], secrets: [] });
  assert.strictEqual(S.scanImage('app:dev', { scanner: null }), null);
});

test('scanImage: rejects flag-shaped references', () => {
  const { spawn } = fakeSpawn(TEXT);
  assert.throws(() => S.scanImage('--config=/x', { scanner: TRIVY, spawn }), /invalid image reference/);
});

test('findTrivy: PATH first, then the winget Packages directory', () => {
  const home = tmp();
  const wg = path.join(home, 'AppData', 'Local', 'Microsoft', 'WinGet', 'Packages', 'AquaSecurity.Trivy_Microsoft.Winget.Source_8wekyb3d8bbwe');
  fs.mkdirSync(wg, { recursive: true });
  const exe = process.platform === 'win32' ? 'trivy.exe' : 'trivy';
  const env = { PATH: '', USERPROFILE: home, HOME: home };
  assert.strictEqual(S.findTrivy({ env }), null);
  fs.writeFileSync(path.join(wg, exe), '');
  assert.deepStrictEqual(S.findTrivy({ env }), { name: 'trivy', bin: path.join(wg, exe) });

  const onPath = tmp();
  fs.writeFileSync(path.join(onPath, exe), '');
  assert.deepStrictEqual(S.findTrivy({ env: { ...env, PATH: onPath } }), { name: 'trivy', bin: path.join(onPath, exe) });
});

test('fingerprintDir: path + newest mtime + file count, stable per content', () => {
  const dir = tmp();
  assert.match(S.fingerprintDir(path.join(dir, 'nope')), /\|missing$/);
  fs.writeFileSync(path.join(dir, 'a.js'), 'x');
  const a = S.fingerprintDir(dir);
  assert.strictEqual(a, S.fingerprintDir(dir));
  fs.writeFileSync(path.join(dir, 'b.js'), 'y');
  assert.notStrictEqual(a, S.fingerprintDir(dir));

  fs.mkdirSync(path.join(dir, 'node_modules'));
  fs.writeFileSync(path.join(dir, 'node_modules', 'c.js'), 'z');
  const skipped = S.fingerprintDir(dir, ['node_modules']);
  assert.ok(skipped.endsWith('|2'), skipped);
  assert.ok(S.fingerprintDir(dir).endsWith('|3'));
  assert.match(S.fingerprintDir(path.join(dir, 'a.js')), /a\.js\|\d+\|1$/);
});

test('re-exports lib/docker so existing image callers keep working', () => {
  const D = require('../lib/docker.js');
  assert.strictEqual(S.isFloatingTag, D.isFloatingTag);
  assert.strictEqual(S.parseReport, D.parseReport);
  assert.strictEqual(S.normSeverity, D.normSeverity);
  assert.strictEqual(S.composeImages, D.composeImages);
  assert.deepStrictEqual(D.parseReport('trivy', TEXT), D.parseReport('trivy', REPORT)); // text or parsed
});

test('live: real trivy finds a planted secret and reports no value', { skip: process.env.SECOPS_LIVE !== '1' }, () => {
  const found = S.findTrivy();
  assert.ok(found, 'trivy not installed');
  const dir = tmp();
  fs.mkdirSync(path.join(dir, 'dist'));
  fs.writeFileSync(path.join(dir, 'dist', 'bundle.js'), `const T="ghp_${'0123456789abcdefghijklmnopqrstuvwxyzAB'}";\n`);
  const r = S.scanFs(dir, { scanners: 'secret' });
  assert.ok(r.secrets.some((s) => s.rule === 'github-pat' && /bundle\.js$/.test(s.target)), JSON.stringify(r.secrets));
  assert.ok(!JSON.stringify(r.secrets).includes('ghp_0123'));
});
