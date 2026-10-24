'use strict';
const test = require('node:test');
const assert = require('node:assert');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { spawnSync } = require('node:child_process');
const B = require('../build-gate.js');
const { cfg } = require('./helpers/fakes.js');

const SCRIPT = path.join(__dirname, '..', 'build-gate.js');
const tmp = () => fs.mkdtempSync(path.join(os.tmpdir(), 'secops-build-'));
const CANARY = 'CANARYSECRETVALUE0123';

const post = (command, cwd, tool_response = { stdout: '', stderr: '', interrupted: false }) =>
  ({ hook_event_name: 'PostToolUse', tool_name: 'Bash', tool_input: { command }, tool_response, cwd });
const pre = (command, cwd) => ({ hook_event_name: 'PreToolUse', tool_name: 'Bash', tool_input: { command }, cwd });

const SECRET = { rule: 'github-pat', severity: 'CRITICAL', title: 'GitHub Personal Access Token', target: 'dist/bundle.js', line: 1 };
const CVE = { id: 'CVE-2021-23337', severity: 'HIGH', pkg: 'lodash' };

// result: what every scan returns, or an Error to throw, or null for "scanner vanished"
function bdeps({ result = { scanner: 'trivy', vulns: [], secrets: [] }, scanner = { name: 'trivy', bin: '/x/trivy' }, config = {}, clock } = {}) {
  const calls = { scanner: 0, fs: [], image: [], cached: [] };
  const deps = {
    loadConfig: () => cfg(config),
    findScanner: () => { calls.scanner++; return scanner; },
    scanFs: (p, o) => { calls.fs.push({ path: p, ...o }); if (result instanceof Error) throw result; return result; },
    scanImage: (i, o) => { calls.image.push({ image: i, ...o }); if (result instanceof Error) throw result; return result; },
    fingerprintDir: (p) => `fp(${p})`,
    cached: async (key, ttl, fn) => { calls.cached.push({ key, ttl }); return fn(); },
    now: clock || (() => 0),
  };
  return { deps, calls };
}
const never = new Proxy({}, { get: (_, k) => () => { throw new Error(`dep ${String(k)} must not be used`); }, has: () => true });

function jsProject(extra = {}) {
  const dir = tmp();
  fs.mkdirSync(path.join(dir, 'dist'));
  fs.writeFileSync(path.join(dir, 'dist', 'bundle.js'), 'x');
  for (const [f, body] of Object.entries(extra)) fs.writeFileSync(path.join(dir, f), body);
  return dir;
}

// ---------- policy ----------

test('build with CVEs -> context, never a block', async () => {
  const { deps, calls } = bdeps({ result: { scanner: 'trivy', vulns: [CVE], secrets: [] } });
  const r = await B.decide(post('npm run build', jsProject()), deps);
  assert.strictEqual(r.decision, 'context');
  assert.match(r.context, /CVE-2021-23337 \(HIGH, lodash\)/);
  assert.match(r.context, /Not blocking \(report-only policy for CVEs\)/);
  assert.strictEqual(calls.fs.length, 1);
  assert.strictEqual(path.basename(calls.fs[0].path), 'dist');
  assert.deepStrictEqual(calls.fs[0].skipDirs, ['node_modules', '.git']);
});

test('build with a secret -> block, names file/line/rule and the inlined-env-var trap', async () => {
  const { deps } = bdeps({ result: { scanner: 'trivy', vulns: [], secrets: [SECRET] } });
  const r = await B.decide(post('npm run build', jsProject()), deps);
  assert.strictEqual(r.decision, 'block');
  assert.match(r.reason, /SECRET BAKED INTO THE BUILD ARTIFACT/);
  assert.match(r.reason, /github-pat \(CRITICAL\) in dist\/bundle\.js line 1/);
  assert.match(r.reason, /rotate it now/);
  assert.match(r.reason, /\.dockerignore and \.gitignore/);
  assert.match(r.reason, /REACT_APP_\*, VITE_\* and NEXT_PUBLIC_\*/);
  assert.match(r.reason, /Do NOT publish, push or deploy/);
});

test('publish with a secret -> deny; publish with CVEs -> context', async () => {
  const dir = jsProject();
  const deny = await B.decide(pre('npm publish', dir), bdeps({ result: { scanner: 'trivy', vulns: [], secrets: [SECRET] } }).deps);
  assert.strictEqual(deny.decision, 'deny');
  assert.match(deny.reason, /^secops-guard: SECRET BAKED/);
  assert.match(deny.reason, /cannot be unpublished/);

  const ok = await B.decide(pre('npm publish', dir), bdeps({ result: { scanner: 'trivy', vulns: [CVE], secrets: [] } }).deps);
  assert.strictEqual(ok.decision, 'context');
});

test('docker push scans that image tag, not the filesystem', async () => {
  const { deps, calls } = bdeps({ result: { scanner: 'trivy', vulns: [], secrets: [SECRET] } });
  const r = await B.decide(pre('docker push registry.example.com/app:1.2.3', tmp()), deps);
  assert.strictEqual(r.decision, 'deny');
  assert.strictEqual(calls.image[0].image, 'registry.example.com/app:1.2.3');
  assert.strictEqual(calls.fs.length, 0);
  assert.ok(!r.reason.includes('REACT_APP'));
});

test('secret VALUES never reach the output, only rule / file / line', async () => {
  const leaky = { ...SECRET, title: `GitHub token ${CANARY}`, rule: CANARY };
  const { deps } = bdeps({ result: { scanner: 'trivy', vulns: [], secrets: [leaky] } });
  const r = await B.decide(pre('npm publish', jsProject()), deps);
  assert.ok(!JSON.stringify(r).includes(CANARY), JSON.stringify(r));
});

test('no scanner -> context explaining Side B is inactive, and nothing is cached', async () => {
  const { deps, calls } = bdeps({ scanner: null });
  const r = await B.decide(post('npm run build', jsProject()), deps);
  assert.strictEqual(r.decision, 'context');
  assert.match(r.context, /Side B build scanning is inactive/);
  assert.match(r.context, /winget install AquaSecurity\.Trivy/);
  assert.deepStrictEqual(calls.cached, []);
  assert.deepStrictEqual(calls.fs, []);
});

test('scanner failure -> context, never a deny', async () => {
  const { deps } = bdeps({ result: new Error('trivy failed: ETIMEDOUT') });
  const r = await B.decide(pre('npm publish', jsProject()), deps);
  assert.strictEqual(r.decision, 'context');
  assert.match(r.context, /could not scan dist \(trivy failed: ETIMEDOUT\)/);
  assert.match(r.context, /did not finish within 90s/);
});

test('budget expiry before the scan -> context, publish allowed unchecked', async () => {
  let t = 0;
  const { deps, calls } = bdeps({ clock: () => (t += 100000) }); // second read is already past the 90s budget
  const r = await B.decide(pre('npm publish', jsProject()), deps);
  assert.strictEqual(r.decision, 'context');
  assert.match(r.context, /did not finish within 90s/);
  assert.match(r.context, /SECOPS_BUILD_BUDGET_MS/);
  assert.deepStrictEqual(calls.fs, []);
});

test('failed build and non-build commands -> no output, no scanner lookup', async () => {
  assert.strictEqual(await B.decide(post('npm run build', jsProject(), { exitCode: 1 }), never), null);
  assert.strictEqual(await B.decide(post('npm run build', jsProject(), { interrupted: true }), never), null);
  assert.strictEqual(await B.decide(post('npm test', tmp()), never), null);
  assert.strictEqual(await B.decide(post('git commit -m "npm run build"', tmp()), never), null);
  assert.strictEqual(await B.decide(pre('npm install lodash', tmp()), never), null);
  assert.strictEqual(await B.decide(pre('cargo publish --dry-run', tmp()), never), null); // a dry run is a build, not a publish
  assert.strictEqual(await B.decide({ tool_name: 'Bash', tool_input: {} }, never), null);
});

test('clean scan -> null', async () => {
  const { deps } = bdeps();
  assert.strictEqual(await B.decide(post('pnpm build', jsProject()), deps), null);
});

test('allowlisted image tag is skipped entirely', async () => {
  const { deps, calls } = bdeps({ config: { allow: new Set(['image:app:dev']) }, result: { scanner: 'trivy', vulns: [], secrets: [SECRET] } });
  assert.strictEqual(await B.decide(pre('docker push app:dev', tmp()), deps), null);
  assert.deepStrictEqual(calls.image, []);
});

test('a build/publish pair reuses one cache key per artifact', async () => {
  const dir = jsProject();
  const { deps, calls } = bdeps();
  await B.decide(post('npm run build', dir), deps);
  await B.decide(pre('npm publish', dir), deps);
  assert.strictEqual(calls.cached.length, 2);
  assert.strictEqual(calls.cached[0].key, calls.cached[1].key);
  assert.strictEqual(calls.cached[0].ttl, 10 * 60e3);
});

// ---------- .dockerignore ----------

test('docker build without .dockerignore -> context warning (not a deny)', async () => {
  const dir = tmp();
  fs.writeFileSync(path.join(dir, '.env'), 'API_KEY=x');
  const { deps } = bdeps();
  const r = await B.decide(post('docker build -t app:dev .', dir), deps);
  assert.strictEqual(r.decision, 'context');
  assert.match(r.context, /has no \.dockerignore/);
  assert.match(r.context, /\.env\*/);
});

test('.dockerignore that misses .git is still flagged; a complete one is silent', () => {
  const dir = tmp();
  fs.writeFileSync(path.join(dir, '.env'), 'x');
  fs.writeFileSync(path.join(dir, '.dockerignore'), '# comment\n.env*\nnode_modules\n');
  assert.match(B.dockerignoreIssue(dir), /does not exclude \.git\b/);
  fs.writeFileSync(path.join(dir, '.dockerignore'), '.env\n.git\n');
  assert.strictEqual(B.dockerignoreIssue(dir), null);
  fs.writeFileSync(path.join(dir, '.dockerignore'), '*\n!src\n');
  assert.strictEqual(B.dockerignoreIssue(dir), null);
  // nothing sensitive in the context and no .dockerignore: nothing to warn about
  assert.strictEqual(B.dockerignoreIssue(tmp()), null);
});

// ---------- detection ----------

test('buildKind covers the four ecosystems and rejects lookalikes', () => {
  for (const c of ['npm run build', 'pnpm build', 'yarn build', 'bun run build', 'npm run build:prod', 'vite build', 'npx next build', 'sudo npx astro build', 'CI=1 npm run build']) {
    assert.strictEqual(B.buildKind(require('../lib/parse-command').tokenize(c)), 'js', c);
  }
  const k = (c) => B.buildKind(require('../lib/parse-command').tokenize(c));
  assert.strictEqual(k('python -m build'), 'py');
  assert.strictEqual(k('poetry build'), 'py');
  assert.strictEqual(k('pip wheel .'), 'py');
  assert.strictEqual(k('hatch build'), 'py');
  assert.strictEqual(k('python setup.py bdist_wheel'), 'py');
  assert.strictEqual(k('cargo build --release'), 'rust');
  assert.strictEqual(k('cargo publish --dry-run'), 'rust');
  assert.strictEqual(k('cargo build'), null); // debug build ships nothing
  assert.strictEqual(k('npm run test'), null);
  assert.strictEqual(k('npm run buildx'), null);
  assert.strictEqual(k('python -m pytest'), null);
  assert.strictEqual(k(''), null);
});

test('publishKind covers the outward-facing commands only', () => {
  const p = (c) => B.publishKind(require('../lib/parse-command').tokenize(c));
  assert.deepStrictEqual(p('docker push app:1.0'), { kind: 'image', tag: 'app:1.0' });
  assert.deepStrictEqual(p('docker image push app:1.0'), { kind: 'image', tag: 'app:1.0' });
  assert.deepStrictEqual(p('npm publish --access public'), { kind: 'js' });
  assert.deepStrictEqual(p('yarn npm publish'), { kind: 'js' });
  assert.deepStrictEqual(p('twine upload dist/*'), { kind: 'py' });
  assert.deepStrictEqual(p('poetry publish'), { kind: 'py' });
  assert.deepStrictEqual(p('cargo publish'), { kind: 'rust' });
  assert.deepStrictEqual(p('gh release upload v1 ./a.zip'), { kind: 'files', files: ['./a.zip'] });
  assert.strictEqual(p('cargo publish --dry-run'), null);
  assert.strictEqual(p('docker push'), null);
  assert.strictEqual(p('npm run publish-docs'), null);
  assert.strictEqual(p('gh release list'), null);
});

test('jobsFor: outdir precedence, cwd fallback, rust split', () => {
  const dir = tmp();
  assert.strictEqual(B.jobsFor({ kind: 'js' }, dir)[0].path, dir); // no outdir -> project root
  assert.deepStrictEqual(B.jobsFor({ kind: 'js' }, dir)[0].skipDirs, ['node_modules', '.git']);
  fs.mkdirSync(path.join(dir, 'build'));
  fs.mkdirSync(path.join(dir, 'dist'));
  assert.strictEqual(B.jobsFor({ kind: 'js' }, dir)[0].path, path.join(dir, 'dist')); // dist wins

  const rust = tmp();
  fs.mkdirSync(path.join(rust, 'target', 'release'), { recursive: true });
  fs.writeFileSync(path.join(rust, 'Cargo.lock'), '');
  assert.deepStrictEqual(B.jobsFor({ kind: 'rust' }, rust).map((j) => [path.relative(rust, j.path), j.scanners]),
    [[path.join('target', 'release'), 'secret'], ['Cargo.lock', 'vuln']]);

  const rel = tmp();
  fs.writeFileSync(path.join(rel, 'a.zip'), 'x');
  assert.deepStrictEqual(B.jobsFor({ kind: 'files', files: ['a.zip', 'missing.zip'] }, rel).map((j) => j.label), ['a.zip']);
});

// ---------- process ----------

test('spawned script: exits 0 and stays silent on irrelevant input', () => {
  const run = (payload, env = {}) => spawnSync(process.execPath, [SCRIPT], { input: JSON.stringify(payload), encoding: 'utf8', env: { ...process.env, ...env } });
  let r = run(post('npm test', tmp()));
  assert.strictEqual(r.status, 0);
  assert.strictEqual(r.stdout, '');

  r = run(post('npm run build', jsProject()), { SECOPS_DISABLE: '1' });
  assert.strictEqual(r.status, 0);
  assert.strictEqual(r.stdout, '');

  r = spawnSync(process.execPath, [SCRIPT], { input: 'not json', encoding: 'utf8' });
  assert.strictEqual(r.status, 0);
  assert.strictEqual(r.stdout, '');

  r = run({ hook_event_name: 'PreToolUse', tool_name: 'Read', tool_input: { file_path: 'x' } });
  assert.strictEqual(r.status, 0);
  assert.strictEqual(r.stdout, '');
});

test('spawned script: emits PostToolUse additionalContext when no scanner is installed', { skip: process.platform !== 'win32' }, () => {
  const home = tmp(); // no trivy on this PATH and no winget Packages dir under this home
  const r = spawnSync(process.execPath, [SCRIPT], {
    input: JSON.stringify(post('npm run build', jsProject())),
    encoding: 'utf8',
    env: { ...process.env, PATH: '', Path: '', USERPROFILE: home, HOME: home, SECOPS_STATE_DIR: path.join(home, 'state') },
  });
  assert.strictEqual(r.status, 0);
  const out = JSON.parse(r.stdout);
  assert.strictEqual(out.hookSpecificOutput.hookEventName, 'PostToolUse');
  assert.match(out.hookSpecificOutput.additionalContext, /Side B build scanning is inactive/);
});

test('live: real trivy denies a publish of a bundle holding a planted secret', { skip: process.env.SECOPS_LIVE !== '1' }, async () => {
  const S = require('../lib/scan.js');
  assert.ok(S.findTrivy(), 'trivy not installed');
  const dir = tmp();
  fs.mkdirSync(path.join(dir, 'dist'));
  const token = `ghp_${'0123456789abcdefghijklmnopqrstuvwxyzAB'}`;
  fs.writeFileSync(path.join(dir, 'dist', 'bundle.js'), `const T="${token}";\n`);
  const r = await B.decide(pre('npm publish', dir), { cached: async (k, t, fn) => fn() });
  assert.strictEqual(r.decision, 'deny');
  assert.match(r.reason, /github-pat/);
  assert.ok(!JSON.stringify(r).includes('ghp_0123'));
});
