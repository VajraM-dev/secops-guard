'use strict';
const test = require('node:test');
const assert = require('node:assert');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { spawnSync } = require('node:child_process');
const M = require('../manifest-gate.js');
const { fakes, throwing } = require('./helpers/fakes.js');

const SCRIPT = path.join(__dirname, '..', 'manifest-gate.js');
const tmp = () => fs.mkdtempSync(path.join(os.tmpdir(), 'secops-man-'));
const names = (list) => list.map((x) => `${x.ecosystem}:${x.name}@${x.spec}${x.unparsed ? '?' : ''}`);

function setup(file, content) {
  const dir = tmp();
  const p = path.join(dir, file);
  if (content != null) fs.writeFileSync(p, content);
  return { dir, p };
}

const PKG = JSON.stringify({ dependencies: { lodash: '^4.17.21' }, devDependencies: { jest: '29.0.0' } }, null, 2);

test('package.json Edit adding a dep is checked; vulnerable -> deny', async () => {
  const { dir, p } = setup('package.json', PKG);
  const { deps, calls } = fakes({ registry: { 'npm:left-pad': '1.1.0' }, vulns: { 'npm:left-pad@1.1.0': [{ id: 'GHSA-lp', severity: 'HIGH', fixed: '1.3.0' }] } });
  const payload = { tool_name: 'Edit', cwd: dir, tool_input: { file_path: p, old_string: '"lodash": "^4.17.21"', new_string: '"lodash": "^4.17.21",\n    "left-pad": "~1.1.0"' } };
  const r = await M.decide(payload, deps);
  assert.strictEqual(r.decision, 'deny');
  assert.match(r.reason, /^secops-guard: left-pad@1\.1\.0 has known vulnerabilities/);
  assert.match(r.reason, /dependency added in package\.json/);
  assert.deepStrictEqual(calls.resolve.map((c) => `${c.name}@${c.spec}`), ['left-pad@~1.1.0']);
});

test('package.json edit that touches no deps: null, deps untouched', async () => {
  const { dir, p } = setup('package.json', PKG);
  const payload = { tool_name: 'Edit', cwd: dir, tool_input: { file_path: p, old_string: '"jest"', new_string: '"jest"' } };
  assert.strictEqual(await M.decide(payload, throwing), null);
});

test('version change counts as change; git/file/workspace specs ignored', () => {
  const before = PKG;
  const after = JSON.stringify({ dependencies: { lodash: '^4.17.20', mine: 'file:../mine', gh: 'user/repo', ws: 'workspace:*', al: 'npm:real@2.0.0' }, devDependencies: { jest: '29.0.0' } });
  assert.deepStrictEqual(names(M.changedDeps('npm', before, after)), ['npm:lodash@^4.17.20', 'npm:real@2.0.0']);
});

test('invalid JSON mid-edit: null', async () => {
  const { dir, p } = setup('package.json', PKG);
  const r = await M.decide({ tool_name: 'Write', cwd: dir, tool_input: { file_path: p, content: '{ "dependencies": {' } }, throwing);
  assert.strictEqual(r, null);
});

test('requirements.txt Write on new file: not found -> deny', async () => {
  const { dir, p } = setup('requirements-dev.txt', null);
  const { deps } = fakes({ registry: { 'pypi:flask': '3.0.0' } });
  const r = await M.decide({ tool_name: 'Write', cwd: dir, tool_input: { file_path: p, content: '# deps\nflask==3.0.0\nflaskk-extra>=1  # typo\n-r base.txt\n-e .\n' } }, deps);
  assert.strictEqual(r.decision, 'deny');
  assert.match(r.reason, /"flaskk-extra" does not exist/);
  assert.doesNotMatch(r.reason, /flask@3/);
});

test('MultiEdit and replace_all are applied before diffing', () => {
  const cur = 'a==1\nb==1\n';
  assert.strictEqual(M.newContent('MultiEdit', { edits: [{ old_string: 'a==1', new_string: 'a==2' }, { old_string: 'b==1', new_string: 'c==1' }] }, cur), 'a==2\nc==1\n');
  assert.strictEqual(M.newContent('Edit', { old_string: '==1', new_string: '==3', replace_all: true }, cur), 'a==3\nb==3\n');
  assert.strictEqual(M.newContent('Edit', { old_string: '==1', new_string: '$&x' }, cur), 'a$&x\nb==1\n');
  assert.strictEqual(M.newContent('Edit', { old_string: 'zzz', new_string: 'y' }, cur), null);
});

test('pyproject: [project] arrays, optional deps, dependency-groups, poetry tables', () => {
  const toml = [
    '[project]',
    'name = "x"',
    'dependencies = [',
    '  "httpx>=0.27",',
    '  "rich[jupyter]==13.7.1 ; python_version >= \'3.9\'",  # comment',
    '  "local @ file:///tmp/x",',
    ']',
    '[project.optional-dependencies]',
    'dev = ["pytest>=8"]',
    '[dependency-groups]',
    'lint = ["ruff==0.4.0", {include-group = "dev"}]',
    '[tool.poetry.dependencies]',
    'python = "^3.11"',
    'django = "^4.2"',
    'celery = { version = "~5.3", extras = ["redis"] }',
    'mylib = { path = "../mylib" }',
    'weird = "4.*"',
    '[tool.poetry.group.dev.dependencies]',
    'black = "24.1.0"',
  ].join('\n');
  assert.deepStrictEqual(names(M.changedDeps('pyproject', '', toml)), [
    'pypi:httpx@>=0.27', 'pypi:rich@==13.7.1', 'pypi:pytest@>=8', 'pypi:ruff@==0.4.0',
    'pypi:django@>=4.2,<5', 'pypi:celery@>=5.3,<5.4', 'pypi:weird@4.*?', 'pypi:black@==24.1.0',
  ]);
});

test('Cargo.toml: dependency tables, inline tables, renames, subtables', () => {
  const toml = [
    '[package]',
    'version = "0.1.0"',
    '[dependencies]',
    'serde = "1.0"',
    'tokio = { version = "1", features = ["full"] }',
    'local = { path = "../local" }',
    'ws = { workspace = true }',
    'alias = { package = "real-crate", version = "2" }',
    '[dev-dependencies]',
    'insta = "1.34"',
    "[target.'cfg(unix)'.dependencies]",
    'nix = "0.27"',
    '[dependencies.reqwest]',
    'version = "0.11"',
    'features = ["json"]',
    '[workspace.dependencies]',
    'anyhow = "1"',
  ].join('\n');
  assert.deepStrictEqual(names(M.changedDeps('cargo', '', toml)), [
    'crates:serde@1.0', 'crates:tokio@1', 'crates:real-crate@2', 'crates:insta@1.34', 'crates:nix@0.27', 'crates:reqwest@0.11', 'crates:anyhow@1',
  ]);
});

test('Cargo.toml version bump is detected; unchanged deps are not rechecked', () => {
  const a = '[dependencies]\nserde = "1.0"\ntokio = "1"\n';
  const b = '[dependencies]\nserde = "1.0"\ntokio = "1.40"\n';
  assert.deepStrictEqual(names(M.changedDeps('cargo', a, b)), ['crates:tokio@1.40']);
});

test('unparseable spec -> additionalContext note, not deny', async () => {
  const { dir, p } = setup('pyproject.toml', '[tool.poetry.dependencies]\npython = "^3.11"\n');
  const { deps, calls } = fakes();
  const r = await M.decide({ tool_name: 'Edit', cwd: dir, tool_input: { file_path: p, old_string: 'python = "^3.11"', new_string: 'python = "^3.11"\nfoo = "4.*"' } }, deps);
  assert.strictEqual(r.decision, 'context');
  assert.match(r.context, /could not check foo/);
  assert.strictEqual(calls.resolve.length, 0);
});

test('clean dependency -> no output', async () => {
  const { dir, p } = setup('Cargo.toml', '[dependencies]\n');
  const { deps } = fakes({ registry: { 'crates:serde': '1.0.190' } });
  const r = await M.decide({ tool_name: 'Write', cwd: dir, tool_input: { file_path: p, content: '[dependencies]\nserde = "1.0"\n' } }, deps);
  assert.strictEqual(r, null);
});

test('too-new dep in manifest -> deny', async () => {
  const { dir, p } = setup('package.json', '{}');
  const { deps } = fakes({ registry: { 'npm:fresh': { error: 'too_new', detail: { version: '3.0.0', suggestion: '2.9.0' } } } });
  const r = await M.decide({ tool_name: 'Write', cwd: dir, tool_input: { file_path: p, content: '{"dependencies":{"fresh":"3.0.0"}}' } }, deps);
  assert.match(r.reason, /Use fresh@2\.9\.0 instead/);
});

test('other files are ignored', async () => {
  assert.strictEqual(M.kindOf('src/index.ts'), null);
  assert.strictEqual(M.kindOf('C:\\proj\\Requirements-dev.txt'), 'req');
  assert.strictEqual(await M.decide({ tool_name: 'Write', tool_input: { file_path: 'README.md', content: 'x' } }, throwing), null);
});

const run = (input, env = {}) => spawnSync(process.execPath, [SCRIPT], { input, encoding: 'utf8', env: { ...process.env, SECOPS_STATE_DIR: tmp(), ...env } });

test('spawn: non-manifest file and SECOPS_DISABLE -> no output', () => {
  let r = run(JSON.stringify({ tool_name: 'Write', tool_input: { file_path: 'a.js', content: 'x' } }));
  assert.strictEqual(r.status, 0);
  assert.strictEqual(r.stdout, '');
  r = run(JSON.stringify({ tool_name: 'Write', tool_input: { file_path: path.join(tmp(), 'package.json'), content: '{"dependencies":{"x":"1"}}' } }), { SECOPS_DISABLE: '1' });
  assert.strictEqual(r.stdout, '');
  r = run('garbage');
  assert.strictEqual(r.stdout, '');
});
