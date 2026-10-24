'use strict';
const test = require('node:test');
const assert = require('node:assert');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { findLockfiles, parseLockfile } = require('../lib/lockfiles');

const FX = path.join(__dirname, 'fixtures');
const ids = (file) => parseLockfile(path.join(FX, file)).map((p) => `${p.ecosystem}:${p.name}@${p.version}`).sort();

test('package-lock v3: node_modules keys, nested, alias name, skips root/link/workspace/git', () => {
  assert.deepStrictEqual(ids('npm-v3/package-lock.json'), [
    'npm:@babel/code-frame@7.22.13', 'npm:chalk@2.4.2', 'npm:lodash@4.17.15', 'npm:real-pkg@1.0.0',
  ]);
});

test('npm-shrinkwrap v1: dependency tree, nested versions, npm: alias, skips git', () => {
  assert.deepStrictEqual(ids('npm-v1/npm-shrinkwrap.json'), [
    'npm:lodash@4.17.21', 'npm:minimist@0.0.8', 'npm:minimist@1.2.0', 'npm:mkdirp@0.5.1',
  ]);
});

test('pnpm v6: leading slash, quoted keys, peer suffix stripped', () => {
  assert.deepStrictEqual(ids('pnpm-v6/pnpm-lock.yaml'), [
    'npm:@babel/core@7.22.0', 'npm:@types/node@20.8.0', 'npm:debug@4.3.4', 'npm:lodash@4.17.15',
  ]);
});

test('pnpm v9: packages + snapshots deduped, inline {} values, ignores importers and tarballs', () => {
  assert.deepStrictEqual(ids('pnpm-v9/pnpm-lock.yaml'), [
    'npm:@types/node@22.10.1', 'npm:express@4.18.2', 'npm:ms@2.1.3', 'npm:vite@5.4.11',
  ]);
});

test('yarn v1: multi-selector keys, scoped, alias, skips file:', () => {
  assert.deepStrictEqual(ids('yarn-v1/yarn.lock'), [
    'npm:@babel/code-frame@7.12.13', 'npm:lodash@4.17.15', 'npm:lodash@4.17.21',
  ]);
});

test('yarn berry: uses resolution, skips workspace and patch protocols', () => {
  assert.deepStrictEqual(ids('yarn-berry/yarn.lock'), ['npm:@babel/code-frame@7.24.2', 'npm:lodash@4.17.21']);
});

test('bun.lock: packages entries, skips workspace', () => {
  assert.deepStrictEqual(ids('bun/bun.lock'), ['npm:@types/node@20.8.0', 'npm:lodash@4.17.15', 'npm:undici-types@5.25.3']);
});

test('requirements.txt: only == pins, extras/markers/comments/hashes handled, names PEP 503', () => {
  assert.deepStrictEqual(ids('py-req/requirements.txt'), [
    'pypi:cryptography@41.0.0', 'pypi:django@3.2.0', 'pypi:pillow@9.0.0', 'pypi:requests@2.19.0', 'pypi:urllib3@1.26.5',
  ]);
});

test('uv.lock: registry packages only', () => {
  assert.deepStrictEqual(ids('uv/uv.lock'), ['pypi:certifi@2024.2.2', 'pypi:requests@2.19.0']);
});

test('poetry.lock: subtable keys ignored, directory source skipped', () => {
  assert.deepStrictEqual(ids('poetry/poetry.lock'), ['pypi:jinja2@2.10', 'pypi:markupsafe@2.1.5']);
});

test('Pipfile.lock: default + develop, deduped, editable skipped', () => {
  assert.deepStrictEqual(ids('pipfile/Pipfile.lock'), ['pypi:flask-login@0.6.0', 'pypi:pytest@7.0.0', 'pypi:requests@2.19.0']);
});

test('Cargo.lock: registry packages only (workspace + git skipped)', () => {
  assert.deepStrictEqual(ids('cargo/Cargo.lock'), ['crates:serde@1.0.150', 'crates:smallvec@1.6.0']);
});

test('CRLF line endings and BOM parse the same', () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'sg-lock-'));
  const src = fs.readFileSync(path.join(FX, 'cargo/Cargo.lock'), 'utf8');
  fs.writeFileSync(path.join(dir, 'Cargo.lock'), '\uFEFF' + src.replace(/\n/g, '\r\n'));
  assert.deepStrictEqual(parseLockfile(path.join(dir, 'Cargo.lock')).length, 2);
  fs.rmSync(dir, { recursive: true, force: true });
});

test('unknown file -> []; malformed JSON lockfile throws', () => {
  assert.deepStrictEqual(parseLockfile(path.join(FX, 'py-req/notes.txt')), []);
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'sg-lock-'));
  fs.writeFileSync(path.join(dir, 'package-lock.json'), '{nope');
  assert.throws(() => parseLockfile(path.join(dir, 'package-lock.json')));
  fs.rmSync(dir, { recursive: true, force: true });
});

test('findLockfiles: per ecosystem, requirements*.txt glob, no recursion', () => {
  const rel = (list) => list.map((p) => path.basename(p));
  assert.deepStrictEqual(rel(findLockfiles(path.join(FX, 'py-req'), 'pypi')), ['requirements-dev.txt', 'requirements.txt']);
  assert.deepStrictEqual(rel(findLockfiles(path.join(FX, 'py-req'), 'npm')), []);
  assert.deepStrictEqual(rel(findLockfiles(path.join(FX, 'cargo'))), ['Cargo.lock']);
  assert.deepStrictEqual(findLockfiles(FX), []);
  assert.deepStrictEqual(findLockfiles(path.join(FX, 'does-not-exist')), []);
});
