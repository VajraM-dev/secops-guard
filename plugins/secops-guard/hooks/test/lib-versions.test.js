'use strict';
const test = require('node:test');
const assert = require('node:assert');
const { compareSemver, comparePep440, isPrerelease, satisfies } = require('../lib/versions');

const sorted = (cmp, list) => [...list].sort(cmp);

test('compareSemver orders releases and prereleases per semver 2.0', () => {
  const order = ['1.0.0-alpha', '1.0.0-alpha.1', '1.0.0-alpha.beta', '1.0.0-beta', '1.0.0-beta.2', '1.0.0-beta.11', '1.0.0-rc.1', '1.0.0', '1.0.1', '1.10.0', '2.0.0'];
  assert.deepStrictEqual(sorted(compareSemver, [...order].reverse()), order);
  assert.strictEqual(compareSemver('1.0.0+build', '1.0.0'), 0);
  assert.strictEqual(compareSemver('v1.2.3', '1.2.3'), 0);
  assert.strictEqual(compareSemver('junk', '0.0.1'), -1); // unparseable sorts lowest
});

test('comparePep440 handles epochs, pre/post/dev, local', () => {
  const order = ['1.0.dev0', '1.0a1.dev1', '1.0a1', '1.0b2', '1.0rc1', '1.0', '1.0+local.1', '1.0.post1.dev0', '1.0.post1', '1.1', '2!0.1'];
  assert.deepStrictEqual(sorted(comparePep440, [...order].reverse()), order);
  assert.strictEqual(comparePep440('1.0', '1.0.0'), 0);
  assert.strictEqual(comparePep440('1.0.0-alpha1', '1.0a1'), 0);
  assert.strictEqual(comparePep440('1.0-1', '1.0.post1'), 0);
  assert.strictEqual(comparePep440('1.0+abc.5', '1.0+abc.10'), -1);
});

test('isPrerelease', () => {
  assert.ok(isPrerelease('npm', '1.0.0-beta.1'));
  assert.ok(!isPrerelease('npm', '1.0.0'));
  assert.ok(isPrerelease('crates', '0.1.0-alpha'));
  assert.ok(isPrerelease('pypi', '2.0rc1'));
  assert.ok(isPrerelease('pypi', '2.0.dev3'));
  assert.ok(!isPrerelease('pypi', '2.0.post1'));
});

const cases = (eco, rows) => {
  for (const [v, spec, want] of rows) assert.strictEqual(satisfies(eco, v, spec), want, `${eco} ${v} ${JSON.stringify(spec)}`);
};

test('npm ranges', () => {
  cases('npm', [
    ['1.2.3', '^1.0.0', true], ['2.0.0', '^1.0.0', false], ['0.2.5', '^0.2.3', true], ['0.3.0', '^0.2.3', false],
    ['0.0.3', '^0.0.3', true], ['0.0.4', '^0.0.3', false], ['1.9.9', '^1', true], ['0.9.0', '^0.x', true],
    ['1.2.9', '~1.2.3', true], ['1.3.0', '~1.2.3', false], ['1.9.0', '~1', true],
    ['1.5.0', '1.x', true], ['2.0.0', '1.x', false], ['1.2.7', '1.2.*', true], ['5.0.0', '*', true], ['5.0.0', '', true],
    ['1.2.3', '1.2.3', true], ['1.2.4', '=1.2.3', false], ['1.2.3', 'v1.2.3', true],
    ['1.5.0', '>=1.2.3 <2.0.0', true], ['2.0.0', '>=1.2.3 <2.0.0', false], ['1.5.0', '>= 1.2.3 < 2', true],
    ['1.3.0', '>1.2', true], ['1.2.9', '>1.2', false], ['1.2.9', '<=1.2', true], ['1.3.0', '<=1.2', false], ['1.1.0', '<1.2', true],
    ['3.1.0', '^1.0.0 || ^3.0.0', true], ['2.1.0', '^1.0.0 || ^3.0.0', false],
    ['1.5.0', '1.2.3 - 2.3', true], ['2.3.9', '1.2.3 - 2.3', true], ['2.4.0', '1.2.3 - 2.3', false], ['2.3.4', '1.2.3 - 2.3.4', true],
    ['2.0.0-beta', '^1.0.0', false], ['1.2.4-beta', '^1.2.3', false], ['1.2.3-beta.2', '>=1.2.3-beta.1', true], ['1.2.4-beta', '>=1.2.3-beta.1', false],
    ['1.0.0', 'latest', null], ['1.0.0', 'next', null], ['1.0.0', 'git+https://x', null], ['1.0.0', '1.x.3', null], ['1.0.0', 'file:../x', null],
    ['junk', '^1.0.0', false],
  ]);
});

test('cargo requirements (bare = caret)', () => {
  cases('crates', [
    ['1.0.150', '1.0.100', true], ['2.0.0', '1.0', false], ['0.2.9', '0.2', true], ['0.3.0', '0.2.1', false],
    ['1.0.100', '=1.0.100', true], ['1.0.101', '=1.0.100', false], ['1.2.9', '~1.2.3', true], ['1.3.0', '~1.2', false],
    ['1.5.0', '>=1.2, <1.6', true], ['1.6.0', '>=1.2, <1.6', false], ['9.9.9', '*', true], ['1.9.0', '1.*', true], ['2.0.0', '1.*', false],
    ['1.0.0', '', true], ['1.0.0', 'abc', null], ['1.0.0', '>=1.0,', null],
  ]);
});

test('PyPI specifiers', () => {
  cases('pypi', [
    ['2.19.0', '==2.19.0', true], ['2.19', '==2.19.0', true], ['2.19.1', '==2.19.0', false], ['2.19.0', '!=2.19.0', false],
    ['2.5', '>=2.0,<3', true], ['3.0', '>=2.0,<3', false], ['2.5', '>=2.0, <3', true], ['1.4.9', '~=1.4.5', true], ['1.5.0', '~=1.4.5', false],
    ['2.9', '~=2.2', true], ['3.0', '~=2.2', false], ['1.2.7', '==1.2.*', true], ['1.3.0', '==1.2.*', false], ['1.3.0', '!=1.2.*', true],
    ['3.0a1', '<3.0', false], ['3.0.post1', '>3.0', false], ['3.1', '>3.0', true], ['3.0+local', '==3.0', true],
    ['2.0rc1', '>=1.0', false], ['2.0rc1', '>=2.0rc1', true], ['1.0', '===1.0', true], ['1.0.0', '===1.0', false],
    ['5.0', '', true], ['5.0b1', '', false], ['1.0', '1.0', true],
    ['1.0', 'latest', null], ['1.0', '~=1', null], ['1.0', '>=1.0;', null], ['not a version', '>=1.0', false], ['not a version', '>=junk', null],
  ]);
});

test('unknown ecosystem / non-string spec -> null', () => {
  assert.strictEqual(satisfies('maven', '1.0.0', '1.0.0'), null);
  assert.strictEqual(satisfies('npm', '1.0.0', undefined), null);
});
