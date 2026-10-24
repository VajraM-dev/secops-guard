'use strict';
const test = require('node:test');
const assert = require('node:assert');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { spawnSync } = require('node:child_process');
const { snapshotPlugins, diffSnapshots, riskyMarketplaces, run } = require('../plugin-integrity.js');

const SCRIPT = path.join(__dirname, '..', 'plugin-integrity.js');

function put(root, rel, content) {
  const p = path.join(root, ...rel.split('/'));
  fs.mkdirSync(path.dirname(p), { recursive: true });
  fs.writeFileSync(p, content);
}

// Fake ~/.claude with one cached plugin (two versions), a root-style and a plugins/-style marketplace, user hooks.
function fakeHome() {
  const home = fs.mkdtempSync(path.join(os.tmpdir(), 'secops-pi-'));
  put(home, 'plugins/cache/mk/p1/1.0.0/hooks/a.js', 'old');
  put(home, 'plugins/cache/mk/p1/2.0.0/hooks/hooks.json', '{"hooks":{}}');
  put(home, 'plugins/cache/mk/p1/2.0.0/hooks/a.js', 'v2');
  put(home, 'plugins/cache/mk/p1/2.0.0/.claude-plugin/plugin.json', '{"name":"p1"}');
  put(home, 'plugins/cache/mk/p1/2.0.0/README.md', 'not hashed');
  put(home, 'plugins/cache/mk/p1/2.0.0/node_modules/x/index.js', 'skipped');
  put(home, 'plugins/cache/mk/p1/2.0.0/.mcp.json', '{"mcpServers":{}}');
  put(home, 'plugins/installed_plugins.json', JSON.stringify({ plugins: {
    'p1@mk': [{ installPath: path.join(home, 'plugins/cache/mk/p1/1.0.0') }],
    'rp@rootmk': [{}],
    'q@multi': [{ installPath: path.join(home, 'missing') }],
  } }));
  put(home, 'plugins/marketplaces/rootmk/.claude-plugin/plugin.json', '{"name":"rp"}');
  put(home, 'plugins/marketplaces/rootmk/scripts/run.txt', 'in scripts dir');
  put(home, 'plugins/marketplaces/multi/plugins/q/hooks/h.py', 'print(1)');
  put(home, 'plugins/marketplaces/notinstalled/.claude-plugin/plugin.json', '{"name":"ni"}');
  put(home, 'plugins/marketplaces/notinstalled/src/big.js', 'monorepo code');
  put(home, 'hooks/guard.py', 'x');
  put(home, 'settings.json', JSON.stringify({
    hooks: { PreToolUse: [] },
    extraKnownMarketplaces: { mk: { source: { source: 'github', repo: 'o/mk' }, autoUpdate: true }, safe: { source: { repo: 'o/s' } } },
  }));
  return home;
}

test('snapshot: keys, installPath is source of truth, marketplace fallbacks', () => {
  const home = fakeHome();
  let s = snapshotPlugins(home);
  assert.deepStrictEqual(Object.keys(s.plugins).sort(), ['mk/p1', 'multi/q', 'rootmk/rp', 'user/hooks']);
  assert.ok(s.plugins['mk/p1'].root.endsWith('1.0.0'), 'active installPath wins over newer cached version');
  assert.strictEqual(s.plugins['rootmk/rp'].root, path.join(home, 'plugins/marketplaces/rootmk'));
  assert.strictEqual(s.plugins['multi/q'].root, path.join(home, 'plugins/marketplaces/multi/plugins/q'));
  assert.ok('hooks/h.py' in s.plugins['multi/q'].files);
  assert.ok('scripts/run.txt' in s.plugins['rootmk/rp'].files);
  put(home, 'plugins/installed_plugins.json', JSON.stringify({ plugins: { 'p1@mk': [{ installPath: path.join(home, 'plugins/cache/mk/p1/2.0.0') }] } }));
  s = snapshotPlugins(home);
  assert.deepStrictEqual(Object.keys(s.plugins).sort(), ['mk/p1', 'user/hooks'], 'uninstalled marketplace clones are not walked');
  const p1 = s.plugins['mk/p1'];
  assert.ok(p1.root.endsWith('2.0.0'));
  assert.deepStrictEqual(Object.keys(p1.files).sort(), ['.claude-plugin/plugin.json', '.mcp.json', 'hooks/a.js', 'hooks/hooks.json']);
  assert.match(p1.files['hooks/a.js'], /^[0-9a-f]{64}$/);
  assert.deepStrictEqual(p1.hooks, { hooks: {} });
  assert.deepStrictEqual(p1.mcp, { mcpServers: {} });
  assert.deepStrictEqual(Object.keys(s.plugins['user/hooks'].files).sort(), ['hooks/guard.py', 'settings.json#hooks']);
  assert.ok(!Number.isNaN(Date.parse(s.takenAt)));
});

test('snapshot: falls back to newest cached version without installed_plugins.json', () => {
  const home = fakeHome();
  fs.rmSync(path.join(home, 'plugins/installed_plugins.json'));
  const old = path.join(home, 'plugins/cache/mk/p1/1.0.0');
  fs.utimesSync(old, new Date(2000, 0, 1), new Date(2000, 0, 1));
  assert.ok(snapshotPlugins(home).plugins['mk/p1'].root.endsWith('2.0.0'));
});

test('snapshot: skips files over 2 MB', () => {
  const home = fakeHome();
  put(home, 'plugins/cache/mk/p1/2.0.0/hooks/big.js', Buffer.alloc(2 * 1024 * 1024 + 1));
  assert.ok(!('hooks/big.js' in snapshotPlugins(home).plugins['mk/p1'].files));
});

test('snapshot: missing claude home gives empty plugins', () => {
  assert.deepStrictEqual(snapshotPlugins(path.join(os.tmpdir(), 'secops-does-not-exist-xyz')).plugins, {});
});

test('diffSnapshots: added, removed, changed (modified/new/deleted files)', () => {
  const prev = { plugins: { a: { files: { x: '1', y: '2' } }, gone: { files: {} }, same: { files: { z: '1' } } } };
  const next = { plugins: { a: { files: { x: '9', w: '3' } }, fresh: { files: {} }, same: { files: { z: '1' } } } };
  assert.deepStrictEqual(diffSnapshots(prev, next), {
    added: ['fresh'], removed: ['gone'], changed: [{ plugin: 'a', files: ['w', 'x', 'y'] }],
  });
  assert.deepStrictEqual(diffSnapshots(next, next), { added: [], removed: [], changed: [] });
  assert.deepStrictEqual(diffSnapshots(null, { plugins: { a: { files: {} } } }).added, ['a']);
});

test('riskyMarketplaces: only autoUpdate true', () => {
  assert.deepStrictEqual(riskyMarketplaces({ extraKnownMarketplaces: {
    a: { source: { repo: 'o/a' }, autoUpdate: true }, b: { source: { url: 'https://x' }, autoUpdate: false }, c: { source: { url: 'https://c' }, autoUpdate: true },
  } }), [{ name: 'a', repo: 'o/a', autoUpdate: true }, { name: 'c', repo: 'https://c', autoUpdate: true }]);
  assert.deepStrictEqual(riskyMarketplaces({}), []);
  assert.deepStrictEqual(riskyMarketplaces(null), []);
});

test('run: baseline, then quiet, then change report, risky once per day', () => {
  const home = fakeHome();
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'secops-state-'));
  const t0 = Date.UTC(2026, 0, 1);

  const r1 = run({ claudeHome: home, dir, now: t0 });
  assert.strictEqual(r1.userMsg, null);
  assert.match(r1.claudeContext, /baseline recorded for 4 plugins/);
  assert.match(r1.claudeContext, /autoUpdate on/);
  assert.ok(fs.existsSync(path.join(dir, 'plugin-snapshot.json')));

  assert.deepStrictEqual(run({ claudeHome: home, dir, now: t0 + 1000 }), { userMsg: null, claudeContext: null });

  put(home, 'plugins/cache/mk/p1/1.0.0/hooks/a.js', 'tampered');
  const r3 = run({ claudeHome: home, dir, now: t0 + 2000 });
  assert.match(r3.userMsg, /~ mk\/p1: hooks\/a\.js/);
  assert.doesNotMatch(r3.userMsg, /autoUpdate/);
  assert.match(r3.claudeContext, /\/secops-guard:plugin-audit/);

  const r4 = run({ claudeHome: home, dir, now: t0 + 25 * 3600 * 1000 });
  assert.match(r4.userMsg, /autoUpdate on[^\n]*mk/);
  assert.match(r4.claudeContext, /plugin-audit/);
});

test('run: summary capped at 10 lines', () => {
  const home = fakeHome();
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'secops-state-'));
  run({ claudeHome: home, dir, now: 0 });
  for (let i = 0; i < 15; i++) put(home, `plugins/cache/mk/n${i}/1.0.0/hooks/h.js`, 'x');
  const r = run({ claudeHome: home, dir, now: 1 });
  const listed = r.userMsg.split('\n').filter((l) => l.startsWith('  '));
  assert.strictEqual(listed.length, 10);
  assert.match(listed[9], /and 6 more/);
});

test('run: never writes into claude home', () => {
  const home = fakeHome();
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'secops-state-'));
  const list = (p) => fs.readdirSync(p, { recursive: true }).sort();
  const before = list(home);
  run({ claudeHome: home, dir });
  assert.deepStrictEqual(list(home), before);
});

const spawnRun = (env) => spawnSync(process.execPath, [SCRIPT], { input: '{}', encoding: 'utf8', env: { ...process.env, ...env } });

test('spawn: SECOPS_DISABLE=1 prints nothing', () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'secops-state-'));
  const r = spawnRun({ SECOPS_STATE_DIR: dir, SECOPS_DISABLE: '1' });
  assert.strictEqual(r.status, 0);
  assert.strictEqual(r.stdout, '');
  assert.ok(!fs.existsSync(path.join(dir, 'plugin-snapshot.json')));
});

test('spawn: baseline output is SessionStart JSON with context only', () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'secops-state-'));
  const user = fs.mkdtempSync(path.join(os.tmpdir(), 'secops-user-'));
  fs.renameSync(fakeHome(), path.join(user, '.claude'));
  // USERPROFILE/HOME redirect os.homedir() so the real ~/.claude is never touched
  const r = spawnRun({ SECOPS_STATE_DIR: dir, USERPROFILE: user, HOME: user });
  assert.strictEqual(r.status, 0);
  const out = JSON.parse(r.stdout);
  assert.strictEqual(out.systemMessage, undefined);
  assert.strictEqual(out.hookSpecificOutput.hookEventName, 'SessionStart');
  assert.match(out.hookSpecificOutput.additionalContext, /baseline recorded/);
});

test('spawn: unwritable state dir prints nothing, exits 0', () => {
  const f = path.join(fs.mkdtempSync(path.join(os.tmpdir(), 'secops-state-')), 'file');
  fs.writeFileSync(f, 'x');
  const user = path.dirname(f);
  const r = spawnRun({ SECOPS_STATE_DIR: path.join(f, 'sub'), USERPROFILE: user, HOME: user });
  assert.strictEqual(r.status, 0);
  assert.strictEqual(r.stdout, '');
});

// Fake clock: each call advances 1 ms, so deadline N lets exactly N plugins through.
const ticker = () => { let t = 0; return () => t++; };
const readSnap = (dir) => JSON.parse(fs.readFileSync(path.join(dir, 'plugin-snapshot.json'), 'utf8'));

test('budget: snapshot stops between plugins, records covered and pending', () => {
  const home = fakeHome();
  const s = snapshotPlugins(home, { deadline: 2, clock: ticker() });
  assert.strictEqual(s.partial, true);
  assert.strictEqual(s.covered.length, 2);
  assert.deepStrictEqual(Object.keys(s.plugins).sort(), [...s.covered].sort());
  assert.strictEqual(s.covered.length + s.pending.length, 4);
  for (const k of s.covered) assert.ok(Object.keys(s.plugins[k].files).length > 0, 'covered plugin fully hashed');
  const s2 = snapshotPlugins(home, { deadline: 1, clock: ticker(), first: s.pending });
  assert.deepStrictEqual(s2.covered, [s.pending[0]], 'pending keys go first');
  assert.strictEqual(snapshotPlugins(home).partial, undefined);
});

test('budget exceeded: partial snapshot, no output; next full run completes baseline', () => {
  const home = fakeHome();
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'secops-state-'));
  assert.deepStrictEqual(run({ claudeHome: home, dir, budget: 0 }), { userMsg: null, claudeContext: null });
  const snap = readSnap(dir);
  assert.strictEqual(snap.partial, true);
  assert.deepStrictEqual(snap.covered, []);
  assert.strictEqual(snap.pending.length, 4);
  assert.ok(!fs.existsSync(path.join(dir, 'plugin-integrity-state.json')), 'risky notice not consumed by a partial run');

  run({ claudeHome: home, dir, budget: 3, clock: ticker() }); // run's own deadline read uses one tick
  assert.strictEqual(Object.keys(readSnap(dir).plugins).length, 2);
  const r = run({ claudeHome: home, dir, now: 0 });
  assert.strictEqual(r.userMsg, null, 'unknown keys of a partial baseline are not reported as new');
  assert.match(r.claudeContext, /baseline completed for 4 plugins/);
  assert.strictEqual(readSnap(dir).partial, undefined);
});

test('budget exceeded against full baseline: change is kept for the next full run', () => {
  const home = fakeHome();
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'secops-state-'));
  run({ claudeHome: home, dir, now: 0 });
  const base = readSnap(dir);
  put(home, 'plugins/cache/mk/p1/1.0.0/hooks/a.js', 'tampered');
  assert.deepStrictEqual(run({ claudeHome: home, dir, now: 1, budget: 2, clock: ticker() }), { userMsg: null, claudeContext: null });
  assert.deepStrictEqual(readSnap(dir).plugins, base.plugins, 'full baseline not overwritten by partial run');
  const r = run({ claudeHome: home, dir, now: 2 });
  assert.match(r.userMsg, /~ mk\/p1: hooks\/a\.js/);
  assert.doesNotMatch(r.userMsg, /removed/);
});

test('diffSnapshots: partial next reports no removals; partial prev reports no additions', () => {
  const full = { plugins: { a: { files: { x: '1' } }, b: { files: { y: '1' } }, c: { files: {} } } };
  const partial = { partial: true, covered: ['a'], plugins: { a: { files: { x: '2' } } } };
  assert.deepStrictEqual(diffSnapshots(full, partial), { added: [], removed: [], changed: [{ plugin: 'a', files: ['x'] }] });
  assert.deepStrictEqual(diffSnapshots({ ...partial, plugins: { a: { files: { x: '1' } } } }, full), { added: [], removed: [], changed: [] });
});

test('spawn: SECOPS_INTEGRITY_BUDGET_MS=0 prints nothing, writes partial snapshot', () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'secops-state-'));
  const user = fs.mkdtempSync(path.join(os.tmpdir(), 'secops-user-'));
  fs.renameSync(fakeHome(), path.join(user, '.claude'));
  const r = spawnRun({ SECOPS_STATE_DIR: dir, USERPROFILE: user, HOME: user, SECOPS_INTEGRITY_BUDGET_MS: '0' });
  assert.strictEqual(r.status, 0);
  assert.strictEqual(r.stdout, '');
  assert.strictEqual(readSnap(dir).partial, true);
});

test('fresh laptop: missing or empty ~/.claude/plugins records a clean baseline', () => {
  for (const setup of [() => {}, (h) => fs.mkdirSync(path.join(h, 'plugins')), (h) => fs.mkdirSync(path.join(h, 'plugins', 'cache'), { recursive: true })]) {
    const home = fs.mkdtempSync(path.join(os.tmpdir(), 'secops-fresh-'));
    setup(home);
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'secops-state-'));
    assert.deepStrictEqual(run({ claudeHome: home, dir }), { userMsg: null, claudeContext: 'secops-guard: baseline recorded for 0 plugins' });
    assert.deepStrictEqual(readSnap(dir).plugins, {});
    assert.deepStrictEqual(run({ claudeHome: home, dir }), { userMsg: null, claudeContext: null });
  }
});

test('spawn: fresh laptop (no ~/.claude, or empty ~/.claude/plugins) prints baseline, no error', () => {
  for (const setup of [() => {}, (u) => fs.mkdirSync(path.join(u, '.claude', 'plugins'), { recursive: true })]) {
    const user = fs.mkdtempSync(path.join(os.tmpdir(), 'secops-user-'));
    setup(user);
    const dir = path.join(user, 'state');
    const r = spawnRun({ SECOPS_STATE_DIR: dir, USERPROFILE: user, HOME: user });
    assert.strictEqual(r.status, 0);
    assert.strictEqual(r.stderr, '');
    assert.strictEqual(JSON.parse(r.stdout).hookSpecificOutput.additionalContext, 'secops-guard: baseline recorded for 0 plugins');
    assert.deepStrictEqual(readSnap(dir).plugins, {});
  }
});
