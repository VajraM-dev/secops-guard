#!/usr/bin/env node
'use strict';
// SessionStart hook: fingerprint installed plugins + user hooks, report what changed since last session.
// Strictly read-only against ~/.claude/plugins and ~/.claude/hooks; only writes its own files in STATE_DIR.
// Never throws: any error means no output (fail quiet, the session must start).

const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const crypto = require('node:crypto');

const MAX_FILE = 2 * 1024 * 1024;
const SKIP_DIRS = new Set(['node_modules', '.git']);
const CODE_EXT = /\.(?:js|cjs|mjs|py|sh|ps1|cmd)$/i;
const CODE_DIRS = /^(?:hooks|scripts|bin)\//;
const NAMED = new Set(['plugin.json', 'settings.json', '.mcp.json']);
const DAY_MS = 24 * 60 * 60 * 1000;
const MAX_LINES = 10;
const DEFAULT_BUDGET_MS = 10000;

function budgetMs() {
  const v = Number(process.env.SECOPS_INTEGRITY_BUDGET_MS);
  return process.env.SECOPS_INTEGRITY_BUDGET_MS && Number.isFinite(v) && v >= 0 ? v : DEFAULT_BUDGET_MS;
}

const defaultHome = () => path.join(os.homedir(), '.claude');
const stateDir = () => process.env.SECOPS_STATE_DIR || path.join(os.homedir(), '.claude', 'secops-guard');

const readJson = (p) => { try { return JSON.parse(fs.readFileSync(p, 'utf8')); } catch { return null; } };
const isDir = (p) => { try { return fs.statSync(p).isDirectory(); } catch { return false; } };
const listDirs = (p) => { try { return fs.readdirSync(p, { withFileTypes: true }).filter((d) => d.isDirectory()).map((d) => d.name); } catch { return []; } };
const sha256 = (buf) => crypto.createHash('sha256').update(buf).digest('hex');

// Symlinks are not followed so a plugin cannot point the walk outside its root.
function hashTree(root, include) {
  const files = {};
  const walk = (dir, rel) => {
    let ents;
    try { ents = fs.readdirSync(dir, { withFileTypes: true }); } catch { return; }
    for (const e of ents) {
      const r = rel ? `${rel}/${e.name}` : e.name;
      const full = path.join(dir, e.name);
      if (e.isDirectory()) { if (!SKIP_DIRS.has(e.name)) walk(full, r); continue; }
      if (!e.isFile() || !include(r, e.name)) continue;
      try {
        if (fs.statSync(full).size > MAX_FILE) continue;
        files[r] = sha256(fs.readFileSync(full));
      } catch { /* unreadable file: skip */ }
    }
  };
  walk(root, '');
  return files;
}

const pluginInclude = (rel, name) => CODE_DIRS.test(rel) || CODE_EXT.test(name) || NAMED.has(name);

function pluginEntry(root) {
  const manifest = readJson(path.join(root, '.claude-plugin', 'plugin.json')) || {};
  const hooksFile = readJson(path.join(root, 'hooks', 'hooks.json'));
  const mcpFile = readJson(path.join(root, '.mcp.json'));
  return {
    root,
    files: hashTree(root, pluginInclude),
    hooks: hooksFile || (manifest.hooks && typeof manifest.hooks === 'object' ? manifest.hooks : null),
    mcp: mcpFile || (manifest.mcpServers && typeof manifest.mcpServers === 'object' ? manifest.mcpServers : null),
  };
}

function newestDir(base) {
  let best = null, bestMtime = -1;
  for (const v of listDirs(base)) {
    try {
      const m = fs.statSync(path.join(base, v)).mtimeMs;
      if (m > bestMtime) { bestMtime = m; best = path.join(base, v); }
    } catch { /* skip */ }
  }
  return best;
}

// Marketplace clone layouts: the root is the plugin (source "./") or plugins/<name>.
function marketplaceDir(home, mkt, plugin) {
  const root = path.join(home, 'plugins', 'marketplaces', mkt);
  const sub = path.join(root, 'plugins', plugin);
  if (isDir(sub)) return sub;
  const own = readJson(path.join(root, '.claude-plugin', 'plugin.json'));
  return own && (own.name || mkt) === plugin ? root : null;
}

// Only the active install is hashed (installPath in installed_plugins.json), so stale cached
// versions and whole marketplace monorepos stay out of the walk. Fallbacks: newest cache dir, then the clone.
// opts.deadline/clock bound wall time; checked between plugins so no plugin is half-hashed.
// opts.first lists keys to hash before the rest (what a previous partial run did not reach).
function snapshotPlugins(claudeHome = defaultHome(), opts = {}) {
  const clock = opts.clock || Date.now;
  const deadline = opts.deadline == null ? Infinity : opts.deadline;
  const cache = path.join(claudeHome, 'plugins', 'cache');
  const installed = (readJson(path.join(claudeHome, 'plugins', 'installed_plugins.json')) || {}).plugins || {};
  const ids = new Set(Object.keys(installed));
  // cache dirs with no installed record still run if referenced, so they are tracked too
  for (const mkt of listDirs(cache)) for (const p of listDirs(path.join(cache, mkt))) ids.add(`${p}@${mkt}`);
  const tasks = [];
  for (const id of ids) {
    const at = id.lastIndexOf('@');
    if (at <= 0) continue;
    const plugin = id.slice(0, at), mkt = id.slice(at + 1);
    const recs = installed[id];
    const p = Array.isArray(recs) && recs[0] && recs[0].installPath;
    const dir = (typeof p === 'string' && isDir(p) && p) || newestDir(path.join(cache, mkt, plugin)) || marketplaceDir(claudeHome, mkt, plugin);
    if (dir) tasks.push([`${mkt}/${plugin}`, () => pluginEntry(dir)]);
  }
  tasks.push(['user/hooks', () => {
    const settings = readJson(path.join(claudeHome, 'settings.json')) || {};
    const userHooks = settings.hooks && typeof settings.hooks === 'object' ? settings.hooks : null;
    const files = {};
    const hooksDir = path.join(claudeHome, 'hooks');
    if (isDir(hooksDir)) for (const [r, h] of Object.entries(hashTree(hooksDir, () => true))) files[`hooks/${r}`] = h;
    if (userHooks) files['settings.json#hooks'] = sha256(JSON.stringify(userHooks));
    return Object.keys(files).length ? { root: claudeHome, files, hooks: userHooks, mcp: null } : null;
  }]);
  const first = new Set(opts.first || []);
  tasks.sort((x, y) => Number(first.has(y[0])) - Number(first.has(x[0])));

  const plugins = {};
  const covered = [];
  for (const [key, fn] of tasks) {
    if (clock() >= deadline) {
      return { takenAt: new Date().toISOString(), plugins, partial: true, covered, pending: tasks.slice(covered.length).map((t) => t[0]) };
    }
    const entry = fn();
    if (entry) plugins[key] = entry;
    covered.push(key);
  }
  return { takenAt: new Date().toISOString(), plugins };
}

// A partial snapshot only speaks for the keys it covered: absent keys are unknown, not removed,
// and a partial prev cannot prove a key is new.
function diffSnapshots(prev, next) {
  const a = (prev && prev.plugins) || {};
  const b = (next && next.plugins) || {};
  const nextPartial = Boolean(next && next.partial);
  const prevPartial = Boolean(prev && prev.partial);
  const added = prevPartial ? [] : Object.keys(b).filter((k) => !(k in a)).sort();
  const removed = nextPartial ? [] : Object.keys(a).filter((k) => !(k in b)).sort();
  const changed = [];
  for (const k of Object.keys(b).sort()) {
    if (!(k in a)) continue;
    const fa = a[k].files || {}, fb = b[k].files || {};
    const files = [...new Set([...Object.keys(fa), ...Object.keys(fb)])].filter((f) => fa[f] !== fb[f]).sort();
    if (files.length) changed.push({ plugin: k, files });
  }
  return { added, removed, changed };
}

function riskyMarketplaces(settings) {
  const mk = settings && settings.extraKnownMarketplaces;
  if (!mk || typeof mk !== 'object') return [];
  return Object.entries(mk)
    .filter(([, v]) => v && v.autoUpdate === true)
    .map(([name, v]) => {
      const s = v.source || {};
      return { name, repo: s.repo || s.url || s.path || null, autoUpdate: true };
    });
}

function summaryLines(diff) {
  const lines = [
    ...diff.added.map((k) => `+ ${k} (new)`),
    ...diff.removed.map((k) => `- ${k} (removed)`),
    ...diff.changed.map((c) => `~ ${c.plugin}: ${c.files.slice(0, 5).join(', ')}${c.files.length > 5 ? ` (+${c.files.length - 5} more)` : ''}`),
  ];
  if (lines.length <= MAX_LINES) return lines;
  return [...lines.slice(0, MAX_LINES - 1), `... and ${lines.length - MAX_LINES + 1} more`];
}

function emit(userMsg, claudeContext) {
  try {
    require('./lib/io.js').sessionMessage(userMsg, claudeContext);
  } catch {
    process.stdout.write(JSON.stringify({
      ...(userMsg ? { systemMessage: userMsg } : {}),
      ...(claudeContext ? { hookSpecificOutput: { hookEventName: 'SessionStart', additionalContext: claudeContext } } : {}),
    }));
  }
}

// Returns {userMsg, claudeContext} (either may be null); pure apart from state-file IO. Exposed for tests.
function run({ claudeHome = defaultHome(), dir = stateDir(), now = Date.now(), budget = budgetMs(), clock = Date.now } = {}) {
  const snapFile = path.join(dir, 'plugin-snapshot.json');
  const stateFile = path.join(dir, 'plugin-integrity-state.json');
  const prev = readJson(snapFile);
  const hasPrev = Boolean(prev && prev.plugins);
  const next = snapshotPlugins(claudeHome, { deadline: clock() + budget, clock, first: hasPrev && prev.pending });
  fs.mkdirSync(dir, { recursive: true });

  if (next.partial) {
    // Out of time: stay silent. Against a full baseline keep it as-is (so changes seen now are still
    // reported by the next full run); an incomplete baseline is extended with what was hashed.
    // Known, accepted gap: a plugin installed while the baseline is still incomplete is absorbed into it
    // and never reported as new (diffSnapshots cannot tell it from a plugin the baseline had not reached).
    const baseIncomplete = !hasPrev || prev.partial;
    const plugins = baseIncomplete ? { ...next.plugins, ...(hasPrev ? prev.plugins : {}) } : prev.plugins;
    fs.writeFileSync(snapFile, JSON.stringify({
      takenAt: hasPrev ? prev.takenAt : next.takenAt, plugins, partial: baseIncomplete, covered: next.covered, pending: next.pending,
    }));
    return { userMsg: null, claudeContext: null };
  }
  fs.writeFileSync(snapFile, JSON.stringify(next));

  const settings = readJson(path.join(claudeHome, 'settings.json')) || {};
  const known = readJson(path.join(claudeHome, 'plugins', 'known_marketplaces.json')) || {};
  const risky = riskyMarketplaces({ extraKnownMarketplaces: { ...known, ...(settings.extraKnownMarketplaces || {}) } });
  const state = readJson(stateFile) || {};
  const riskyDue = risky.length > 0 && !(now - (state.riskyNoticeAt || 0) < DAY_MS);
  if (riskyDue) fs.writeFileSync(stateFile, JSON.stringify({ ...state, riskyNoticeAt: now }));
  const riskyLine = riskyDue
    ? `secops-guard: marketplaces with autoUpdate on (code changes without review): ${risky.map((r) => r.name).join(', ')}.`
    : null;

  if (!prev || !prev.plugins) {
    const n = Object.keys(next.plugins).length;
    return { userMsg: null, claudeContext: [`secops-guard: baseline recorded for ${n} plugins`, riskyLine].filter(Boolean).join('\n') };
  }
  const diff = diffSnapshots(prev, next);
  const lines = summaryLines(diff);
  if (!lines.length && !riskyLine) {
    const done = prev.partial ? `secops-guard: baseline completed for ${Object.keys(next.plugins).length} plugins` : null;
    return { userMsg: null, claudeContext: done };
  }
  const parts = [];
  if (lines.length) parts.push('secops-guard: plugin code changed since last session:', ...lines.map((l) => `  ${l}`));
  if (riskyLine) parts.push(riskyLine);
  const userMsg = parts.join('\n');
  const claudeContext = `${userMsg}\nRecommend the user run the /secops-guard:plugin-audit skill to review ${lines.length ? 'these changes' : 'auto-updating marketplaces'}.`;
  return { userMsg, claudeContext };
}

function main() {
  try {
    if (process.env.SECOPS_DISABLE === '1') return;
    const { userMsg, claudeContext } = run();
    if (userMsg || claudeContext) emit(userMsg, claudeContext);
  } catch {
    // any error -> no output; never block session start
  }
}

module.exports = { snapshotPlugins, diffSnapshots, riskyMarketplaces, run };
if (require.main === module) main();
