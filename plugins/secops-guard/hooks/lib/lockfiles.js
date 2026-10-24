'use strict';
// Lockfile/manifest -> [{ecosystem, name, version}]. Line-based parsers on purpose: no YAML/TOML deps.
// Only registry packages with concrete versions are returned (git/path/workspace entries are skipped).
// Read and JSON errors throw so callers can tell "unreadable" from "empty".

const fs = require('node:fs');
const path = require('node:path');

const FIXED = { npm: ['package-lock.json', 'npm-shrinkwrap.json', 'pnpm-lock.yaml', 'yarn.lock', 'bun.lock'], pypi: ['uv.lock', 'poetry.lock', 'Pipfile.lock'], crates: ['Cargo.lock'] };
const REQ_RE = /^requirements[\w.-]*\.txt$/i;
const SEMVERISH = /^\d+\.\d+\.\d+[0-9A-Za-z.+-]*$/;
const pep503 = (n) => n.toLowerCase().replace(/[-_.]+/g, '-');
const unquote = (s) => s.trim().replace(/^["']|["']$/g, '');

function findLockfiles(cwd, ecosystem) {
  let entries;
  try { entries = fs.readdirSync(cwd); } catch { return []; }
  const ecos = ecosystem ? [ecosystem] : Object.keys(FIXED);
  const out = [];
  for (const eco of ecos) {
    for (const f of FIXED[eco] || []) if (entries.includes(f)) out.push(path.join(cwd, f));
    if (eco === 'pypi') for (const f of entries.filter((e) => REQ_RE.test(e)).sort()) out.push(path.join(cwd, f));
  }
  return out.filter((p) => { try { return fs.statSync(p).isFile(); } catch { return false; } });
}

// "@scope/name@1.2.3" -> ["@scope/name", "1.2.3"]; '@' at index 0 is a scope.
function splitAt(s) {
  const i = s.lastIndexOf('@');
  return i > 0 ? [s.slice(0, i), s.slice(i + 1)] : null;
}

function packageLock(text) {
  const doc = JSON.parse(text);
  const out = [];
  if (doc.packages && typeof doc.packages === 'object') {
    for (const [key, e] of Object.entries(doc.packages)) {
      const at = key.lastIndexOf('node_modules/');
      if (!key || at === -1 || !e || e.link) continue;
      out.push(['npm', e.name || key.slice(at + 'node_modules/'.length), e.version]);
    }
    return out;
  }
  const walk = (deps) => {
    for (const [name, e] of Object.entries(deps || {})) {
      if (!e || typeof e !== 'object') continue;
      let [n, v] = [name, e.version];
      if (typeof v === 'string' && v.startsWith('npm:')) [n, v] = splitAt(v.slice(4)) || [n, v]; // alias
      out.push(['npm', n, v]);
      walk(e.dependencies);
    }
  };
  walk(doc.dependencies);
  return out;
}

function pnpmLock(text) {
  const out = [];
  let section = '';
  for (const line of text.split(/\r?\n/)) {
    if (/^\S/.test(line)) { section = line.replace(/:.*$/, ''); continue; }
    if (section !== 'packages' && section !== 'snapshots') continue;
    const m = /^ {2}(\S[^ ]*):(?: |$)/.exec(line); // v9 snapshots may read "  ms@2.1.3: {}"
    if (!m) continue;
    let key = unquote(m[1]).replace(/^\//, '');
    const paren = key.indexOf('(');
    if (paren !== -1) key = key.slice(0, paren); // peer-dependency suffix
    const nv = splitAt(key);
    if (nv) out.push(['npm', nv[0], nv[1]]);
  }
  return out;
}

function yarnLock(text) {
  const out = [];
  let cur = null;
  const flush = () => {
    if (!cur) return;
    if (cur.resolution) {
      const i = cur.resolution.lastIndexOf('@npm:');
      if (i > 0) out.push(['npm', cur.resolution.slice(0, i), cur.resolution.slice(i + 5)]);
    } else if (cur.version) {
      // first selector: name@range | name@npm:range | alias@npm:real@range
      const sel = unquote(cur.key.split(',')[0]);
      const at = sel.indexOf('@', 1);
      if (at > 0) {
        let name = sel.slice(0, at);
        const rest = sel.slice(at + 1);
        if (rest.startsWith('npm:')) { const real = splitAt(rest.slice(4)); if (real) name = real[0]; } else if (/^[a-z+]+:/i.test(rest)) name = null; // git:, file:, workspace:…
        if (name) out.push(['npm', name, cur.version]);
      }
    }
    cur = null;
  };
  for (const line of text.split(/\r?\n/)) {
    if (!line.trim() || line.startsWith('#')) continue;
    if (/^\S/.test(line)) {
      flush();
      if (line.endsWith(':') && !line.startsWith('__metadata')) cur = { key: line.slice(0, -1) };
      continue;
    }
    if (!cur) continue;
    const v = /^ {2}version:?\s+"?([^"\s]+)"?\s*$/.exec(line);
    if (v) cur.version = v[1];
    const r = /^ {2}resolution:\s+"?([^"]+)"?\s*$/.exec(line);
    if (r) cur.resolution = r[1];
  }
  flush();
  return out;
}

function bunLock(text) {
  const out = [];
  let inPackages = false;
  for (const line of text.split(/\r?\n/)) {
    if (/^\s*"packages"\s*:\s*\{/.test(line)) { inPackages = true; continue; }
    if (!inPackages) continue;
    if (/^ {2}\}/.test(line)) break;
    const m = /^\s*"[^"]+"\s*:\s*\[\s*"([^"]+)"/.exec(line);
    const nv = m && splitAt(m[1]);
    if (nv) out.push(['npm', nv[0], nv[1]]);
  }
  return out;
}

function requirements(text) {
  const out = [];
  for (let line of text.split(/\r?\n/)) {
    line = line.replace(/(^|\s)#.*$/, '').split(';')[0].replace(/\s--\S.*$/, '').replace(/\\\s*$/, '').trim();
    if (!line || line.startsWith('-')) continue;
    const m = /^([A-Za-z0-9][A-Za-z0-9._-]*)\s*(?:\[[^\]]*\])?\s*===?\s*([A-Za-z0-9!+._-]+)$/.exec(line);
    if (m) out.push(['pypi', pep503(m[1]), m[2]]);
  }
  return out;
}

// TOML [[package]] blocks: name/version/source at block top level; subtable keys are ignored
// (a poetry [package.dependencies] entry named "version" must not clobber the real one).
function tomlPackages(text, eco, keep) {
  const out = [];
  let cur = null;
  let sub = null;
  const flush = () => { if (cur && cur.name && cur.version && keep(cur)) out.push([eco, eco === 'pypi' ? pep503(cur.name) : cur.name, cur.version]); };
  for (const line of text.split(/\r?\n/)) {
    if (/^\[\[package\]\]\s*$/.test(line)) { flush(); cur = {}; sub = null; continue; }
    if (/^\[/.test(line)) { sub = line.trim(); if (!sub.startsWith('[package.')) { flush(); cur = null; } continue; }
    if (!cur) continue;
    const m = /^([A-Za-z_-]+)\s*=\s*(.+)$/.exec(line);
    if (!m) continue;
    if (!sub && ['name', 'version', 'source'].includes(m[1])) cur[m[1]] = m[1] === 'source' ? m[2].trim() : unquote(m[2]);
    if (sub === '[package.source]' && m[1] === 'type') cur.sourceType = unquote(m[2]);
  }
  flush();
  return out;
}

function pipfileLock(text) {
  const doc = JSON.parse(text);
  const out = [];
  for (const sect of ['default', 'develop']) {
    for (const [name, e] of Object.entries(doc[sect] || {})) {
      const m = e && typeof e.version === 'string' && /^===?\s*(\S+)$/.exec(e.version);
      if (m) out.push(['pypi', pep503(name), m[1]]);
    }
  }
  return out;
}

const PARSERS = {
  'package-lock.json': packageLock,
  'npm-shrinkwrap.json': packageLock,
  'pnpm-lock.yaml': pnpmLock,
  'yarn.lock': yarnLock,
  'bun.lock': bunLock,
  'uv.lock': (t) => tomlPackages(t, 'pypi', (p) => !p.source || p.source.includes('registry')),
  'poetry.lock': (t) => tomlPackages(t, 'pypi', (p) => !['git', 'directory', 'file', 'url'].includes(p.sourceType)),
  'Pipfile.lock': pipfileLock,
  'Cargo.lock': (t) => tomlPackages(t, 'crates', (p) => !!p.source && unquote(p.source).startsWith('registry+')),
};

function parseLockfile(file) {
  const base = path.basename(file);
  const parser = PARSERS[base] || (REQ_RE.test(base) ? requirements : null);
  if (!parser) return [];
  const text = fs.readFileSync(file, 'utf8').replace(/^\uFEFF/, '');
  const seen = new Map();
  for (const [ecosystem, name, version] of parser(text)) {
    if (typeof name !== 'string' || !name || typeof version !== 'string') continue;
    if (ecosystem !== 'pypi' && !SEMVERISH.test(version)) continue; // file:, link:, git urls, tarballs
    if (ecosystem === 'pypi' && !/^\d/.test(version)) continue;
    seen.set(`${ecosystem}:${name}@${version}`, { ecosystem, name, version });
  }
  return [...seen.values()];
}

module.exports = { findLockfiles, parseLockfile };
