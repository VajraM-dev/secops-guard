#!/usr/bin/env node
'use strict';
// PreToolUse (Edit|Write|MultiEdit): dependencies added or re-versioned in package.json, requirements*.txt,
// pyproject.toml or Cargo.toml get the same cooldown + OSV + existence checks as explicit installs.
// Deny only; manifests are never rewritten. Line-based TOML reading on purpose (stdlib only).

const fs = require('node:fs');
const path = require('node:path');
const { parseNpmSpec, parsePep508, poetryToPep440, isNonRegistry } = require('./lib/parse-command');

function kindOf(file) {
  const b = path.basename(String(file)).toLowerCase();
  if (b === 'package.json') return 'npm';
  if (/^requirements[\w.-]*\.(?:txt|in)$/.test(b)) return 'req';
  if (b === 'pyproject.toml') return 'pyproject';
  if (b === 'cargo.toml') return 'cargo';
  return null;
}

function replaceOnce(text, e) {
  const oldS = String(e.old_string ?? '');
  const newS = String(e.new_string ?? '');
  if (!oldS) return text === '' ? newS : null;
  const idx = text.indexOf(oldS);
  if (idx === -1) return null; // the Edit tool will fail on its own
  return e.replace_all ? text.split(oldS).join(newS) : text.slice(0, idx) + newS + text.slice(idx + oldS.length);
}

function newContent(toolName, ti, current) {
  if (toolName === 'Write') return typeof ti.content === 'string' ? ti.content : null;
  if (toolName === 'Edit') return replaceOnce(current, ti);
  if (toolName === 'MultiEdit') {
    let t = current;
    for (const e of Array.isArray(ti.edits) ? ti.edits : []) { t = replaceOnce(t, e); if (t == null) return null; }
    return t;
  }
  return null;
}

// '#' outside quotes starts a TOML/requirements comment
function stripComment(line) {
  let q = null;
  for (let i = 0; i < line.length; i++) {
    const c = line[i];
    if (q) { if (c === q) q = null; } else if (c === '"' || c === "'") q = c; else if (c === '#') return line.slice(0, i);
  }
  return line;
}

// strings outside inline tables ({include-group = "x"} is not a dependency)
function tomlStrings(s) {
  const out = [];
  let braces = 0;
  for (let i = 0; i < s.length; i++) {
    const q = s[i];
    if (q === '{') braces++;
    else if (q === '}') braces--;
    if (q !== '"' && q !== "'") continue;
    const end = s.indexOf(q, i + 1);
    if (end === -1) break;
    if (!braces) out.push(s.slice(i + 1, end));
    i = end;
  }
  return out;
}

function arrayClosed(s) {
  let depth = 0;
  let q = null;
  for (const c of s) {
    if (q) { if (c === q) q = null; continue; }
    if (c === '"' || c === "'") q = c;
    else if (c === '[') depth++;
    else if (c === ']' && --depth === 0) return true;
  }
  return false;
}

const unparsed = (ecosystem, name, spec) => ({ ecosystem, name, spec, unparsed: true });

function pep508Dep(s) {
  const p = parsePep508(s);
  if (p) return { ecosystem: 'pypi', name: p.name, spec: p.spec };
  return isNonRegistry(s) || s.includes('@') ? null : unparsed('pypi', s, '');
}

function npmDeps(text) {
  let j;
  try { j = JSON.parse(text); } catch { return null; }
  const out = [];
  for (const sec of ['dependencies', 'devDependencies', 'optionalDependencies', 'peerDependencies']) {
    const obj = j && j[sec];
    if (!obj || typeof obj !== 'object') continue;
    for (const [name, raw] of Object.entries(obj)) {
      if (typeof raw !== 'string') continue;
      const s = raw.trim();
      if (s.startsWith('npm:')) {
        const p = parseNpmSpec(s.slice(4));
        if (p) out.push({ ecosystem: 'npm', name: p.name, spec: p.spec });
      } else if (!/^[./\\]/.test(s) && !/[:/]/.test(s) && !/\.(?:tgz|tar\.gz)$/i.test(s)) { // not file/git/url/workspace
        out.push({ ecosystem: 'npm', name, spec: s });
      }
    }
  }
  return out;
}

function reqDeps(text) {
  const out = [];
  for (const l of text.split(/\r?\n/)) {
    const line = stripComment(l).trim();
    if (!line || line[0] === '-' || line.endsWith('\\')) continue;
    const dep = pep508Dep(line);
    if (dep) out.push(dep);
  }
  return out;
}

const POETRY_TABLE = /^tool\.poetry\.(?:dependencies|dev-dependencies|group\.[^.]+\.dependencies)$/;

function pyprojectDeps(text) {
  const out = [];
  const lines = text.split(/\r?\n/);
  let table = '';
  for (let i = 0; i < lines.length; i++) {
    const line = stripComment(lines[i]).trim();
    const h = /^\[\[?([^\]]+)\]\]?$/.exec(line);
    if (h) { table = h[1].trim(); continue; }
    const m = /^([\w.\-"']+)\s*=\s*(.*)$/.exec(line);
    if (!m) continue;
    const key = m[1].replace(/["']/g, '');
    const val = m[2];
    const arrays = (table === 'project' && key === 'dependencies') || table === 'project.optional-dependencies' || table === 'dependency-groups';
    if (arrays && val.startsWith('[')) {
      let buf = val;
      while (!arrayClosed(buf) && i + 1 < lines.length) buf += `\n${stripComment(lines[++i])}`;
      for (const s of tomlStrings(buf)) { const dep = pep508Dep(s); if (dep) out.push(dep); }
      continue;
    }
    if (!POETRY_TABLE.test(table) || key.toLowerCase() === 'python') continue;
    let spec;
    if (val[0] === '"' || val[0] === "'") spec = tomlStrings(val)[0];
    else if (val[0] === '{') {
      if (/\b(?:path|git|url)\s*=/.test(val)) continue;
      const vm = /\bversion\s*=\s*["']([^"']*)["']/.exec(val);
      if (!vm) continue;
      spec = vm[1];
    } else { out.push(unparsed('pypi', key, val)); continue; }
    const pep = poetryToPep440(spec);
    out.push(pep === null ? unparsed('pypi', key, spec) : { ecosystem: 'pypi', name: key, spec: pep });
  }
  return out;
}

const CARGO_TABLE = /(?:^|\.)(?:dev-|build-)?dependencies$/;
const CARGO_SUB = /(?:^|\.)(?:dev-|build-)?dependencies\.([\w-]+)$/;

function cargoDeps(text) {
  const out = [];
  let table = '';
  let sub = null; // [dependencies.foo] form
  const flush = () => { if (sub && !sub.skip && sub.spec != null) out.push({ ecosystem: 'crates', name: sub.name, spec: sub.spec }); sub = null; };
  for (const l of text.split(/\r?\n/)) {
    const line = stripComment(l).trim();
    const h = /^\[([^\]]+)\]$/.exec(line);
    if (h) {
      flush();
      table = h[1].trim();
      const s = CARGO_SUB.exec(table);
      if (s) sub = { name: s[1], spec: null, skip: false };
      continue;
    }
    const m = /^([\w\-"']+)\s*=\s*(.*)$/.exec(line);
    if (!m) continue;
    const key = m[1].replace(/["']/g, '');
    const val = m[2];
    if (sub) {
      if (key === 'version') sub.spec = tomlStrings(val)[0] ?? null;
      else if (key === 'package') sub.name = tomlStrings(val)[0] || sub.name;
      else if (['path', 'git', 'workspace'].includes(key)) sub.skip = true;
      continue;
    }
    if (!CARGO_TABLE.test(table)) continue;
    if (val[0] === '"' || val[0] === "'") { out.push({ ecosystem: 'crates', name: key, spec: tomlStrings(val)[0] }); continue; }
    if (val[0] !== '{' || /\b(?:path|git|workspace)\s*=/.test(val)) continue;
    const vm = /\bversion\s*=\s*["']([^"']*)["']/.exec(val);
    const pm = /\bpackage\s*=\s*["']([^"']*)["']/.exec(val);
    if (vm) out.push({ ecosystem: 'crates', name: pm ? pm[1] : key, spec: vm[1] });
  }
  flush();
  return out;
}

const EXTRACT = { npm: npmDeps, req: reqDeps, pyproject: pyprojectDeps, cargo: cargoDeps };
const depKey = (x) => `${x.ecosystem}|${x.ecosystem === 'pypi' ? x.name.toLowerCase().replace(/[-_.]+/g, '-') : x.name}|${x.spec}`;

// deps present in `next` that are new or carry a different spec than in `current`
function changedDeps(kind, current, next) {
  const after = EXTRACT[kind](next);
  if (!after) return null;
  const before = new Set((EXTRACT[kind](current) || []).map(depKey));
  const seen = new Set();
  return after.filter((x) => { const k = depKey(x); if (before.has(k) || seen.has(k)) return false; seen.add(k); return true; });
}

async function decide(payload, deps = {}) {
  const ti = (payload && payload.tool_input) || {};
  const kind = kindOf(ti.file_path || '');
  if (!kind) return null;
  const file = path.resolve(payload.cwd || process.cwd(), ti.file_path);
  let current = '';
  try { current = fs.readFileSync(file, 'utf8'); } catch { /* new file */ }
  const next = newContent(payload.tool_name, ti, current);
  if (next == null) return null;
  const changed = changedDeps(kind, current, next);
  if (!changed || !changed.length) return null;

  const { checkPackages, withDeps } = require('./dep-gate');
  const d = withDeps(deps);
  const cfg = d.loadConfig();
  const base = path.basename(file);
  const notes = [];
  const items = [];
  for (const x of changed) {
    const tag = x.ecosystem === 'npm' && /^[a-z][\w.-]*$/i.test(x.spec); // dist-tag
    if (x.unparsed || (x.spec && !tag && d.satisfies(x.ecosystem, '0.0.0', x.spec) === null)) {
      notes.push(`secops-guard: could not check ${x.name} "${x.spec}" in ${base} (unsupported version spec). Prefer an exact or simple range spec so it can be verified.`);
    } else items.push(x);
  }
  const deny = [];
  for (const r of items.length ? await checkPackages(items, cfg, d) : []) {
    if (r.deny) deny.push(`${r.deny} (dependency added in ${base}; change it there before writing.)`);
    if (r.note) notes.push(r.note);
  }
  if (deny.length) return { decision: 'deny', reason: deny.join('\n') };
  return notes.length ? { decision: 'context', context: notes.join('\n') } : null;
}

function main() {
  if (process.env.SECOPS_DISABLE === '1') return;
  let payload;
  try { payload = JSON.parse(fs.readFileSync(0, 'utf8')); } catch { return; }
  if (!payload || !['Edit', 'Write', 'MultiEdit'].includes(payload.tool_name)) return;
  if (!kindOf((payload.tool_input || {}).file_path || '')) return;
  decide(payload).then((res) => {
    if (!res) return;
    const io = require('./lib/io');
    if (res.decision === 'deny') io.preDeny(res.reason);
    else io.preContext(res.context);
  }).catch((e) => {
    process.stderr.write(`secops-guard: manifest-gate error ${e && e.message}\n`);
  }).finally(() => process.stdout.write('', () => process.exit(0)));
}

module.exports = { decide, changedDeps, newContent, kindOf, npmDeps, reqDeps, pyprojectDeps, cargoDeps };
if (require.main === module) main();
