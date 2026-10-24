'use strict';
// dep-audit: lockfiles -> OSV, cooldown check on direct deps, floating Docker bases, unpinned GitHub Actions.
// Usage: node audit.js --cwd <dir> [--json] [--recursive]. Always exits 0.

const fs = require('node:fs');
const path = require('node:path');

const LIB = path.join(__dirname, '../../../hooks/lib');
const SKIP_DIRS = new Set(['node_modules', '.venv', 'venv', 'target', '.git', 'dist', 'build', '__pycache__', '.tox', '.next']);
const SEV_ORDER = ['MALICIOUS', 'CRITICAL', 'HIGH', 'MODERATE', 'LOW'];
const MANIFESTS = ['package.json', 'pyproject.toml', 'Cargo.toml', 'Pipfile'];
const MAX_DEPTH = 4;
const DAY = 86400000;

function loadDeps() {
  const deps = { errors: [] };
  const want = { lockfiles: ['findLockfiles', 'parseLockfile'], osv: ['queryPackages'], registries: ['getPackageVersions'], config: ['loadConfig'] };
  for (const [mod, fns] of Object.entries(want)) {
    try {
      const m = require(path.join(LIB, `${mod}.js`));
      for (const f of fns) if (typeof m[f] === 'function') deps[f] = m[f];
    } catch (e) {
      deps.errors.push(`lib/${mod}.js unavailable: ${e.message.split('\n')[0]}`);
    }
  }
  return deps;
}

const rel = (cwd, p) => path.relative(cwd, p).replace(/\\/g, '/') || '.';

function walkDirs(root, recursive) {
  const out = [root];
  if (!recursive) return out;
  const visit = (dir, depth) => {
    if (depth >= MAX_DEPTH) return;
    let ents = [];
    try { ents = fs.readdirSync(dir, { withFileTypes: true }); } catch { return; }
    for (const e of ents) {
      if (!e.isDirectory() || SKIP_DIRS.has(e.name) || e.name.startsWith('.')) continue;
      const p = path.join(dir, e.name);
      out.push(p);
      visit(p, depth + 1);
    }
  };
  visit(root, 0);
  return out;
}

function readText(p) {
  try { return fs.readFileSync(p, 'utf8'); } catch { return null; }
}

function listFiles(dir) {
  try { return fs.readdirSync(dir, { withFileTypes: true }).filter((e) => e.isFile()).map((e) => e.name); } catch { return []; }
}

// --- Dockerfile: FROM without tag/digest, or :latest ---
function dockerFloating(text) {
  const out = [];
  const stages = new Set();
  text.split(/\r?\n/).forEach((raw, i) => {
    const m = /^\s*FROM\s+(.+)$/i.exec(raw);
    if (!m) return;
    const toks = m[1].trim().split(/\s+/).filter((t) => !t.startsWith('--'));
    const image = toks[0];
    if (!image) return;
    if (toks.length >= 3 && toks[1].toLowerCase() === 'as') stages.add(toks[2].toLowerCase());
    if (image.toLowerCase() === 'scratch' || stages.has(image.toLowerCase()) || image.includes('$')) return;
    if (image.includes('@sha256:')) return;
    const lastSeg = image.slice(image.lastIndexOf('/') + 1);
    const tag = lastSeg.includes(':') ? lastSeg.slice(lastSeg.indexOf(':') + 1) : '';
    if (!tag) out.push({ line: i + 1, image, reason: 'no tag (implicit :latest)' });
    else if (tag === 'latest') out.push({ line: i + 1, image, reason: ':latest tag' });
  });
  return out;
}

// --- GitHub Actions: uses: owner/repo@ref where ref is not a 40-char SHA ---
function actionsUnpinned(text) {
  const out = [];
  text.split(/\r?\n/).forEach((raw, i) => {
    const m = /^\s*(?:-\s*)?uses:\s*['"]?([^\s'"#]+)/.exec(raw);
    if (!m) return;
    const uses = m[1];
    if (uses.startsWith('./')) return;
    if (uses.startsWith('docker://')) {
      if (!uses.includes('@sha256:')) out.push({ line: i + 1, uses, reason: 'docker action without digest' });
      return;
    }
    const at = uses.lastIndexOf('@');
    const ref = at === -1 ? '' : uses.slice(at + 1);
    if (!/^[0-9a-f]{40}$/i.test(ref)) out.push({ line: i + 1, uses, reason: ref ? `ref "${ref}" is mutable` : 'no ref' });
  });
  return out;
}

// --- direct deps from manifests (names only; versions come from the lockfile) ---
const pepName = (s) => {
  const m = /^\s*([A-Za-z0-9][A-Za-z0-9._-]*)/.exec(s);
  return m ? m[1] : null;
};

function tomlSections(text) {
  const out = {};
  let cur = '';
  for (const line of text.split(/\r?\n/)) {
    const h = /^\s*\[([^\]]+)\]\s*$/.exec(line);
    if (h) { cur = h[1].trim(); out[cur] = out[cur] || []; continue; }
    (out[cur] = out[cur] || []).push(line);
  }
  return out;
}

function directDeps(file, text) {
  const base = path.basename(file);
  const deps = [];
  try {
    if (base === 'package.json') {
      const j = JSON.parse(text);
      for (const k of ['dependencies', 'devDependencies', 'optionalDependencies']) {
        for (const name of Object.keys(j[k] || {})) deps.push({ ecosystem: 'npm', name });
      }
    } else if (base === 'pyproject.toml') {
      const secs = tomlSections(text);
      const proj = (secs.project || []).join('\n');
      const arr = /(?:^|\n)\s*dependencies\s*=\s*\[([^\]]*)\]/.exec(proj);
      if (arr) {
        for (const q of arr[1].split(',')) {
          const s = q.trim().replace(/^['"]|['"]$/g, '');
          const n = s && pepName(s);
          if (n) deps.push({ ecosystem: 'pypi', name: n });
        }
      }
      for (const sec of ['tool.poetry.dependencies', 'tool.poetry.dev-dependencies', 'tool.poetry.group.dev.dependencies']) {
        for (const line of secs[sec] || []) {
          const m = /^\s*([A-Za-z0-9][A-Za-z0-9._-]*)\s*=/.exec(line);
          if (m && m[1].toLowerCase() !== 'python') deps.push({ ecosystem: 'pypi', name: m[1] });
        }
      }
    } else if (base === 'Pipfile') {
      const secs = tomlSections(text);
      for (const sec of ['packages', 'dev-packages']) {
        for (const line of secs[sec] || []) {
          const m = /^\s*"?([A-Za-z0-9][A-Za-z0-9._-]*)"?\s*=/.exec(line);
          if (m) deps.push({ ecosystem: 'pypi', name: m[1] });
        }
      }
    } else if (base === 'Cargo.toml') {
      const secs = tomlSections(text);
      for (const [sec, lines] of Object.entries(secs)) {
        const t = /^(?:target\.[^\]]+\.)?(dependencies|dev-dependencies|build-dependencies)(?:\.([A-Za-z0-9_-]+))?$/.exec(sec);
        if (!t) continue;
        if (t[2]) { deps.push({ ecosystem: 'crates', name: t[2] }); continue; }
        for (const line of lines) {
          const m = /^\s*([A-Za-z0-9_-]+)\s*=/.exec(line);
          if (m) deps.push({ ecosystem: 'crates', name: m[1] });
        }
      }
    }
  } catch { /* malformed manifest: no direct deps */ }
  return deps;
}

function hasLockfile(dir, eco, deps) {
  if (!deps.findLockfiles) return true; // cannot tell; do not report
  try { return deps.findLockfiles(dir, eco).length > 0; } catch { return true; }
}

function isWorkspaceRoot(dir, eco) {
  if (eco === 'npm') {
    if (fs.existsSync(path.join(dir, 'pnpm-workspace.yaml'))) return true;
    try { return !!JSON.parse(readText(path.join(dir, 'package.json')) || '{}').workspaces; } catch { return false; }
  }
  if (eco === 'crates') return /^\s*\[workspace\]/m.test(readText(path.join(dir, 'Cargo.toml')) || '');
  if (eco === 'pypi') return /^\s*\[tool\.uv\.workspace\]/m.test(readText(path.join(dir, 'pyproject.toml')) || '');
  return false;
}

// Workspace members share the root lockfile: walk up to the nearest lockfile or workspace marker, stopping at the repo root.
function coveredByAncestor(dir, eco, deps) {
  let cur = dir;
  for (let i = 0; i < 12; i++) {
    if (fs.existsSync(path.join(cur, '.git'))) return false;
    const up = path.dirname(cur);
    if (up === cur) return false;
    cur = up;
    if (hasLockfile(cur, eco, deps) || isWorkspaceRoot(cur, eco)) return true;
  }
  return false;
}

const normKey = (eco, name) => `${eco}:${eco === 'pypi' ? name.toLowerCase().replace(/[-_.]+/g, '-') : eco === 'crates' ? name.toLowerCase().replace(/_/g, '-') : name}`;

async function mapLimit(items, limit, fn) {
  const out = new Array(items.length);
  let i = 0;
  const worker = async () => { while (i < items.length) { const k = i++; out[k] = await fn(items[k]); } };
  await Promise.all(Array.from({ length: Math.min(limit, items.length) }, worker));
  return out;
}

async function audit(opts, deps) {
  const cwd = path.resolve(opts.cwd || process.cwd());
  const now = deps.now || Date.now();
  const res = { cwd, lockfiles: [], vulns: [], tooNew: [], missingLockfiles: [], docker: [], actions: [], errors: [...(deps.errors || [])], cooldownDays: 7 };
  let cfg = null;
  try { if (deps.loadConfig) cfg = deps.loadConfig(); } catch (e) { res.errors.push(`config: ${e.message}`); }
  if (cfg && Number.isFinite(cfg.cooldownDays)) res.cooldownDays = cfg.cooldownDays;

  const pkgs = new Map(); // key eco:name@ver -> {ecosystem,name,version,lockfiles:Set}
  const lockedVersions = new Map(); // normKey -> Set(version)
  const directs = new Map(); // normKey -> {ecosystem,name}

  for (const dir of walkDirs(cwd, opts.recursive)) {
    const names = listFiles(dir);
    let locks = [];
    if (deps.findLockfiles) {
      try { locks = deps.findLockfiles(dir) || []; } catch (e) { res.errors.push(`findLockfiles ${rel(cwd, dir)}: ${e.message}`); }
    }
    locks = locks.map((p) => path.resolve(dir, p));
    for (const lf of locks) {
      if (res.lockfiles.includes(rel(cwd, lf))) continue;
      res.lockfiles.push(rel(cwd, lf));
      let parsed = [];
      try { parsed = deps.parseLockfile(lf) || []; } catch (e) { res.errors.push(`parse ${rel(cwd, lf)}: ${e.message}`); }
      for (const p of parsed) {
        if (!p || !p.name || !p.version) continue;
        const key = `${p.ecosystem}:${p.name}@${p.version}`;
        if (!pkgs.has(key)) pkgs.set(key, { ecosystem: p.ecosystem, name: p.name, version: p.version, lockfiles: new Set() });
        pkgs.get(key).lockfiles.add(rel(cwd, lf));
        const nk = normKey(p.ecosystem, p.name);
        if (!lockedVersions.has(nk)) lockedVersions.set(nk, new Set());
        lockedVersions.get(nk).add(p.version);
      }
    }
    for (const m of names.filter((n) => MANIFESTS.includes(n))) {
      const text = readText(path.join(dir, m));
      if (text == null) continue;
      const dd = directDeps(m, text);
      for (const d of dd) directs.set(normKey(d.ecosystem, d.name), d);
      if (dd.length && !hasLockfile(dir, dd[0].ecosystem, deps) && !coveredByAncestor(dir, dd[0].ecosystem, deps)) {
        res.missingLockfiles.push(rel(cwd, path.join(dir, m)));
      }
    }
    for (const n of names.filter((x) => /^Dockerfile|\.Dockerfile$|^Containerfile/i.test(x))) {
      const text = readText(path.join(dir, n));
      if (text) for (const f of dockerFloating(text)) res.docker.push({ file: rel(cwd, path.join(dir, n)), ...f });
    }
    const wf = path.join(dir, '.github', 'workflows');
    for (const n of listFiles(wf).filter((x) => /\.ya?ml$/i.test(x))) {
      const text = readText(path.join(wf, n));
      if (text) for (const f of actionsUnpinned(text)) res.actions.push({ file: rel(cwd, path.join(wf, n)), ...f });
    }
  }

  const list = [...pkgs.values()];
  if (list.length && deps.queryPackages) {
    try {
      const hits = await deps.queryPackages(list.map(({ ecosystem, name, version }) => ({ ecosystem, name, version })), {});
      for (const p of list) {
        for (const v of hits.get(`${p.ecosystem}:${p.name}@${p.version}`) || []) {
          const severity = String(v.id).startsWith('MAL-') ? 'MALICIOUS' : (v.severity || 'HIGH');
          res.vulns.push({ severity, id: v.id, aliases: v.aliases || [], summary: v.summary || '', ecosystem: p.ecosystem, name: p.name, version: p.version, fixed: v.fixed || null, lockfiles: [...p.lockfiles] });
        }
      }
    } catch (e) {
      res.errors.push(`OSV query failed: ${e.message}`);
    }
  }
  res.vulns.sort((a, b) => SEV_ORDER.indexOf(a.severity) - SEV_ORDER.indexOf(b.severity) || a.name.localeCompare(b.name));

  // Cooldown: only direct deps, to bound registry traffic.
  if (deps.getPackageVersions && res.cooldownDays > 0) {
    const checks = [];
    for (const [nk, d] of directs) for (const version of lockedVersions.get(nk) || []) checks.push({ ...d, version });
    await mapLimit(checks, 8, async (c) => {
      try {
        const versions = await deps.getPackageVersions(c.ecosystem, c.name, {});
        const hit = (versions || []).find((v) => v.version === c.version);
        if (!hit || !hit.publishedAt) return;
        const ageDays = (now - new Date(hit.publishedAt).getTime()) / DAY;
        if (ageDays < res.cooldownDays) res.tooNew.push({ ecosystem: c.ecosystem, name: c.name, version: c.version, publishedAt: new Date(hit.publishedAt).toISOString(), ageDays: Math.round(ageDays * 10) / 10 });
      } catch (e) {
        res.errors.push(`registry ${c.ecosystem}:${c.name}: ${e.message}`);
      }
    });
  }
  res.packagesScanned = list.length;
  res.directDeps = directs.size;
  return res;
}

function formatReport(r) {
  const L = [];
  const counts = SEV_ORDER.map((s) => `${s} ${r.vulns.filter((v) => v.severity === s).length}`).join(' | ');
  L.push(`# dep-audit: ${r.cwd}`);
  L.push(`lockfiles: ${r.lockfiles.length ? r.lockfiles.join(', ') : 'none'} | packages: ${r.packagesScanned || 0} | direct deps: ${r.directDeps || 0}`);
  L.push(`vulns: ${counts}`);
  for (const sev of SEV_ORDER) {
    const vs = r.vulns.filter((v) => v.severity === sev);
    if (!vs.length) continue;
    L.push('', `## ${sev} (${vs.length})`, '| id | package@version | fixed | lockfile | summary |', '|---|---|---|---|---|');
    for (const v of vs) {
      const ids = [v.id, ...v.aliases.filter((a) => a.startsWith('CVE-'))].join(' ');
      L.push(`| ${ids} | ${v.ecosystem}:${v.name}@${v.version} | ${v.fixed || '-'} | ${v.lockfiles.join(', ')} | ${v.summary.replace(/\|/g, '/').slice(0, 90)} |`);
    }
  }
  if (r.tooNew.length) {
    L.push('', `## Too new (< ${r.cooldownDays} days, direct deps)`);
    for (const t of r.tooNew) L.push(`- ${t.ecosystem}:${t.name}@${t.version} published ${t.publishedAt.slice(0, 10)} (${t.ageDays}d)`);
  }
  if (r.missingLockfiles.length) {
    L.push('', '## Missing lockfiles (transitive deps unchecked)');
    for (const m of r.missingLockfiles) L.push(`- ${m}`);
  }
  if (r.docker.length) {
    L.push('', '## Floating Docker base images');
    for (const d of r.docker) L.push(`- ${d.file}:${d.line} ${d.image} (${d.reason})`);
  }
  if (r.actions.length) {
    L.push('', '## GitHub Actions not pinned to a commit SHA');
    for (const a of r.actions) L.push(`- ${a.file}:${a.line} ${a.uses} (${a.reason})`);
  }
  if (r.errors.length) {
    L.push('', '## Errors (results may be incomplete)');
    for (const e of r.errors) L.push(`- ${e}`);
  }
  if (!r.vulns.length && !r.tooNew.length && !r.missingLockfiles.length && !r.docker.length && !r.actions.length && !r.errors.length) L.push('', 'No findings.');
  return L.join('\n');
}

function parseArgs(argv) {
  const o = { cwd: process.cwd(), json: false, recursive: false };
  for (let i = 0; i < argv.length; i++) {
    if (argv[i] === '--cwd') o.cwd = argv[++i] || o.cwd;
    else if (argv[i] === '--json') o.json = true;
    else if (argv[i] === '--recursive' || argv[i] === '-r') o.recursive = true;
  }
  return o;
}

async function main() {
  try {
    const opts = parseArgs(process.argv.slice(2));
    const r = await audit(opts, loadDeps());
    process.stdout.write(`${opts.json ? JSON.stringify(r, null, 2) : formatReport(r)}\n`);
  } catch (e) {
    process.stdout.write(`dep-audit error: ${e && e.message}\n`);
  }
  process.exitCode = 0;
}

module.exports = { audit, formatReport, dockerFloating, actionsUnpinned, directDeps, walkDirs, parseArgs };

if (require.main === module) main();
