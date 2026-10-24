'use strict';
// Shell command -> package install intents. Pure (no I/O) and linear-time: hand-written scanners,
// and every regex here runs on a single short token with at most one unbounded quantifier.
// Only the command word of each segment is inspected, so `echo "npm i x"` or `git commit -m "pip install y"`
// never parse as installs. Bash and PowerShell syntax are both accepted.

const MAX_LEN = 20000; // longer commands: the tail is not inspected
const MAX_DEPTH = 3;   // nesting of bash -c / cmd /c / pwsh -c strings
const SPACE = new Set([' ', '\t', '\r', '\n']);
const DQ_ESC = new Set(['"', '\\', '$', '`']);
// bare backslash escapes only shell metachars, so Windows paths like C:\Users\x survive
const BARE_ESC = new Set([' ', '\t', '"', "'", '\\', ';', '&', '|', '<', '>', '(', ')', '$', '`', '#', '*', '?', '[', ']', '{', '}', '!']);

// ---------- splitting / lexing ----------

function splitSpans(cmd) {
  const s = String(cmd).slice(0, MAX_LEN);
  const out = [];
  let start = 0;
  let q = null;
  const cut = (end, next) => { out.push({ text: s.slice(start, end), start }); start = next; };
  for (let i = 0; i < s.length; i++) {
    const c = s[i];
    if (q) {
      if (c === q) q = null;
      else if (q === '"' && (c === '\\' || c === '`')) i++;
      continue;
    }
    if (c === "'" || c === '"') { q = c; continue; }
    if (c === '\\' || c === '`') { i++; continue; }
    if (c === '#' && (i === start || SPACE.has(s[i - 1]))) {
      const nl = s.indexOf('\n', i);
      const end = nl === -1 ? s.length : nl;
      cut(i, end);
      i = end - 1;
      continue;
    }
    if (c === ';' || c === '\n') { cut(i, i + 1); continue; }
    if (c === '|' || c === '&') {
      if (c === '&' && (s[i - 1] === '>' || s[i + 1] === '>')) continue; // 2>&1, &>file
      const two = s[i + 1] === c;
      cut(i, i + (two ? 2 : 1));
      if (two) i++;
    }
  }
  out.push({ text: s.slice(start), start });
  return out.filter((p) => p.text.trim());
}

function splitSegments(cmd) {
  return splitSpans(cmd).map((p) => p.text.trim());
}

// tokens carry absolute source offsets (or null inside strings we cannot map 1:1) for rewriting
function lex(text, base) {
  const toks = [];
  const n = text.length;
  const at = (k) => (base == null ? null : base + k);
  let i = 0;
  outer:
  while (i < n) {
    while (i < n && SPACE.has(text[i])) i++;
    if (i >= n || text[i] === '#') break;
    const s = i;
    let val = '';
    let quote = null;
    let plain = true;
    while (i < n && !SPACE.has(text[i])) {
      const c = text[i];
      if (c === "'" || c === '"') {
        quote = quote || c;
        i++;
        while (i < n && text[i] !== c) {
          if (c === '"' && i + 1 < n && ((text[i] === '\\' && DQ_ESC.has(text[i + 1])) || text[i] === '`')) {
            val += text[i + 1]; i += 2; plain = false; continue;
          }
          val += text[i++];
        }
        i++;
        continue;
      }
      if ((c === '`' || (c === '\\' && BARE_ESC.has(text[i + 1]))) && i + 1 < n) {
        val += text[i + 1]; i += 2; plain = false; continue;
      }
      if (c === '<' || c === '>') {
        if (quote || !/^[\d&]*$/.test(val)) break; // word ends; redirect op follows
        while (i < n && (text[i] === '<' || text[i] === '>' || text[i] === '&')) i++;
        toks.push({ op: true, value: text.slice(s, i), start: at(s), end: at(i) });
        continue outer;
      }
      val += c;
      i++;
    }
    const raw = text.slice(s, i);
    toks.push({ value: val, raw, start: at(s), end: at(i), quote, exact: plain && !!quote && raw === quote + val + quote });
  }
  return toks;
}

// drop redirect operators and their targets
function clean(toks) {
  const out = [];
  for (let k = 0; k < toks.length; k++) {
    if (toks[k].op) { k++; continue; }
    out.push({ ...toks[k], idx: out.length });
  }
  return out;
}

function tokenize(segment) {
  return clean(lex(String(segment), null)).map((t) => t.value);
}

// ---------- spec helpers ----------

const NPM_NAME = /^(?:@[a-z0-9~][\w.~-]*\/)?[a-z0-9~][\w.~-]*$/i;
const PY_NAME = /^[A-Za-z0-9][A-Za-z0-9._-]*/;
const CRATE_NAME = /^[A-Za-z0-9_-]+$/;

function isNonRegistry(v) {
  return /^(?:[.~/\\$%]|[A-Za-z]:[\\/])/.test(v)
    || v.includes('://')
    || /^(?:git\+|git:|github:|gitlab:|bitbucket:|file:|link:|workspace:|portal:|patch:|catalog:)/i.test(v)
    || /\.(?:tgz|tar\.gz|tar\.bz2|tar|zip|whl)$/i.test(v);
}

function parseNpmSpec(v) {
  if (!v || isNonRegistry(v)) return null;
  const at = v.indexOf('@', 1);
  const name = at === -1 ? v : v.slice(0, at);
  const spec = at === -1 ? '' : v.slice(at + 1);
  if (!NPM_NAME.test(name)) return null; // also rejects user/repo github shorthand
  if (spec.startsWith('npm:')) {
    const inner = parseNpmSpec(spec.slice(4));
    return inner && !inner.alias ? { ...inner, alias: name } : null;
  }
  if (/[:/]/.test(spec)) return null; // git/file/url specs
  return { name, spec };
}

function parsePep508(v) {
  const s = String(v).trim();
  if (!s || isNonRegistry(s)) return null;
  const m = PY_NAME.exec(s);
  if (!m) return null;
  const name = m[0];
  let rest = s.slice(name.length);
  let extras = '';
  if (rest[0] === '[') {
    const e = rest.indexOf(']');
    if (e === -1) return null;
    extras = rest.slice(0, e + 1);
    rest = rest.slice(e + 1);
  }
  const semi = rest.indexOf(';');
  const markers = semi === -1 ? '' : rest.slice(semi + 1).trim();
  const spec = (semi === -1 ? rest : rest.slice(0, semi)).replace(/\s/g, '');
  if (spec && !/^[<>=!~]/.test(spec)) return null; // "name @ url" and junk
  return { name, extras, spec, markers };
}

// "name[extras]@ver" (uvx / poetry add / cargo) -> {name, extras, spec}
function parseAtSpec(v, nameRe) {
  if (!v || isNonRegistry(v)) return null;
  const at = v.indexOf('@');
  const head = at === -1 ? v : v.slice(0, at);
  const ver = at === -1 ? '' : v.slice(at + 1);
  const b = head.indexOf('[');
  const name = b === -1 ? head : head.slice(0, b);
  const extras = b === -1 ? '' : head.slice(b);
  if (!nameRe.test(name) || (extras && !extras.endsWith(']')) || /[:/]/.test(ver)) return null;
  return { name, extras, spec: ver === 'latest' ? '' : ver };
}

// Poetry constraint -> PEP 440 (null = cannot translate)
function poetryToPep440(spec) {
  const s = String(spec || '').trim();
  if (!s || s === '*' || s === 'latest') return '';
  if (/^(?:[<>=!]|~=)/.test(s)) return s.replace(/\s/g, '');
  const m = /^([\^~]?)(\d+(?:\.\d+){0,3})$/.exec(s);
  if (!m) return null;
  const parts = m[2].split('.').map(Number);
  if (!m[1]) return `==${m[2]}`;
  let idx;
  if (m[1] === '~') idx = parts.length === 1 ? 0 : 1;
  else { idx = parts.findIndex((p) => p !== 0); if (idx === -1) idx = parts.length - 1; }
  const upper = parts.slice(0, idx + 1);
  upper[idx] += 1;
  return `>=${m[2]},<${upper.join('.')}`;
}

function pinToken(pkg, version) {
  switch (pkg.fmt) {
    case 'npm': return `${pkg.alias ? `${pkg.alias}@npm:` : ''}${pkg.name}@${version}`;
    case 'npm-create': return `${pkg.display}@${version}`;
    case 'pep508': return `${pkg.name}${pkg.extras || ''}==${version}${pkg.markers ? `; ${pkg.markers}` : ''}`;
    case 'cargo-add': return `${pkg.name}@=${version}`;
    default: return `${pkg.name}${pkg.extras || ''}@${version}`; // 'at': uvx, cargo install
  }
}

// ---------- argument scanning ----------

function scanArgs(toks, valSet, stopAtPos = false) {
  const pos = [];
  const flags = [];
  for (let k = 0; k < toks.length; k++) {
    const t = toks[k];
    const v = t.value;
    if (v === '--') {
      if (stopAtPos) return { pos: toks[k + 1] ? [toks[k + 1]] : [], flags, tail: toks.slice(k + 2) };
      pos.push(...toks.slice(k + 1));
      break;
    }
    if (v.length > 1 && v[0] === '-') {
      const eq = v.startsWith('--') ? v.indexOf('=') : -1;
      if (eq > 0) flags.push({ name: v.slice(0, eq), value: v.slice(eq + 1), tok: t, prefix: v.slice(0, eq + 1) });
      else if (valSet.has(v) && k + 1 < toks.length) { flags.push({ name: v, value: toks[k + 1].value, tok: t, valTok: toks[k + 1] }); k++; }
      else flags.push({ name: v, value: true, tok: t });
      continue;
    }
    pos.push(t);
    if (stopAtPos) return { pos, flags, tail: toks.slice(k + 1) };
  }
  return { pos, flags, tail: [] };
}

const flagsNamed = (flags, names) => flags.filter((f) => names.includes(f.name) && typeof f.value === 'string');
const flagVals = (flags, names) => flagsNamed(flags, names).map((f) => f.value);
const hasFlag = (flags, names) => flags.some((f) => names.includes(f.name));

function cmdName(v) {
  return v.replace(/^[({]+/, '').replace(/\\/g, '/').split('/').pop().toLowerCase().replace(/\.(?:exe|cmd|bat|ps1)$/, '');
}

function joinCwd(cur, arg) {
  const a = arg.replace(/\\/g, '/');
  // `cd ~/proj && npm install` is the normal idiom on Linux and macOS. Returning `~/proj`
  // verbatim made path.resolve produce `<cwd>/~/proj`, so no lockfile was found and the
  // install was allowed as "no lockfile". Expand it here, before anything resolves it.
  if (a === '~' || a.startsWith('~/')) return require('os').homedir().replace(/\\/g, '/') + a.slice(1);
  if (/^(?:\/|[A-Za-z]:)/.test(a) || !cur) return a;
  return `${cur.replace(/\/+$/, '')}/${a}`;
}

// ---------- package builders ----------

// tok: the token holding the spec; flag: the --flag=value token form (keeps its prefix on rewrite)
function mkPkg(tok, parsed, fmt, extra = {}) {
  if (!parsed) return null;
  return {
    name: parsed.name,
    spec: parsed.spec,
    raw: tok.value,
    ...(parsed.extras ? { extras: parsed.extras } : {}),
    ...(parsed.markers ? { markers: parsed.markers } : {}),
    ...(parsed.alias ? { alias: parsed.alias } : {}),
    fmt,
    start: tok.start,
    end: tok.end,
    quote: tok.quote,
    tokenIndex: tok.idx,
    ...extra,
  };
}

function pkgFromFlag(f, parse, fmt) {
  if (f.valTok) return mkPkg(f.valTok, parse(f.value), fmt);
  const p = mkPkg(f.tok, parse(f.value), fmt, { prefix: f.prefix });
  if (p) p.raw = f.value;
  return p;
}

const npmPkg = (t) => mkPkg(t, parseNpmSpec(t.value), 'npm');
const pyPkg = (t) => mkPkg(t, parsePep508(t.value), 'pep508');

function createPkg(t) {
  const v = t.value;
  if (/^@[a-z0-9~][\w.~-]*$/i.test(v)) return mkPkg(t, { name: `${v}/create`, spec: '' }, 'npm-create', { display: v });
  const p = parseNpmSpec(v);
  if (!p || p.alias) return null;
  const slash = p.name.indexOf('/');
  const name = p.name[0] === '@' ? `${p.name.slice(0, slash)}/create-${p.name.slice(slash + 1)}` : `create-${p.name}`;
  return mkPkg(t, { name, spec: p.spec }, 'npm-create', { display: p.name });
}

// ---------- per-tool handlers ----------

const NPM_VAL = new Set(['--registry', '--prefix', '-C', '--tag', '--workspace', '-w', '--omit', '--include', '--cache', '--userconfig', '--globalconfig', '--loglevel', '--save-prefix', '--before', '--otp', '--install-strategy', '--package', '-p', '--call', '-c']);
const PNPM_VAL = new Set(['--filter', '-F', '--dir', '-C', '--registry', '--reporter', '--package', '--config-dir', '--store-dir', '--virtual-store-dir', '--loglevel', '--allow-build']);
const YARN_VAL = new Set(['--cwd', '--registry', '--package', '-p', '--modules-folder', '--cache-folder', '--network-timeout', '--mutex']);
const BUN_VAL = new Set(['--cwd', '--registry', '--package', '-p', '--config', '-c', '--cache-dir', '--backend', '--omit', '--filter']);
const NPM_FAMILY = {
  npm: { val: NPM_VAL, install: new Set(['i', 'install', 'add', 'isntall', 'in', 'ins', 'inst', 'insta', 'instal', 'isnt', 'isnta', 'isntal', 'install-test', 'it']), lock: new Set(['ci', 'clean-install', 'ic', 'install-clean', 'isntall-clean']), exec: new Set(['exec', 'x']), create: new Set(['create', 'init', 'innit']) },
  pnpm: { val: PNPM_VAL, install: new Set(['add', 'i', 'install']), lock: new Set(), exec: new Set(['dlx']), create: new Set(['create']) },
  yarn: { val: YARN_VAL, install: new Set(['add']), lock: new Set(['install']), exec: new Set(['dlx']), create: new Set(['create']) },
  bun: { val: BUN_VAL, install: new Set(['add', 'a', 'i', 'install']), lock: new Set(), exec: new Set(['x']), create: new Set(['create', 'c']) },
};

function npmRunner(tail, val, mgr, emit) {
  const { pos, flags } = scanArgs(tail, val, true);
  const pk = flagsNamed(flags, ['--package', '-p']);
  const registries = flagVals(flags, ['--registry']);
  if (pk.length) return emit.explicit('npm', mgr, pk.map((f) => pkgFromFlag(f, parseNpmSpec, 'npm')), { runner: true, registries });
  if (hasFlag(flags, ['-c', '--call']) || !pos.length) return undefined;
  return emit.explicit('npm', mgr, [npmPkg(pos[0])], { runner: true, registries });
}

function npmFamily(mgr, rest, emit) {
  const fam = NPM_FAMILY[mgr];
  const head = scanArgs(rest, fam.val, true);
  const sub = head.pos[0] ? head.pos[0].value : null;
  const gcwd = flagVals(head.flags, ['--prefix', '-C', '--dir', '--cwd'])[0];
  if (!sub) return mgr === 'yarn' && !head.flags.some((f) => f.name === '--version' || f.name === '-v') ? emit.lockfile('npm', mgr, { cwd: gcwd }) : undefined;
  if (fam.exec.has(sub)) return npmRunner(head.tail, fam.val, `${mgr} ${sub}`, emit);
  if (fam.create.has(sub)) {
    const { pos } = scanArgs(head.tail, fam.val, true);
    return pos.length ? emit.explicit('npm', `${mgr} ${sub}`, [createPkg(pos[0])], { runner: true }) : undefined;
  }
  let tail = head.tail;
  let isInstall = fam.install.has(sub);
  if (mgr === 'yarn' && sub === 'global' && tail[0] && tail[0].value === 'add') { tail = tail.slice(1); isInstall = true; }
  if (!isInstall && !fam.lock.has(sub)) return undefined;
  const { pos, flags } = scanArgs(tail, fam.val);
  const all = [...head.flags, ...flags];
  const cwd = flagVals(all, ['--prefix', '-C', '--dir', '--cwd'])[0];
  if (fam.lock.has(sub) || !pos.length) return sub === 'add' && !pos.length ? undefined : emit.lockfile('npm', mgr, { cwd });
  return emit.explicit('npm', mgr, pos.map(npmPkg), { registries: flagVals(all, ['--registry']), global: hasFlag(all, ['-g', '--global']) || sub === 'global' });
}

const PY_VAL = new Set(['-i', '--index-url', '--extra-index-url', '-c', '--constraint', '-t', '--target', '--python', '--python-version', '--platform', '--implementation', '--abi', '--root', '--prefix', '--src', '--upgrade-strategy', '--progress-bar', '-f', '--find-links', '--trusted-host', '--cache-dir', '--log', '--proxy', '--retries', '--timeout', '--exists-action', '--cert', '--client-cert', '--global-option', '--config-settings', '-C', '--report', '--only-binary', '--no-binary', '--keyring-provider', '--root-user-action', '-r', '--requirement', '--requirements', '-e', '--editable', '--use-feature', '--group', '--extra', '-p', '--index', '--default-index', '--directory', '--project', '--with', '--with-requirements', '--with-editable', '--from', '--spec', '--pip-args', '--suffix', '--source', '-G', '-E', '--extras', '-P', '--optional', '--package', '--rev', '--tag', '--branch', '--overrides', '--index-strategy', '--resolution', '--prerelease', '--exclude-newer', '--torch-backend']);
const PY_INDEX = ['-i', '--index-url', '--extra-index-url', '--index', '--default-index'];
const pyCwd = (flags) => flagVals(flags, ['--directory', '--project', '-C', '-P'])[0];

function reqFiles(flags) {
  const files = flagVals(flags, ['-r', '--requirement', '--requirements']);
  for (const f of flags) if (/^-r[^-]/.test(f.name)) files.push(f.name.slice(2));
  return files;
}

// pip-style "install" args (pip, uv pip, pipenv)
function pipInstall(tail, mgr, emit, extraFlags = []) {
  const { pos, flags } = scanArgs(tail, PY_VAL);
  const all = [...extraFlags, ...flags];
  const files = reqFiles(all);
  const pkgs = pos.map(pyPkg).filter(Boolean);
  if (files.length) emit.lockfile('pypi', mgr, { files, cwd: pyCwd(all) });
  if (pkgs.length) emit.explicit('pypi', mgr, pkgs, { registries: flagVals(all, PY_INDEX) });
  return { pos, files, pkgs };
}

function pyRunner(tail, mgr, emit) {
  const { pos, flags } = scanArgs(tail, PY_VAL, true);
  const from = flagsNamed(flags, ['--from', '--spec']);
  const pkgs = flagsNamed(flags, ['--with']).map((f) => pkgFromFlag(f, parsePep508, 'pep508'));
  if (from.length) pkgs.push(pkgFromFlag(from[0], parsePep508, 'pep508'));
  else if (pos.length) pkgs.push(mkPkg(pos[0], parseAtSpec(pos[0].value, PY_NAME_FULL), 'at'));
  for (const p of pkgs) if (p && p.fmt === 'at' && p.spec && /^\d/.test(p.spec)) p.spec = `==${p.spec}`;
  emit.explicit('pypi', mgr, pkgs, { runner: true, registries: flagVals(flags, PY_INDEX) });
}
const PY_NAME_FULL = /^[A-Za-z0-9][A-Za-z0-9._-]*$/;

function pipFamily(mgr, rest, emit) {
  const head = scanArgs(rest, PY_VAL, true);
  if (!head.pos[0] || head.pos[0].value !== 'install') return;
  pipInstall(head.tail, mgr, emit, head.flags);
}

function uvTool(rest, emit) {
  const head = scanArgs(rest, PY_VAL, true);
  const sub = head.pos[0] && head.pos[0].value;
  const tail = head.tail;
  if (sub === 'pip') {
    const h2 = scanArgs(tail, PY_VAL, true);
    const s2 = h2.pos[0] && h2.pos[0].value;
    if (s2 === 'install') pipInstall(h2.tail, 'uv pip', emit, [...head.flags, ...h2.flags]);
    else if (s2 === 'sync') {
      const { pos, flags } = scanArgs(h2.tail, PY_VAL);
      emit.lockfile('pypi', 'uv pip', { files: pos.map((t) => t.value), cwd: pyCwd([...head.flags, ...flags]) });
    }
  } else if (sub === 'add') {
    const { pos, flags } = scanArgs(tail, PY_VAL);
    const all = [...head.flags, ...flags];
    if (hasFlag(all, ['--git', '--path', '--editable'])) return;
    const files = reqFiles(all);
    if (files.length) emit.lockfile('pypi', 'uv add', { files, cwd: pyCwd(all) });
    emit.explicit('pypi', 'uv add', pos.map(pyPkg), { registries: flagVals(all, PY_INDEX) });
  } else if (sub === 'sync') {
    emit.lockfile('pypi', 'uv sync', { cwd: pyCwd([...head.flags, ...scanArgs(tail, PY_VAL).flags]) });
  } else if (sub === 'run') {
    const { flags } = scanArgs(tail, PY_VAL, true);
    emit.explicit('pypi', 'uv run', flagsNamed(flags, ['--with']).map((f) => pkgFromFlag(f, parsePep508, 'pep508')), { runner: true });
  } else if (sub === 'tool') {
    const h2 = scanArgs(tail, PY_VAL, true);
    const s2 = h2.pos[0] && h2.pos[0].value;
    if (s2 === 'run') pyRunner(h2.tail, 'uv tool run', emit);
    else if (s2 === 'install') {
      const { pos, flags } = scanArgs(h2.tail, PY_VAL);
      const pkgs = [...flagsNamed(flags, ['--with']).map((f) => pkgFromFlag(f, parsePep508, 'pep508')), ...pos.slice(0, 1).map(pyPkg)];
      emit.explicit('pypi', 'uv tool', pkgs, { registries: flagVals(flags, PY_INDEX) });
    }
  }
}

function pipxTool(rest, emit) {
  const head = scanArgs(rest, PY_VAL, true);
  const sub = head.pos[0] && head.pos[0].value;
  if (sub === 'run') return pyRunner(head.tail, 'pipx run', emit);
  if (sub !== 'install') return;
  const { pos, flags } = scanArgs(head.tail, PY_VAL);
  emit.explicit('pypi', 'pipx', pos.map(pyPkg), { registries: flagVals(flags, PY_INDEX) });
}

function poetryTool(rest, emit) {
  const head = scanArgs(rest, PY_VAL, true);
  const sub = head.pos[0] && head.pos[0].value;
  const { pos, flags } = scanArgs(head.tail, PY_VAL);
  const cwd = pyCwd([...head.flags, ...flags]);
  if (sub === 'install' || sub === 'sync') return emit.lockfile('pypi', 'poetry', { cwd });
  if (sub !== 'add') return;
  const pkgs = pos.map((t) => {
    const v = t.value;
    if (/[<>=!~]/.test(v.replace(/@.*/, ''))) return pyPkg(t); // "foo>=1" pep508 form
    const p = parseAtSpec(v, PY_NAME_FULL);
    if (!p) return null;
    const spec = poetryToPep440(p.spec);
    return spec === null ? null : mkPkg(t, { ...p, spec }, 'pep508');
  });
  emit.explicit('pypi', 'poetry', pkgs, {});
}

function pipenvTool(rest, emit) {
  const head = scanArgs(rest, PY_VAL, true);
  const sub = head.pos[0] && head.pos[0].value;
  if (sub === 'sync') return emit.lockfile('pypi', 'pipenv', {});
  if (sub !== 'install') return;
  const r = pipInstall(head.tail, 'pipenv', emit, head.flags);
  if (!r.pos.length && !r.files.length) emit.lockfile('pypi', 'pipenv', {});
}

const CARGO_VAL = new Set(['--features', '-F', '--rename', '--package', '-p', '--path', '--git', '--branch', '--tag', '--rev', '--registry', '--target', '--manifest-path', '--bin', '--example', '--root', '--index', '--target-dir', '-j', '--jobs', '--profile', '--config', '-Z', '--version', '--vers', '--color']);
const CARGO_LOCK = new Set(['build', 'b', 'fetch', 'run', 'r', 'test', 't', 'check', 'c', 'bench', 'doc', 'clippy']);

function cargoTool(rest, emit) {
  const r = rest.filter((t) => t.value[0] !== '+'); // +nightly toolchain
  const head = scanArgs(r, CARGO_VAL, true);
  const sub = head.pos[0] && head.pos[0].value;
  if (CARGO_LOCK.has(sub)) return emit.lockfile('crates', 'cargo', {});
  if (sub !== 'add' && sub !== 'install') return;
  const { pos, flags } = scanArgs(head.tail, CARGO_VAL);
  const registries = flagVals(flags, ['--registry', '--index']);
  if (hasFlag(flags, ['--git'])) return;
  if (sub === 'add') {
    if (hasFlag(flags, ['--path'])) return;
    return emit.explicit('crates', 'cargo add', pos.map((t) => mkPkg(t, parseAtSpec(t.value, CRATE_NAME), 'cargo-add')), { registries });
  }
  const path = flagVals(flags, ['--path'])[0];
  if (path || !pos.length) return emit.lockfile('crates', 'cargo install', { cwd: path });
  const ver = flags.find((f) => (f.name === '--version' || f.name === '--vers') && typeof f.value === 'string');
  const pkgs = pos.map((t) => mkPkg(t, parseAtSpec(t.value, CRATE_NAME), 'at'));
  if (ver && pkgs[0] && !pkgs[0].spec) {
    // spec moves into the name token (name@=x) on rewrite, so the flag is dropped
    pkgs[0].spec = ver.value;
    pkgs[0].drop = [[ver.tok.start, ver.valTok ? ver.valTok.end : ver.tok.end]];
  }
  for (const p of pkgs) if (p && /^\d/.test(p.spec || '')) p.spec = `=${p.spec}`; // cargo install x@1.2.3 is exact
  return emit.explicit('crates', 'cargo install', pkgs, { registries });
}

const DOCKER_SHORT_VAL = new Set(['a', 'c', 'e', 'h', 'l', 'm', 'p', 'u', 'v', 'w']);
const DOCKER_LONG_VAL = new Set(['--name', '--network', '--net', '--entrypoint', '--workdir', '--user', '--platform', '--env', '--env-file', '--volume', '--publish', '--label', '--label-file', '--mount', '--add-host', '--cpus', '--memory', '--restart', '--log-driver', '--log-opt', '--hostname', '--device', '--cap-add', '--cap-drop', '--security-opt', '--tmpfs', '--ulimit', '--pull', '--health-cmd', '--health-interval', '--health-retries', '--health-timeout', '--health-start-period', '--dns', '--dns-search', '--dns-option', '--gpus', '--ipc', '--pid', '--shm-size', '--stop-signal', '--stop-timeout', '--storage-opt', '--sysctl', '--cidfile', '--cgroupns', '--cgroup-parent', '--volumes-from', '--link', '--expose', '--runtime', '--userns', '--uts', '--isolation', '--memory-swap', '--memory-reservation', '--cpu-shares', '--cpuset-cpus', '--cpuset-mems', '--cpu-period', '--cpu-quota', '--ip', '--ip6', '--mac-address', '--network-alias', '--attach', '--detach-keys', '--group-add', '--blkio-weight', '--device-cgroup-rule', '--domainname', '--oom-score-adj', '--pids-limit', '--annotation', '--context', '--host', '-H', '--config', '--log-level']);
const IMAGE_RE = /^[a-z0-9][\w.\-/:@]*$/i;

function dockerImageArg(toks) {
  for (let k = 0; k < toks.length; k++) {
    const v = toks[k].value;
    if (v === '--') continue;
    if (v.startsWith('--')) { if (!v.includes('=') && DOCKER_LONG_VAL.has(v)) k++; continue; }
    if (v[0] === '-' && v.length > 1) {
      for (let j = 1; j < v.length; j++) {
        if (DOCKER_SHORT_VAL.has(v[j])) { if (j === v.length - 1) k++; break; }
      }
      continue;
    }
    return IMAGE_RE.test(v) ? v : null;
  }
  return null;
}

const COMPOSE_VAL = new Set(['-f', '--file', '-p', '--project-name', '--project-directory', '--env-file', '--profile', '--ansi', '--progress', '--parallel']);
const BUILD_VAL = new Set(['-t', '--tag', '-f', '--file', '--build-arg', '--target', '--platform', '--network', '--label', '--secret', '--ssh', '--cache-from', '--cache-to', '-o', '--output', '--progress', '--iidfile', '--builder', '--build-context', '--add-host', '--shm-size', '--ulimit']);

function composeTool(rest, emit) {
  const head = scanArgs(rest, COMPOSE_VAL, true);
  const sub = head.pos[0] && head.pos[0].value;
  if (!['up', 'pull', 'run', 'create', 'start'].includes(sub)) return;
  emit.push({ kind: 'compose', files: flagVals(head.flags, ['-f', '--file']), cwd: flagVals(head.flags, ['--project-directory'])[0] });
}

function dockerTool(rest, emit) {
  const head = scanArgs(rest, DOCKER_LONG_VAL, true);
  let sub = head.pos[0] && head.pos[0].value;
  let tail = head.tail;
  if ((sub === 'container' || sub === 'image' || sub === 'buildx') && tail[0]) { sub = `${sub} ${tail[0].value}`; tail = tail.slice(1); }
  if (sub === 'compose') return composeTool(tail, emit);
  if (['run', 'create', 'pull', 'container run', 'container create', 'image pull'].includes(sub)) {
    const image = dockerImageArg(tail);
    if (image) emit.push({ kind: 'image', image });
    return;
  }
  if (sub === 'build' || sub === 'buildx build' || sub === 'image build') {
    const tag = flagVals(scanArgs(tail, BUILD_VAL).flags, ['-t', '--tag'])[0];
    if (tag) emit.push({ kind: 'build', tag });
  }
}

// ---------- segment dispatch ----------

const ENV_ASSIGN = /^[A-Za-z_][A-Za-z0-9_]*=/;
const PREFIX = new Set(['sudo', 'doas', 'time', 'nohup', 'exec', 'command', 'builtin', 'nice', 'call', 'start-process']);
const PREFIX_VAL = new Set(['-u', '-g', '-n', '-C', '-h', '-p', '-U']);
const SHELLS = new Set(['bash', 'sh', 'zsh', 'dash', 'ksh', 'fish']);
const PS_CMD = /^-c(?:o(?:m(?:m(?:a(?:n(?:d)?)?)?)?)?)?$/i;

function parseSegment(toks, ctx, depth, oq) {
  let i = 0;
  for (;;) {
    if (i >= toks.length) return;
    const v = toks[i].value;
    const name = cmdName(v);
    if (ENV_ASSIGN.test(v) || v === '!' || v === '' || /^[({]+$/.test(v)) { i++; continue; }
    if (PREFIX.has(name)) {
      i++;
      while (i < toks.length && toks[i].value[0] === '-') i += PREFIX_VAL.has(toks[i].value) ? 2 : 1;
      continue;
    }
    if (name === 'env') {
      i++;
      while (i < toks.length && (toks[i].value[0] === '-' || ENV_ASSIGN.test(toks[i].value))) i++;
      continue;
    }
    break;
  }
  const name = cmdName(toks[i].value);
  const rest = toks.slice(i + 1);
  const recurse = (t) => {
    if (depth < MAX_DEPTH) parseString(t.value, t.exact && t.start != null ? t.start + 1 : null, ctx, depth + 1, t.quote || oq);
  };
  const runRest = (r) => (r.length === 1 ? recurse(r[0]) : r.length && parseSegment(r, ctx, depth, oq));

  if (name === 'cmd') {
    const k = rest.findIndex((t) => /^\/[ck]$/i.test(t.value));
    return k === -1 ? undefined : runRest(rest.slice(k + 1));
  }
  if (name === 'powershell' || name === 'pwsh') {
    const k = rest.findIndex((t) => PS_CMD.test(t.value));
    return k === -1 ? undefined : runRest(rest.slice(k + 1));
  }
  if (SHELLS.has(name)) {
    const k = rest.findIndex((t) => /^-[a-z]*c[a-z]*$/.test(t.value));
    return k !== -1 && rest[k + 1] ? recurse(rest[k + 1]) : undefined;
  }
  if (name === 'cd' || name === 'chdir' || name === 'pushd' || name === 'set-location' || name === 'sl') {
    const args = rest.filter((t) => t.value[0] !== '-' && !/^\/d$/i.test(t.value));
    if (args.length) ctx.cwd = joinCwd(ctx.cwd, args[args.length - 1].value);
    return undefined;
  }

  const emit = makeEmitter(ctx, oq);
  if (NPM_FAMILY[name]) return npmFamily(name, rest, emit);
  if (name === 'npx' || name === 'pnpx') return npmRunner(rest, NPM_VAL, name, emit);
  if (name === 'bunx') return npmRunner(rest, BUN_VAL, 'bunx', emit);
  if (/^pip(?:\d+(?:\.\d+)?)?$/.test(name)) return pipFamily('pip', rest, emit);
  if (/^(?:python(?:\d+(?:\.\d+)?)?|py)$/.test(name)) {
    const k = rest.findIndex((t) => t.value === '-m');
    if (k !== -1 && rest[k + 1] && rest[k + 1].value === 'pip') return pipFamily('pip', rest.slice(k + 2), emit);
    return undefined;
  }
  if (name === 'uv') return uvTool(rest, emit);
  if (name === 'uvx') return pyRunner(rest, 'uvx', emit);
  if (name === 'pipx') return pipxTool(rest, emit);
  if (name === 'poetry') return poetryTool(rest, emit);
  if (name === 'pipenv') return pipenvTool(rest, emit);
  if (name === 'cargo') return cargoTool(rest, emit);
  if (name === 'docker' || name === 'podman') return dockerTool(rest, emit);
  if (name === 'docker-compose') return composeTool(rest, emit);
  return undefined;
}

function makeEmitter(ctx, oq) {
  const push = (intent) => {
    if (ctx.cwd && intent.cwd == null) intent.cwd = ctx.cwd;
    else if (ctx.cwd && intent.cwd) intent.cwd = joinCwd(ctx.cwd, intent.cwd);
    if (intent.cwd == null) delete intent.cwd;
    ctx.intents.push({ ...intent, segmentIndex: ctx.segmentIndex });
  };
  return {
    push,
    explicit(ecosystem, manager, pkgs, extra) {
      const packages = pkgs.filter(Boolean);
      if (!packages.length) return;
      for (const p of packages) if (oq) p.outerQuote = oq;
      const { registries, ...rest } = extra || {};
      push({ kind: 'explicit', ecosystem, manager, packages, tokenIndexes: packages.map((p) => p.tokenIndex), ...(registries && registries.length ? { registries } : {}), ...rest });
    },
    lockfile(ecosystem, manager, extra) {
      const { files, cwd } = extra || {};
      push({ kind: 'lockfile', ecosystem, manager, ...(files && files.length ? { files } : {}), cwd });
    },
  };
}

function parseString(cmd, base, ctx, depth, oq) {
  for (const [idx, sp] of splitSpans(cmd).entries()) {
    if (depth === 0) ctx.segmentIndex = idx;
    const toks = clean(lex(sp.text, base == null ? null : base + sp.start));
    if (toks.length) parseSegment(toks, ctx, depth, oq);
  }
}

function parseInstallIntents(cmd) {
  if (typeof cmd !== 'string' || !cmd) return [];
  const ctx = { intents: [], cwd: '', segmentIndex: 0 };
  parseString(cmd, 0, ctx, 0, null);
  return ctx.intents;
}

// ---------- rewriting ----------

const NEEDS_QUOTE = /[\s;<>|&*?'"$`(){}[\]!#]/;

// Always single-quote and escape embedded single quotes. The previous version picked one
// quote char and flipped it once if the value contained it, so a value holding BOTH quote
// chars produced an unbalanced string: the rewritten command we hand back as updatedInput
// became a second shell command that no hook ever inspected. Never widen this.
// Returns null when the value cannot be placed safely; the caller must then refuse to rewrite.
function quoteFor(val, pkg) {
  const v = String(val);
  // Already inside a quoted string (e.g. bash -c '...'): adding our own quotes would close
  // the outer one and turn the remainder into shell syntax. Emit bare, or give up.
  if (pkg.outerQuote) return v.includes(pkg.outerQuote) ? null : v;
  if (!pkg.quote && !NEEDS_QUOTE.test(v)) return v;
  return `'${v.replace(/'/g, "'\\''")}'`;
}

// Defence in depth: a pin should be an ordinary name@version. If one ever contains a shell
// metacharacter, do not try to quote our way out of it - refuse to rewrite at all.
const PIN_UNSAFE = /[;&|<>`$()\n\r]/;

function rewriteCommand(cmd, pins) {
  const edits = [];
  for (const it of parseInstallIntents(cmd)) {
    for (const p of it.packages || []) {
      if (!pins.has(p.raw) || p.start == null) continue;
      if (PIN_UNSAFE.test(String(pins.get(p.raw)))) return null; // caller must deny, not rewrite
      const q = quoteFor(pins.get(p.raw), p);
      if (q === null) return null;
      edits.push([p.start, p.end, (p.prefix || '') + q]);
      for (const [s, e] of p.drop || []) if (s != null && e != null) edits.push([s, e, '']);
    }
  }
  edits.sort((a, b) => b[0] - a[0]);
  let out = cmd;
  let floor = Infinity;
  for (const [s, e, t] of edits) {
    if (e > floor) continue; // overlapping edit (same token reached twice)
    out = out.slice(0, s) + t + out.slice(e);
    floor = s;
  }
  return out;
}

module.exports = {
  splitSegments, tokenize, parseInstallIntents, rewriteCommand,
  pinToken, parseNpmSpec, parsePep508, poetryToPep440, isNonRegistry,
};
