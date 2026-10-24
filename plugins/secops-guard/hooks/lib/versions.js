'use strict';
// Version compare + range satisfy for npm/crates (semver) and PyPI (PEP 440).
// satisfies() returns null for specs it does not understand, so callers can refuse rather than guess.

// ---------- semver ----------
const SEMVER = /^v?(\d+)\.(\d+)\.(\d+)(?:-([0-9A-Za-z.-]+))?(?:\+[0-9A-Za-z.-]+)?$/;

function parseSemver(v) {
  const m = SEMVER.exec(String(v).trim());
  if (!m) return null;
  return { major: +m[1], minor: +m[2], patch: +m[3], pre: m[4] ? m[4].split('.') : [] };
}

function cmpPre(a, b) {
  if (!a.length || !b.length) return (b.length ? 1 : 0) - (a.length ? 1 : 0); // release > prerelease
  for (let i = 0; i < Math.max(a.length, b.length); i++) {
    if (a[i] === undefined) return -1;
    if (b[i] === undefined) return 1;
    const an = /^\d+$/.test(a[i]);
    const bn = /^\d+$/.test(b[i]);
    if (an && bn) { if (+a[i] !== +b[i]) return +a[i] < +b[i] ? -1 : 1; } else if (an !== bn) return an ? -1 : 1;
    else if (a[i] !== b[i]) return a[i] < b[i] ? -1 : 1;
  }
  return 0;
}

function cmpParsedSemver(a, b) {
  for (const k of ['major', 'minor', 'patch']) if (a[k] !== b[k]) return a[k] < b[k] ? -1 : 1;
  return cmpPre(a.pre, b.pre);
}

// Unparseable versions sort below everything so they are never picked as "newest".
function compareSemver(a, b) {
  const pa = parseSemver(a);
  const pb = parseSemver(b);
  if (!pa || !pb) return (pa ? 1 : 0) - (pb ? 1 : 0);
  return cmpParsedSemver(pa, pb);
}

// ---------- semver ranges (npm + cargo) ----------
const PARTIAL = /^v?(\d+|[xX*])(?:\.(\d+|[xX*]))?(?:\.(\d+|[xX*]))?(?:-([0-9A-Za-z.-]+))?(?:\+[0-9A-Za-z.-]+)?$/;

function parsePartial(s) {
  if (s === '' || s === '*' || s === 'x' || s === 'X') return { parts: [] };
  const m = PARTIAL.exec(s);
  if (!m) return null;
  const parts = [];
  let wild = false;
  for (const p of [m[1], m[2], m[3]]) {
    if (p === undefined) break;
    if (/^[xX*]$/.test(p)) wild = true;
    else if (wild) return null; // "1.x.3" is nonsense
    else parts.push(+p);
  }
  return { parts, pre: m[4] && parts.length === 3 ? m[4].split('.') : [] };
}

const V = (major, minor, patch, pre = []) => ({ major, minor, patch, pre });
const LOWEST = ['0'];
// Comparator: {op, v, user}; user=true only for versions the spec author wrote (prerelease opt-in rule).
const C = (op, v, user = false) => ({ op, v, user });

function bumpAt(parts, idx) {
  const p = [parts[0] || 0, parts[1] || 0, parts[2] || 0];
  p[idx] += 1;
  for (let i = idx + 1; i < 3; i++) p[i] = 0;
  return V(p[0], p[1], p[2], LOWEST);
}

function xrange(parts) {
  if (!parts.length) return [C('>=', V(0, 0, 0))];
  return [C('>=', V(parts[0], parts[1] || 0, 0)), C('<', bumpAt(parts, parts.length - 1))];
}

function desugar(op, partial) {
  const { parts, pre } = partial;
  const full = parts.length === 3;
  const base = V(parts[0] || 0, parts[1] || 0, parts[2] || 0, pre);
  switch (op) {
    case '':
    case '=':
      return full ? [C('=', base, true)] : xrange(parts);
    case '^': {
      if (!parts.length) return xrange(parts);
      const idx = parts[0] !== 0 || parts.length === 1 ? 0 : parts[1] !== 0 || parts.length === 2 ? 1 : 2;
      return [C('>=', base, true), C('<', bumpAt(parts, Math.min(idx, parts.length - 1)))];
    }
    case '~':
      if (!parts.length) return xrange(parts);
      return [C('>=', base, true), C('<', bumpAt(parts, parts.length === 1 ? 0 : 1))];
    case '>':
      if (!parts.length) return [C('<', V(0, 0, 0, LOWEST))]; // >* matches nothing
      return full ? [C('>', base, true)] : [C('>=', bumpAt(parts, parts.length - 1))];
    case '>=':
      return [C('>=', base, true)];
    case '<':
      return full ? [C('<', base, true)] : [C('<', V(parts[0] || 0, parts[1] || 0, 0, LOWEST))];
    case '<=':
      if (!parts.length) return [C('>=', V(0, 0, 0))];
      return full ? [C('<=', base, true)] : [C('<', bumpAt(parts, parts.length - 1))];
    default:
      return null;
  }
}

const OP = /^(\^|~>?|>=|<=|>|<|=)?\s*(.*)$/;

function comparator(token) {
  const m = OP.exec(token);
  const op = m[1] === '~>' ? '~' : m[1] || '';
  const p = parsePartial(m[2]);
  return p ? desugar(op, p) : null;
}

function hyphen(a, b) {
  const pa = parsePartial(a);
  const pb = parsePartial(b);
  if (!pa || !pb) return null;
  const lo = pa.parts.length ? [C('>=', V(pa.parts[0], pa.parts[1] || 0, pa.parts[2] || 0, pa.pre), true)] : [];
  let hi = [];
  if (pb.parts.length === 3) hi = [C('<=', V(...pb.parts, pb.pre), true)];
  else if (pb.parts.length) hi = [C('<', bumpAt(pb.parts, pb.parts.length - 1))];
  return [...lo, ...hi];
}

function testSet(set, v) {
  for (const c of set) {
    const r = cmpParsedSemver(v, c.v);
    const ok = c.op === '=' ? r === 0 : c.op === '>' ? r > 0 : c.op === '>=' ? r >= 0 : c.op === '<' ? r < 0 : r <= 0;
    if (!ok) return false;
  }
  if (!v.pre.length) return true;
  // prereleases only match when the spec names a prerelease of the same major.minor.patch
  return set.some((c) => c.user && c.v.pre.length && c.v.major === v.major && c.v.minor === v.minor && c.v.patch === v.patch);
}

function parseNpmRange(spec) {
  const sets = [];
  for (const alt of spec.split('||')) {
    const s = alt.trim().replace(/(\^|~>?|>=|<=|>|<|=)\s+/g, '$1');
    const hm = /^(\S+)\s+-\s+(\S+)$/.exec(s);
    if (hm) {
      const set = hyphen(hm[1], hm[2]);
      if (!set) return null;
      sets.push(set);
      continue;
    }
    const set = [];
    for (const tok of s ? s.split(/\s+/) : ['*']) {
      const cs = comparator(tok);
      if (!cs) return null;
      set.push(...cs);
    }
    sets.push(set);
  }
  return sets;
}

function parseCargoReq(spec) {
  const set = [];
  for (const raw of spec.split(',')) {
    const tok = raw.trim().replace(/^(\^|~|>=|<=|>|<|=)\s+/, '$1');
    if (!tok) return null;
    const cs = comparator(/^[\^~><=]/.test(tok) || /[*xX]/.test(tok) ? tok : `^${tok}`); // bare = caret
    if (!cs) return null;
    set.push(...cs);
  }
  return [set];
}

// ---------- PEP 440 ----------
const PEP440 = /^v?(?:(\d+)!)?(\d+(?:\.\d+)*)(?:[-_.]?(a|alpha|b|beta|c|rc|pre|preview)[-_.]?(\d+)?)?(?:-(\d+)|[-_.]?(post|rev|r)[-_.]?(\d+)?)?(?:[-_.]?(dev)[-_.]?(\d+)?)?(?:\+([a-z0-9]+(?:[-_.][a-z0-9]+)*))?$/i;
const PRE_RANK = { a: 0, alpha: 0, b: 1, beta: 1, c: 2, rc: 2, pre: 2, preview: 2 };

function parsePep440(v) {
  const m = PEP440.exec(String(v).trim());
  if (!m) return null;
  return {
    epoch: m[1] ? +m[1] : 0,
    release: m[2].split('.').map(Number),
    pre: m[3] ? [PRE_RANK[m[3].toLowerCase()], m[4] ? +m[4] : 0] : null,
    post: m[5] !== undefined ? +m[5] : m[6] ? (m[7] ? +m[7] : 0) : null,
    dev: m[8] ? (m[9] ? +m[9] : 0) : null,
    local: m[10] ? m[10].toLowerCase().split(/[-_.]/) : null,
  };
}

const num = (a, b) => (a === b ? 0 : a < b ? -1 : 1);

function cmpRelease(a, b) {
  for (let i = 0; i < Math.max(a.length, b.length); i++) {
    const r = num(a[i] || 0, b[i] || 0);
    if (r) return r;
  }
  return 0;
}

function cmpParsedPep(a, b, ignoreLocal = false) {
  let r = num(a.epoch, b.epoch) || cmpRelease(a.release, b.release);
  if (r) return r;
  // sort keys mirror packaging.version: dev-only sorts before pre; no pre sorts after any pre
  const preKey = (p) => (p.pre ? p.pre : p.post === null && p.dev !== null ? [-Infinity, 0] : [Infinity, 0]);
  const [pa, pb] = [preKey(a), preKey(b)];
  r = num(pa[0], pb[0]) || num(pa[1], pb[1]);
  if (r) return r;
  r = num(a.post === null ? -Infinity : a.post, b.post === null ? -Infinity : b.post);
  if (r) return r;
  r = num(a.dev === null ? Infinity : a.dev, b.dev === null ? Infinity : b.dev);
  if (r || ignoreLocal) return r;
  if (!a.local || !b.local) return num(a.local ? 1 : 0, b.local ? 1 : 0);
  for (let i = 0; i < Math.max(a.local.length, b.local.length); i++) {
    if (a.local[i] === undefined) return -1;
    if (b.local[i] === undefined) return 1;
    const an = /^\d+$/.test(a.local[i]);
    const bn = /^\d+$/.test(b.local[i]);
    if (an !== bn) return an ? 1 : -1; // numeric segments sort above alphanumeric
    r = an ? num(+a.local[i], +b.local[i]) : num(a.local[i], b.local[i]);
    if (r) return r;
  }
  return 0;
}

function comparePep440(a, b) {
  const pa = parsePep440(a);
  const pb = parsePep440(b);
  if (!pa || !pb) return (pa ? 1 : 0) - (pb ? 1 : 0);
  return cmpParsedPep(pa, pb);
}

const PY_CLAUSE = /^(~=|===|==|!=|<=|>=|<|>)\s*(\S+)$/;

function pyClause(op, ver, v, raw) {
  if (op === '===') return raw.trim() === ver;
  if ((op === '==' || op === '!=') && ver.endsWith('.*')) {
    const s = parsePep440(ver.slice(0, -2));
    if (!s || s.pre || s.post !== null || s.dev !== null || s.local) return null;
    const pfx = s.epoch === v.epoch && s.release.every((n, i) => (v.release[i] || 0) === n);
    return op === '==' ? pfx : !pfx;
  }
  const s = parsePep440(ver);
  if (!s) return null;
  if (op === '==' || op === '!=') {
    const eq = cmpParsedPep(v, s, !s.local) === 0;
    return op === '==' ? eq : !eq;
  }
  if (op === '~=') {
    if (s.release.length < 2 || s.local) return null;
    const prefix = s.release.slice(0, -1);
    return cmpParsedPep(v, s, true) >= 0 && v.epoch === s.epoch && prefix.every((n, i) => (v.release[i] || 0) === n);
  }
  const r = cmpParsedPep(v, s, true);
  const sameRelease = v.epoch === s.epoch && cmpRelease(v.release, s.release) === 0;
  if (op === '>=') return r >= 0;
  if (op === '<=') return r <= 0;
  if (op === '<') return r < 0 && !(!s.pre && s.dev === null && (v.pre || v.dev !== null) && sameRelease);
  if (op === '>') return r > 0 && !(s.post === null && v.post !== null && sameRelease) && !(v.local && cmpParsedPep(v, s, true) === 0);
  return null;
}

function pySatisfies(version, spec) {
  const clauses = spec.split(',').map((c) => c.trim());
  if (clauses.length === 1 && clauses[0] === '') return parsePep440(version) ? !isPrerelease('pypi', version) : false;
  const parsed = clauses.map((c) => PY_CLAUSE.exec(c) || (/^\d/.test(c) ? ['', '==', c] : null));
  if (parsed.some((p) => !p)) return null;
  const v = parsePep440(version);
  // validate the spec even when the version is junk, so null still means "bad spec"
  if (!v) return parsed.every(([, op, ver]) => op === '===' || parsePep440(ver.replace(/\.\*$/, ''))) ? false : null;
  let ok = true;
  for (const [, op, ver] of parsed) {
    const r = pyClause(op, ver, v, version);
    if (r === null) return null;
    ok = ok && r;
  }
  if (ok && (v.pre || v.dev !== null)) {
    // prereleases only match when the spec itself mentions one
    return parsed.some(([, op, ver]) => op !== '!=' && isPrerelease('pypi', ver));
  }
  return ok;
}

// ---------- public ----------
function isPrerelease(eco, v) {
  if (eco === 'pypi') {
    const p = parsePep440(v);
    return !!p && (p.pre !== null || p.dev !== null);
  }
  const p = parseSemver(v);
  return !!p && p.pre.length > 0;
}

function compare(eco, a, b) {
  return eco === 'pypi' ? comparePep440(a, b) : compareSemver(a, b);
}

function satisfies(eco, version, spec) {
  if (typeof spec !== 'string') return null;
  const s = spec.trim();
  if (eco === 'pypi') return pySatisfies(version, s);
  if (eco !== 'npm' && eco !== 'crates') return null;
  const sets = eco === 'npm' ? parseNpmRange(s) : parseCargoReq(s || '*');
  if (!sets) return null;
  const v = parseSemver(version);
  if (!v) return false;
  return sets.some((set) => testSet(set, v));
}

module.exports = { compareSemver, comparePep440, compare, isPrerelease, satisfies, parseSemver, parsePep440 };
