'use strict';
// OSV.dev lookups: querybatch (ids only) then per-id details, normalised to {id, aliases, summary, severity, fixed}.

const { cached } = require('./cache');
const { fetchJson } = require('./registries');
const { compare } = require('./versions');

const API = 'https://api.osv.dev/v1';
const OSV_ECO = { npm: 'npm', pypi: 'PyPI', crates: 'crates.io' };
const RANK = { LOW: 1, MODERATE: 2, HIGH: 3, CRITICAL: 4, MALICIOUS: 5 };
const DETAIL_TTL = 6 * 3600000;
const BATCH_TTL = 6 * 3600000;
const BATCH = 500;
const MAX_PAGES = 20;

const keyOf = (p) => `${p.ecosystem}:${p.name}@${p.version}`;
const normName = (eco, n) => (eco === 'pypi' ? n.toLowerCase().replace(/[-_.]+/g, '-') : n);

// ---------- CVSS v3.x base score ----------
const W = {
  AV: { N: 0.85, A: 0.62, L: 0.55, P: 0.2 },
  AC: { L: 0.77, H: 0.44 },
  UI: { N: 0.85, R: 0.62 },
  CIA: { H: 0.56, L: 0.22, N: 0 },
};

function roundup(x) {
  const i = Math.round(x * 100000);
  return i % 10000 === 0 ? i / 100000 : (Math.floor(i / 10000) + 1) / 10;
}

function cvss3Score(vector) {
  if (!/^CVSS:3\.[01]\//.test(vector)) return null;
  const m = {};
  for (const part of vector.split('/').slice(1)) {
    const [k, v] = part.split(':');
    m[k] = v;
  }
  const changed = m.S === 'C';
  const pr = { N: 0.85, L: changed ? 0.68 : 0.62, H: changed ? 0.5 : 0.27 }[m.PR];
  const vals = [W.AV[m.AV], W.AC[m.AC], pr, W.UI[m.UI], W.CIA[m.C], W.CIA[m.I], W.CIA[m.A]];
  if (vals.some((v) => v === undefined) || (m.S !== 'U' && m.S !== 'C')) return null;
  const [av, ac, p, ui, c, i, a] = vals;
  const iss = 1 - (1 - c) * (1 - i) * (1 - a);
  const impact = changed ? 7.52 * (iss - 0.029) - 3.25 * (iss - 0.02) ** 15 : 6.42 * iss;
  if (impact <= 0) return 0;
  const expl = 8.22 * av * ac * p * ui;
  return roundup(Math.min((changed ? 1.08 : 1) * (impact + expl), 10));
}

const fromScore = (s) => (s >= 9 ? 'CRITICAL' : s >= 7 ? 'HIGH' : s >= 4 ? 'MODERATE' : 'LOW');

function normSev(s) {
  const u = typeof s === 'string' ? s.trim().toUpperCase() : '';
  if (u === 'MEDIUM') return 'MODERATE';
  return ['LOW', 'MODERATE', 'HIGH', 'CRITICAL'].includes(u) ? u : null;
}

// GHSA/OSV malware entries read "Malicious code in X"; plain "a malicious user could…" must not match
const MALICIOUS_TEXT = /\bmalicious (?:code|package)\b/i;

function severityOf(v) {
  const ids = [v.id, ...(v.aliases || [])];
  const db = v.database_specific || {};
  // CWE-506 = Embedded Malicious Code (GHSA tags malware advisories with it)
  if (ids.some((id) => typeof id === 'string' && id.startsWith('MAL-')) || MALICIOUS_TEXT.test(v.summary || '')
    || (Array.isArray(db.cwe_ids) && db.cwe_ids.includes('CWE-506'))) return 'MALICIOUS';
  const ds = normSev(db.severity);
  if (ds) return ds;
  for (const a of v.affected || []) {
    const s = normSev(a.ecosystem_specific && a.ecosystem_specific.severity) || normSev(a.database_specific && a.database_specific.severity);
    if (s) return s;
  }
  for (const s of v.severity || []) {
    const score = s.type === 'CVSS_V3' ? cvss3Score(String(s.score)) : null;
    if (score !== null) return fromScore(score);
  }
  return 'HIGH'; // unknown counts as HIGH (CONTRACT); covers CVSS v4-only entries
}

// Lowest fix above the installed version; falls back to the first fix listed.
function fixedFor(v, pkg) {
  const fixes = [];
  for (const a of v.affected || []) {
    const p = a.package || {};
    if (p.ecosystem !== OSV_ECO[pkg.ecosystem] || normName(pkg.ecosystem, p.name || '') !== normName(pkg.ecosystem, pkg.name)) continue;
    for (const r of a.ranges || []) for (const e of r.events || []) if (e.fixed) fixes.push(e.fixed);
  }
  if (!fixes.length) return null;
  const above = fixes.filter((f) => compare(pkg.ecosystem, f, pkg.version) > 0).sort((x, y) => compare(pkg.ecosystem, x, y));
  return above[0] || fixes[0];
}

async function mapLimit(items, limit, fn) {
  const out = new Array(items.length);
  let next = 0;
  const worker = async () => { while (next < items.length) { const i = next++; out[i] = await fn(items[i]); } };
  await Promise.all(Array.from({ length: Math.min(limit, items.length) }, worker));
  return out;
}

async function queryIds(pkgs, opts) {
  const ids = pkgs.map(() => new Set());
  for (let start = 0; start < pkgs.length; start += BATCH) {
    let pending = pkgs.slice(start, start + BATCH).map((p, j) => ({ idx: start + j, p, token: undefined }));
    for (let page = 0; pending.length; page++) {
      if (page >= MAX_PAGES) throw new Error('OSV pagination did not terminate');
      const body = {
        queries: pending.map(({ p, token }) => ({
          package: { ecosystem: OSV_ECO[p.ecosystem], name: p.name },
          version: p.version,
          ...(token ? { page_token: token } : {}),
        })),
      };
      const res = await fetchJson(`${API}/querybatch`, { timeoutMs: 20000, ...opts }, {
        method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body),
      });
      if (!res || !Array.isArray(res.results) || res.results.length !== pending.length) throw new Error('unexpected OSV querybatch response');
      const again = [];
      res.results.forEach((r, j) => {
        for (const v of (r && r.vulns) || []) if (v && v.id) ids[pending[j].idx].add(v.id);
        if (r && r.next_page_token) again.push({ ...pending[j], token: r.next_page_token });
      });
      pending = again;
    }
  }
  return ids;
}

function getVuln(id, opts) {
  if (!/^[A-Za-z0-9][A-Za-z0-9._:-]*$/.test(id)) throw new Error(`bad OSV id ${id}`);
  return cached(`osv:vuln:${id}`, DETAIL_TTL, async () => {
    const v = await fetchJson(`${API}/vulns/${encodeURIComponent(id)}`, opts);
    if (!v) throw new Error(`OSV vuln ${id} not found`);
    return v;
  });
}

async function queryPackages(pkgs, opts = {}) {
  // sorted so the batch cache key depends only on the package set, not input order
  const uniq = [...new Map(pkgs.filter((p) => OSV_ECO[p.ecosystem] && p.name && p.version).map((p) => [keyOf(p), p])).values()]
    .sort((a, b) => (keyOf(a) < keyOf(b) ? -1 : 1));
  const result = new Map(uniq.map((p) => [keyOf(p), []]));
  if (!uniq.length) return result;
  const ids = await cached(`osv:batch:${uniq.map(keyOf).join('\n')}`, BATCH_TTL, async () => (await queryIds(uniq, opts)).map((s) => [...s]));
  const allIds = [...new Set(ids.flatMap((s) => [...s]))];
  const details = new Map((await mapLimit(allIds, 8, (id) => getVuln(id, opts))).map((v, i) => [allIds[i], v]));
  uniq.forEach((p, i) => {
    result.set(keyOf(p), [...ids[i]].map((id) => {
      const v = details.get(id);
      return { id, aliases: v.aliases || [], summary: v.summary || (v.details || '').slice(0, 200), severity: severityOf(v), fixed: fixedFor(v, p) };
    }));
  });
  return result;
}

function atLeast(severity, threshold) {
  if (threshold === 'ANY' || severity === 'MALICIOUS') return true;
  return (RANK[severity] || RANK.HIGH) >= (RANK[threshold] || RANK.HIGH);
}

module.exports = { queryPackages, atLeast, severityOf, cvss3Score, fixedFor, OSV_ECO, mapLimit };
