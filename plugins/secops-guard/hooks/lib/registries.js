'use strict';
// Registry metadata (npm / PyPI / crates.io) and cooldown-aware version resolution.
// Network errors throw; callers decide fail-open vs deny. 404 means "package does not exist".

const { cached } = require('./cache');
const { compare, isPrerelease, satisfies, parseSemver, parsePep440 } = require('./versions');

const UA = 'secops-guard/0.1 (Claude Code plugin)';
const DAY = 86400000;
const REGISTRY_TTL = 3600000;

// Strict name grammars: anything else (spaces, shell metachars, '..', slashes) never reaches a URL.
const NAME_RE = {
  npm: /^(?:@[a-z0-9~-][a-z0-9._~-]*\/)?[a-z0-9~-][a-z0-9._~-]*$/i,
  pypi: /^[A-Za-z0-9](?:[A-Za-z0-9._-]*[A-Za-z0-9])?$/,
  crates: /^[A-Za-z][A-Za-z0-9_-]*$/,
};
const validName = (eco, name) => typeof name === 'string' && name.length <= 214 && !!NAME_RE[eco] && NAME_RE[eco].test(name);
const pep503 = (name) => name.toLowerCase().replace(/[-_.]+/g, '-');

async function fetchJson(url, opts = {}, init = {}) {
  const { fetchImpl = fetch, timeoutMs = 10000 } = opts;
  const res = await fetchImpl(url, {
    ...init,
    headers: { 'User-Agent': UA, Accept: 'application/json', ...(init.headers || {}) },
    signal: AbortSignal.timeout(timeoutMs),
  });
  if (res.status === 404) return null;
  if (!res.ok) throw new Error(`HTTP ${res.status} from ${new URL(url).host}`);
  return res.json();
}

const ADAPTERS = {
  npm: {
    // full documents (needed for `time`) run to many MB for popular packages
    timeoutMs: 30000,
    url: (n) => `https://registry.npmjs.org/${n.replace('/', '%2f')}`,
    list(doc) {
      if (!doc || !doc.versions || typeof doc.versions !== 'object') return null;
      const time = doc.time || {};
      // versions missing from `versions` were unpublished; deprecated is not yanked
      return Object.keys(doc.versions).filter((v) => time[v]).map((v) => ({ version: v, publishedAt: time[v], yanked: false }));
    },
  },
  pypi: {
    url: (n) => `https://pypi.org/pypi/${pep503(n)}/json`,
    list(doc) {
      if (!doc || !doc.releases || typeof doc.releases !== 'object') return null;
      const out = [];
      for (const [v, files] of Object.entries(doc.releases)) {
        if (!Array.isArray(files) || !files.length) continue;
        const times = files.map((f) => f.upload_time_iso_8601 || f.upload_time).filter(Boolean).sort();
        if (!times.length) continue;
        out.push({ version: v, publishedAt: times[0], yanked: files.every((f) => f.yanked === true) });
      }
      return out;
    },
  },
  crates: {
    url: (n) => `https://crates.io/api/v1/crates/${n}`,
    list(doc) {
      if (!doc || !Array.isArray(doc.versions)) return null;
      return doc.versions.filter((v) => v && v.num && v.created_at).map((v) => ({ version: v.num, publishedAt: v.created_at, yanked: !!v.yanked }));
    },
  },
};

async function getPackageVersions(ecosystem, name, opts = {}) {
  const ad = ADAPTERS[ecosystem];
  if (!ad) throw new Error(`unsupported ecosystem ${ecosystem}`);
  if (!validName(ecosystem, name)) return null;
  const key = `registry:${ecosystem}:${ecosystem === 'pypi' ? pep503(name) : name}`;
  // cache holds only the extracted {version, publishedAt ISO, yanked} list, never the raw document
  const fetchOpts = ad.timeoutMs ? { timeoutMs: ad.timeoutMs, ...opts } : opts;
  const list = await cached(key, REGISTRY_TTL, async () => ad.list(await fetchJson(ad.url(name), fetchOpts)));
  if (!list) return null;
  return list
    .map((v) => ({ version: v.version, publishedAt: new Date(v.publishedAt), yanked: v.yanked }))
    .filter((v) => !Number.isNaN(v.publishedAt.getTime()));
}

function exactPin(ecosystem, spec) {
  if (ecosystem === 'pypi') {
    const m = /^(?:===?\s*)?([^\s,*=<>!~]+)$/.exec(spec);
    return m && parsePep440(m[1]) ? m[1] : null;
  }
  // cargo: a bare "1.2.3" is a caret requirement, only "=1.2.3" pins
  const m = ecosystem === 'crates' ? /^=\s*(\S+)$/.exec(spec) : /^=?\s*(\S+)$/.exec(spec);
  return m && parseSemver(m[1]) ? m[1].replace(/^v/, '') : null;
}

const newest = (eco, list) => list.reduce((best, v) => (!best || compare(eco, v.version, best.version) > 0 ? v : best), null);

async function resolveVersion(ecosystem, name, spec, cooldownDays, opts = {}) {
  const now = opts.now === undefined ? Date.now() : +opts.now;
  const list = await getPackageVersions(ecosystem, name, opts);
  if (!list) return { error: 'not_found', detail: validName(ecosystem, name) ? `${name} not found in ${ecosystem} registry` : `invalid package name ${JSON.stringify(name)}` };
  const cutoff = now - cooldownDays * DAY;
  const oldEnough = (v) => v.publishedAt.getTime() <= cutoff;
  const stable = list.filter((v) => !v.yanked && !isPrerelease(ecosystem, v.version));
  const pick = (pred) => newest(ecosystem, stable.filter((v) => oldEnough(v) && pred(v)));
  const out = (v) => ({ version: v.version, publishedAt: v.publishedAt });

  let s = typeof spec === 'string' ? spec.trim() : '';
  // dist-tags and other bare words cannot be checked against a list; treat as "latest"
  if (s === 'latest' || (/^[A-Za-z][A-Za-z0-9._-]*$/.test(s) && satisfies(ecosystem, '0.0.0', s) === null)) s = '';

  const pin = s && exactPin(ecosystem, s);
  if (pin) {
    // pin always parses, so compare()===0 implies an equivalent parseable version ("1.0" == "1.0.0" on PyPI)
    const hit = list.find((v) => v.version === pin) || list.find((v) => compare(ecosystem, v.version, pin) === 0);
    if (!hit) return { error: 'no_match', detail: `${name}@${pin} does not exist` };
    if (hit.yanked) return { error: 'no_match', detail: `${name}@${hit.version} is yanked` };
    if (!oldEnough(hit)) {
      const sug = pick(() => true);
      return { error: 'too_new', detail: { version: hit.version, publishedAt: hit.publishedAt, suggestion: sug ? sug.version : null } };
    }
    return out(hit);
  }

  if (satisfies(ecosystem, '0.0.0', s) === null) return { error: 'no_match', detail: 'unsupported range; pin an exact version' };
  const best = pick((v) => satisfies(ecosystem, v.version, s) === true);
  if (best) return out(best);
  const anyMatch = stable.some((v) => satisfies(ecosystem, v.version, s) === true);
  return {
    error: 'no_match',
    detail: anyMatch
      ? `every version of ${name} matching "${s}" is younger than ${cooldownDays} days`
      : `no released version of ${name} matches "${s || 'latest'}"`,
  };
}

module.exports = { getPackageVersions, resolveVersion, fetchJson, validName, UA };
