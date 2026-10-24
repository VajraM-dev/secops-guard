'use strict';
// Injected deps for decide() tests: no network, no real cache, no scanners.

const RANK = { LOW: 1, MODERATE: 2, HIGH: 3, CRITICAL: 4, MALICIOUS: 5 };

function cfg(over = {}) {
  return {
    cooldownDays: 7, packageSeverityBlock: 'ANY', lockfileSeverityBlock: 'HIGH', imageSeverityBlock: 'HIGH', failOpen: false,
    allow: new Set(), allowRegistries: ['registry.npmjs.org', 'pypi.org', 'files.pythonhosted.org', 'crates.io'], stateDir: 'unused',
    ...over,
  };
}

// registry: {"eco:name": version | {error, detail} | Error}; vulns: {"eco:name@ver": Vuln[]}
function fakes({ registry = {}, vulns = {}, config = {}, lockfiles = {}, scanner, osvError, images = [] } = {}) {
  const calls = { resolve: [], osv: [], cached: [], scan: [] };
  const deps = {
    loadConfig: () => cfg(config),
    isAllowed: (c, eco, name, ver) => c.allow.has(`${eco}:${name}`) || (ver != null && c.allow.has(`${eco}:${name}@${ver}`)),
    resolveVersion: async (eco, name, spec, days) => {
      calls.resolve.push({ eco, name, spec, days });
      const r = registry[`${eco}:${name}`];
      if (r instanceof Error) throw r;
      if (r === undefined) return { error: 'not_found', detail: `${name} not found in ${eco} registry` };
      return typeof r === 'string' ? { version: r, publishedAt: new Date(0) } : r;
    },
    queryPackages: async (pkgs) => {
      calls.osv.push(pkgs);
      if (osvError) throw osvError;
      return new Map(pkgs.map((p) => { const k = `${p.ecosystem}:${p.name}@${p.version}`; return [k, vulns[k] || []]; }));
    },
    atLeast: (sev, th) => th === 'ANY' || sev === 'MALICIOUS' || (RANK[sev] || 3) >= (RANK[th] || 3),
    satisfies: (eco, v, spec) => (/^[\^~<>=!*\d]/.test(spec) || spec === '' ? true : null),
    parseLockfile: (f) => { const k = Object.keys(lockfiles).find((n) => f.endsWith(n)); if (!k) return []; if (lockfiles[k] instanceof Error) throw lockfiles[k]; return lockfiles[k]; },
    findLockfiles: (dir) => Object.keys(lockfiles).map((n) => require('node:path').join(dir, n)),
    cached: async (key, ttl, fn) => { calls.cached.push(key); return fn(); },
    runScanner: async (img) => { calls.scan.push(img); if (scanner instanceof Error) throw scanner; return scanner ? scanner(img) : null; },
    isFloatingTag: require('../../lib/docker').isFloatingTag,
    composeImages: () => images,
    now: () => 0,
  };
  return { deps, calls };
}

const throwing = new Proxy({}, { get: (_, k) => () => { throw new Error(`dep ${String(k)} must not be used`); }, has: () => true });

module.exports = { fakes, cfg, throwing };
