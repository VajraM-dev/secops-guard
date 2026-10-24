'use strict';
// Config + allowlist. config.json is user-edited only; a broken file must never break hooks.

const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');

const SEVERITIES = ['ANY', 'LOW', 'MODERATE', 'HIGH', 'CRITICAL'];
const DEFAULTS = {
  cooldownDays: 7,
  packageSeverityBlock: 'ANY',
  lockfileSeverityBlock: 'HIGH',
  imageSeverityBlock: 'HIGH',
  failOpen: false,
  allow: [],
  allowRegistries: ['registry.npmjs.org', 'pypi.org', 'files.pythonhosted.org', 'download.pytorch.org', 'crates.io', 'index.crates.io'],
};

const stateDir = () => process.env.SECOPS_STATE_DIR || path.join(os.homedir(), '.claude', 'secops-guard');

// PEP 503; npm/crates names compared as-is except crates, which the registry treats case-insensitively.
function normName(eco, name) {
  if (eco === 'pypi') return String(name).toLowerCase().replace(/[-_.]+/g, '-');
  if (eco === 'crates') return String(name).toLowerCase().replace(/_/g, '-');
  return String(name);
}

function normEntry(entry) {
  const m = /^(npm|pypi|crates|image):(.+)$/.exec(String(entry).trim());
  if (!m) return null;
  const [, eco, rest] = m;
  if (eco === 'image') return `image:${rest}`;
  // '@' at index 0 is an npm scope, not a version separator
  const at = rest.indexOf('@', 1);
  const name = at === -1 ? rest : rest.slice(0, at);
  const ver = at === -1 ? '' : rest.slice(at);
  return `${eco}:${normName(eco, name)}${ver}`;
}

function loadConfig() {
  const dir = stateDir();
  let user = {};
  try {
    const raw = fs.readFileSync(path.join(dir, 'config.json'), 'utf8');
    user = JSON.parse(raw);
    if (!user || typeof user !== 'object' || Array.isArray(user)) throw new Error('not an object');
  } catch (e) {
    if (e.code !== 'ENOENT') process.stderr.write(`secops-guard: ignoring malformed config.json (${e.message})\n`);
    user = {};
  }
  const pick = (k, ok) => (k in user && ok(user[k]) ? user[k] : DEFAULTS[k]);
  const isSev = (v) => SEVERITIES.includes(v);
  const cfg = {
    cooldownDays: pick('cooldownDays', (v) => Number.isFinite(v) && v >= 0),
    packageSeverityBlock: pick('packageSeverityBlock', isSev),
    lockfileSeverityBlock: pick('lockfileSeverityBlock', isSev),
    imageSeverityBlock: pick('imageSeverityBlock', isSev),
    failOpen: pick('failOpen', (v) => typeof v === 'boolean'),
    allow: new Set(pick('allow', Array.isArray).map(normEntry).filter(Boolean)),
    allowRegistries: pick('allowRegistries', (v) => Array.isArray(v) && v.every((s) => typeof s === 'string')),
    stateDir: dir,
  };
  const envDays = Number(process.env.SECOPS_COOLDOWN_DAYS);
  if (process.env.SECOPS_COOLDOWN_DAYS && Number.isFinite(envDays) && envDays >= 0) cfg.cooldownDays = envDays;
  if (process.env.SECOPS_FAIL_OPEN === '1') cfg.failOpen = true;
  return cfg;
}

function isAllowed(cfg, ecosystem, name, version) {
  const base = `${ecosystem}:${normName(ecosystem, name)}`;
  return cfg.allow.has(base) || (version != null && version !== '' && cfg.allow.has(`${base}@${version}`));
}

module.exports = { loadConfig, isAllowed, stateDir, normName };
