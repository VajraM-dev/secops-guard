'use strict';
// Side B scanning: what a build PRODUCES (bundle, wheel, image layer), not what was installed.
// Only trivy does filesystem secret scanning, so fs scans need trivy specifically; image vulnerability
// scanning still falls back to grype / docker scout through lib/docker.js.
// Scanners run with argument arrays (never a shell string).

const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { spawnSync } = require('node:child_process');
const docker = require('./docker');

const { which, normSeverity, parseReport } = docker;

// winget and homebrew install trivy outside the PATH a hook process inherits
function trivyDirs(env) {
  const dirs = [];
  const home = env.USERPROFILE || env.HOME || os.homedir();
  const pkgs = path.join(home, 'AppData', 'Local', 'Microsoft', 'WinGet', 'Packages');
  try {
    for (const d of fs.readdirSync(pkgs)) if (d.startsWith('AquaSecurity.Trivy')) dirs.push(path.join(pkgs, d));
  } catch { /* not Windows, or no winget */ }
  dirs.push('/opt/homebrew/bin', '/usr/local/bin', '/usr/bin');
  return dirs;
}

let memo;
function findTrivy({ env = process.env } = {}) {
  if (memo !== undefined && env === process.env) return memo;
  let bin = which('trivy', env);
  if (!bin) {
    const exe = process.platform === 'win32' ? 'trivy.exe' : 'trivy';
    for (const d of trivyDirs(env)) {
      const p = path.join(d, exe);
      try { if (fs.statSync(p).isFile()) { bin = p; break; } } catch { /* next */ }
    }
  }
  const r = bin ? { name: 'trivy', bin } : null;
  if (env === process.env) memo = r;
  return r;
}

// trivy first: it is the only one of the three that reports secrets
const findScanner = (opts = {}) => findTrivy(opts) || docker.findScanner(opts);

// A finding must carry enough to fix it and nothing of the value itself: trivy's own Match
// keeps the last characters of the secret in clear, so Match and Code are never read here.
const LONG = /[A-Za-z0-9_\-+/=]{16,}/g;
const redact = (s) => String(s == null ? '' : s).replace(LONG, '***').slice(0, 120);

function parseSecrets(data) {
  const out = [];
  const seen = new Set();
  for (const r of data.Results || []) {
    for (const s of r.Secrets || []) {
      const target = String(r.Target || '').slice(0, 200);
      const line = Number(s.StartLine) || 0;
      const rule = redact(s.RuleID) || 'unknown';
      const k = `${target}|${rule}|${line}`;
      if (seen.has(k)) continue;
      seen.add(k);
      out.push({ rule, severity: normSeverity(s.Severity), title: redact(s.Title), target, line });
    }
  }
  return out;
}

const safeTarget = (t, what) => {
  if (typeof t !== 'string' || !t || t[0] === '-') throw new Error(`invalid ${what} ${JSON.stringify(t)}`);
  return t;
};

function run(scanner, args, timeoutMs, spawn) {
  const r = spawn(scanner.bin, args, { encoding: 'utf8', timeout: timeoutMs, maxBuffer: 256 * 1024 * 1024, windowsHide: true });
  if (r.error) throw new Error(`${scanner.name} failed: ${r.error.code || r.error.message}`);
  if (r.status !== 0) throw new Error(`${scanner.name} exited ${r.status}: ${String(r.stderr || '').replace(/\s+/g, ' ').trim().slice(0, 300)}`);
  return JSON.parse(r.stdout);
}

// null = no trivy; throws when the scan itself fails. `target` may be a directory or a single file.
function scanFs(target, { scanners = 'secret,vuln', skipDirs = [], timeoutMs = 90000, scanner = findTrivy(), spawn = spawnSync } = {}) {
  if (!scanner || scanner.name !== 'trivy') return null;
  const args = ['fs', '--quiet', '--format', 'json', '--scanners', String(scanners)];
  for (const d of skipDirs) args.push('--skip-dirs', safeTarget(d, 'skip-dir'));
  args.push(safeTarget(target, 'scan path'));
  const data = run(scanner, args, timeoutMs, spawn);
  return { scanner: 'trivy', vulns: parseReport('trivy', data), secrets: parseSecrets(data) };
}

// Same contract as docker.scanImage but also returns secrets when trivy is the scanner.
function scanImage(image, { timeoutMs = 90000, scanner = findScanner(), spawn = spawnSync } = {}) {
  if (!scanner) return null;
  if (scanner.name !== 'trivy') {
    const r = docker.scanImage(image, { timeoutMs, scanner, spawn });
    return r && { ...r, secrets: [] };
  }
  const data = run(scanner, ['image', '--quiet', '--format', 'json', '--scanners', 'vuln,secret', safeTarget(image, 'image reference')], timeoutMs, spawn);
  return { scanner: 'trivy', vulns: parseReport('trivy', data), secrets: parseSecrets(data) };
}

// Cheap identity for a build output, so a build/publish pair scans once. Bounded: a release
// `target/` can hold hundreds of thousands of files and this must stay far cheaper than the scan.
function fingerprintDir(target, skipDirs = [], limit = 5000) {
  const skip = new Set([...skipDirs, '.git']);
  let newest = 0;
  let count = 0;
  const walk = (d) => {
    let ents;
    try { ents = fs.readdirSync(d, { withFileTypes: true }); } catch { return; }
    for (const e of ents) {
      if (count >= limit) return;
      const p = path.join(d, e.name);
      if (e.isDirectory()) { if (!skip.has(e.name)) walk(p); continue; }
      if (!e.isFile()) continue;
      count++;
      try { const m = fs.statSync(p).mtimeMs; if (m > newest) newest = m; } catch { /* unreadable */ }
    }
  };
  let st;
  try { st = fs.statSync(target); } catch { return `${path.resolve(target)}|missing`; }
  if (st.isDirectory()) walk(target);
  else { newest = st.mtimeMs; count = 1; }
  return `${path.resolve(target)}|${Math.round(newest)}|${count}`;
}

module.exports = { ...docker, findTrivy, findScanner, scanFs, scanImage, parseSecrets, fingerprintDir, redact };
