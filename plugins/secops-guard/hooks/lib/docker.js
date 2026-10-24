'use strict';
// Container image scanning through whichever scanner is installed (grype > trivy > docker scout).
// Scanners run with argument arrays (never a shell string). Parsers follow each tool's documented JSON.

const fs = require('node:fs');
const path = require('node:path');
const { spawnSync } = require('node:child_process');

function which(bin, env = process.env) {
  // .cmd/.bat cannot be spawned without a shell, and every scanner ships a real .exe on Windows
  const exts = process.platform === 'win32' ? ['.exe'] : [''];
  for (const dir of String(env.PATH || '').split(path.delimiter)) {
    if (!dir) continue;
    for (const e of exts) {
      const p = path.join(dir, bin + e);
      try { if (fs.statSync(p).isFile()) return p; } catch { /* next */ }
    }
  }
  return null;
}

let memo;
function findScanner({ env = process.env, spawn = spawnSync } = {}) {
  if (memo !== undefined && env === process.env) return memo;
  let found = null;
  for (const name of ['grype', 'trivy']) {
    const bin = which(name, env);
    if (bin) { found = { name, bin }; break; }
  }
  if (!found) {
    const bin = which('docker', env);
    if (bin && spawn(bin, ['scout', 'version'], { timeout: 10000, stdio: 'ignore', windowsHide: true }).status === 0) found = { name: 'docker-scout', bin };
  }
  if (env === process.env) memo = found;
  return found;
}

function normSeverity(s) {
  const u = String(s || '').toUpperCase();
  if (u === 'CRITICAL' || u === 'HIGH' || u === 'LOW') return u;
  if (u === 'MEDIUM' || u === 'MODERATE') return 'MODERATE';
  if (u === 'NEGLIGIBLE' || u === 'INFO') return 'LOW';
  return 'HIGH'; // unknown counts as HIGH (CONTRACT)
}

const ARGS = {
  grype: (img) => [img, '-o', 'json', '-q'],
  trivy: (img) => ['image', '--quiet', '--format', 'json', img],
  'docker-scout': (img) => ['scout', 'cves', '--format', 'gitlab', img],
};

const PARSE = {
  grype: (d) => (d.matches || []).map((m) => ({ id: m.vulnerability && m.vulnerability.id, severity: m.vulnerability && m.vulnerability.severity, pkg: m.artifact && m.artifact.name })),
  trivy: (d) => (d.Results || []).flatMap((r) => (r.Vulnerabilities || []).map((v) => ({ id: v.VulnerabilityID, severity: v.Severity, pkg: v.PkgName }))),
  // GitLab container-scanning report schema. Written from documentation only and never verified against
  // real `docker scout cves --format gitlab` output (scout needs a Docker login); treat as unexercised.
  'docker-scout': (d) => (d.vulnerabilities || []).map((v) => ({
    id: (v.identifiers && v.identifiers[0] && v.identifiers[0].value) || v.name || v.id,
    severity: v.severity,
    pkg: v.location && v.location.dependency && v.location.dependency.package && v.location.dependency.package.name,
  })),
};

// accepts the raw JSON text or an already-parsed report (lib/scan.js reads secrets from the same object)
function parseReport(scanner, text) {
  const seen = new Set();
  return PARSE[scanner](typeof text === 'string' ? JSON.parse(text) : text)
    .filter((v) => v.id)
    .map((v) => ({ id: String(v.id), severity: normSeverity(v.severity), pkg: v.pkg || '' }))
    .filter((v) => { const k = `${v.id}|${v.pkg}`; if (seen.has(k)) return false; seen.add(k); return true; });
}

// null = no usable scanner; throws when the scan itself fails
function scanImage(image, { timeoutMs = 90000, scanner = findScanner(), spawn = spawnSync } = {}) {
  if (!scanner) return null;
  if (typeof image !== 'string' || !image || image[0] === '-') throw new Error(`invalid image reference ${JSON.stringify(image)}`);
  const r = spawn(scanner.bin, ARGS[scanner.name](image), { encoding: 'utf8', timeout: timeoutMs, maxBuffer: 256 * 1024 * 1024, windowsHide: true });
  if (r.error) throw new Error(`${scanner.name} failed: ${r.error.code || r.error.message}`);
  if (r.status !== 0) {
    const err = String(r.stderr || '').replace(/\s+/g, ' ').trim();
    // scout needs a Docker Hub login; that is a missing scanner, not a failed scan
    if (scanner.name === 'docker-scout' && /log ?in|authenticat/i.test(err)) return null;
    throw new Error(`${scanner.name} exited ${r.status}: ${err.slice(0, 300)}`);
  }
  return { scanner: scanner.name, vulns: parseReport(scanner.name, r.stdout) };
}

function isFloatingTag(image) {
  if (image.includes('@sha256:')) return false;
  const last = image.slice(image.lastIndexOf('/') + 1);
  const c = last.indexOf(':');
  return c === -1 || last.slice(c + 1) === 'latest';
}

const COMPOSE_FILES = ['compose.yaml', 'compose.yml', 'docker-compose.yml', 'docker-compose.yaml'];

// shortcut: line-based `image:` scan, ignores extends/includes and ${VAR} images; upgrade if compose gating matters more
function composeImages(dir, files = []) {
  const list = files.length ? files : COMPOSE_FILES;
  const out = new Set();
  for (const f of list) {
    let text;
    try { text = fs.readFileSync(path.resolve(dir, f), 'utf8'); } catch { continue; }
    for (const line of text.split('\n')) {
      const m = /^\s*image:\s*["']?([^\s"'#]+)/.exec(line);
      if (m && !m[1].includes('$')) out.add(m[1]);
    }
    if (!files.length) break; // compose uses the first default file it finds
  }
  return [...out];
}

module.exports = { findScanner, scanImage, isFloatingTag, composeImages, parseReport, normSeverity, which };
