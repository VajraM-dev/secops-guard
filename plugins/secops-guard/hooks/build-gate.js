#!/usr/bin/env node
'use strict';
// Side B gate: what the user BUILDS and SHIPS, as opposed to what dep-gate lets them install.
// PostToolUse (Bash|PowerShell) after a build, PreToolUse before a publish.
//
// Policy (user-chosen, do not soften): CVEs in the artifact are REPORTED and never blocked.
// A secret baked into the artifact is DENIED, always - a published bundle or pushed image layer
// cannot be unpublished, and the secret is compromised from the moment it was written into it.
// No scanner, or a scan that runs out of budget, is context only: a finding we never got is not
// a finding, and a slow scan must not block a publish when CVEs would not have blocked it either.

const fs = require('node:fs');
const path = require('node:path');
const { splitSegments, tokenize, parseInstallIntents } = require('./lib/parse-command');
const { failed } = require('./post-install-scan');

// PostToolUse payloads carry tool_response; PreToolUse ones do not
const isPreToolUse = (p) => (p.hook_event_name ? p.hook_event_name === 'PreToolUse' : !('tool_response' in p));

const TTL = 10 * 60e3;
const budgetMs = () => Number(process.env.SECOPS_BUILD_BUDGET_MS) || 90000;

const LIB = {
  findScanner: () => require('./lib/scan').findScanner,
  scanFs: () => require('./lib/scan').scanFs,
  scanImage: () => require('./lib/scan').scanImage,
  fingerprintDir: () => require('./lib/scan').fingerprintDir,
  loadConfig: () => require('./lib/config').loadConfig,
  cached: () => require('./lib/cache').cached,
  now: () => () => Date.now(),
};

function withDeps(deps = {}) {
  const d = { ...deps };
  for (const k of Object.keys(LIB)) if (!(k in d)) d[k] = LIB[k]();
  return d;
}

// ---------- command detection ----------

const cmdName = (v) => String(v).replace(/\\/g, '/').split('/').pop().toLowerCase().replace(/\.(?:exe|cmd|bat|ps1)$/, '');
const ENV_ASSIGN = /^[A-Za-z_][A-Za-z0-9_]*=/;
const PREFIX = new Set(['sudo', 'doas', 'env', 'time', 'nohup', 'exec', 'command', 'npx', 'pnpx', 'bunx']);
const JS_MGR = new Set(['npm', 'pnpm', 'yarn', 'bun']);
const JS_BIN = new Set(['vite', 'next', 'astro', 'nuxt', 'remix', 'rollup', 'webpack', 'esbuild', 'parcel', 'tsup', 'ng']);

// drop env assignments and wrappers so `sudo npx vite build` reaches `vite build`
function head(toks) {
  let i = 0;
  while (i < toks.length && toks[i] && (ENV_ASSIGN.test(toks[i]) || PREFIX.has(cmdName(toks[i])) || (i > 0 && toks[i][0] === '-'))) i++;
  return toks.slice(i);
}

// 'js' | 'py' | 'rust' | null - a command that plausibly wrote an artifact to disk
function buildKind(toks) {
  const t = head(toks);
  if (!t.length) return null;
  const c = cmdName(t[0]);
  const args = t.slice(1).filter((a) => a[0] !== '-');
  if (JS_MGR.has(c)) {
    const s = args[0] === 'run' || args[0] === 'run-script' ? args[1] : args[0];
    return s && /^build(?::|$)/.test(s) ? 'js' : null;
  }
  if (JS_BIN.has(c)) return args.includes('build') ? 'js' : null;
  if (c === 'poetry' || c === 'hatch' || c === 'uv') return args[0] === 'build' ? 'py' : null;
  if (c === 'pip' || c === 'pip3') return args[0] === 'wheel' ? 'py' : null;
  if (/^(?:python\d*(?:\.\d+)?|py)$/.test(c)) {
    const m = t.indexOf('-m');
    if (m !== -1 && t[m + 1] === 'build') return 'py';
    return args[0] === 'setup.py' && args.some((a) => /^(?:bdist|sdist)/.test(a)) ? 'py' : null;
  }
  if (c === 'cargo') {
    if (args[0] === 'build' && t.includes('--release')) return 'rust';
    if (args[0] === 'publish' && t.includes('--dry-run')) return 'rust';
  }
  return null;
}

// the irreversible, outward-facing step
function publishKind(toks) {
  const t = head(toks);
  if (!t.length) return null;
  const c = cmdName(t[0]);
  const args = t.slice(1).filter((a) => a[0] !== '-');
  if (c === 'docker' || c === 'podman') {
    const off = args[0] === 'image' ? 1 : 0;
    return args[off] === 'push' && args[off + 1] ? { kind: 'image', tag: args[off + 1] } : null;
  }
  if (JS_MGR.has(c)) {
    const i = c === 'yarn' && args[0] === 'npm' ? 1 : 0;
    return args[i] === 'publish' ? { kind: 'js' } : null;
  }
  if (c === 'twine') return args[0] === 'upload' ? { kind: 'py' } : null; // the uploaded paths are globs we cannot expand; dist/ is what twine builds from
  if (c === 'poetry' || c === 'hatch' || c === 'uv') return args[0] === 'publish' ? { kind: 'py' } : null;
  if (c === 'cargo') return args[0] === 'publish' && !t.includes('--dry-run') ? { kind: 'rust' } : null;
  if (c === 'gh') return args[0] === 'release' && args[1] === 'upload' ? { kind: 'files', files: args.slice(3) } : null;
  return null;
}

function targets(cmd, wantPublish) {
  const out = [];
  if (!wantPublish) for (const it of parseInstallIntents(cmd)) if (it.kind === 'build') out.push({ kind: 'image', tag: it.tag, docker: true });
  for (const seg of splitSegments(cmd)) {
    const toks = tokenize(seg).filter(Boolean);
    if (!toks.length) continue;
    if (wantPublish) { const p = publishKind(toks); if (p) out.push(p); continue; }
    const k = buildKind(toks);
    if (k) out.push({ kind: k });
  }
  return out;
}

// ---------- what to scan ----------

const OUTDIRS = { js: ['dist', 'build', 'out', '.next', '.output/public'], py: ['dist'] };
const SKIP = {
  js: ['node_modules', '.git'],
  py: ['.venv', 'venv', '__pycache__', '.git'],
  rust: ['deps', 'build', 'incremental', '.fingerprint', '.git'],
};
const exists = (p) => { try { fs.statSync(p); return true; } catch { return false; } };

function jobsFor(t, cwd) {
  if (t.kind === 'image') return [{ image: t.tag, label: `image ${t.tag}` }];
  if (t.kind === 'files') {
    // cap: a release can carry many assets and each is one scanner spawn
    return t.files.map((f) => path.resolve(cwd, f)).filter(exists).slice(0, 5)
      .map((p) => ({ path: p, scanners: 'secret,vuln', skipDirs: [], label: path.basename(p) }));
  }
  if (t.kind === 'rust') {
    const out = [];
    const rel = path.join(cwd, 'target', 'release');
    // the binary is huge and Cargo.lock vulns are already Side A's job
    if (exists(rel)) out.push({ path: rel, scanners: 'secret', skipDirs: SKIP.rust, label: 'target/release' });
    const lock = path.join(cwd, 'Cargo.lock');
    if (exists(lock)) out.push({ path: lock, scanners: 'vuln', skipDirs: [], label: 'Cargo.lock' });
    return out;
  }
  const dir = OUTDIRS[t.kind].map((d) => path.join(cwd, ...d.split('/'))).find(exists);
  // no output dir: scan the project but never node_modules / .venv, or this is not a hook, it is a coffee break
  return [{ path: dir || cwd, scanners: 'secret,vuln', skipDirs: SKIP[t.kind], label: dir ? path.relative(cwd, dir) || '.' : '.' }];
}

// ---------- reporting ----------

const RANK = { ANY: 0, LOW: 1, MODERATE: 2, HIGH: 3, CRITICAL: 4 };

// The rule and title come from the scanner's rule database, but redact again at the output
// boundary: this text goes into Claude's context and the transcript, and a secret echoed there
// is exactly the leak the hook exists to prevent. The file path is kept readable on purpose -
// bundlers emit hashed names, and the fix needs the real one.
const fmtSecrets = (list) => {
  const { redact } = require('./lib/scan');
  return list.slice(0, 10)
    .map((s) => `${redact(s.rule)} (${s.severity}) in ${String(s.target).replace(/\s+/g, ' ').slice(0, 200)} line ${s.line}${s.title ? ` - ${redact(s.title)}` : ''}`)
    .join('; ');
};

function fmtVulns(list, floor) {
  const bad = list.filter((v) => (RANK[v.severity] || 3) >= (RANK[floor] || 3));
  const pick = (bad.length ? bad : list).slice(0, 10);
  return `${list.length} vulnerabilities (${bad.length} at or above ${floor}): ${pick.map((v) => `${v.id} (${v.severity}${v.pkg ? `, ${v.pkg}` : ''})`).join(', ')}`;
}

const REMEDY = 'Do all of: (1) remove the secret from the source that produced the artifact; (2) rotate it now - treat it as compromised from the moment it was written into a build output; '
  + '(3) add the offending path to .dockerignore and .gitignore so it cannot be copied in again; (4) rebuild and re-run. '
  + 'Tell the user which secret to rotate, by rule and location - never print the value.';
const JS_NOTE = ' REACT_APP_*, VITE_* and NEXT_PUBLIC_* environment variables are inlined into the JS bundle at build time by design and are then visible to every browser, so they must never hold a secret: move it behind a server endpoint.';
const NO_SCANNER = 'secops-guard: Side B build scanning is inactive - trivy is not installed, so this artifact was NOT checked for baked-in secrets or CVEs. '
  + 'Install it (`winget install AquaSecurity.Trivy`, `brew install trivy`, or https://trivy.dev/latest/getting-started/installation/) and re-run. Mention this to the user once.';

// `docker build` with no .dockerignore copies .env and .git straight into the build context.
// Cheap and scanner-independent, so it still fires when trivy is missing.
function dockerignoreIssue(cwd) {
  let text;
  try { text = fs.readFileSync(path.join(cwd, '.dockerignore'), 'utf8'); } catch {
    return exists(path.join(cwd, '.env')) || exists(path.join(cwd, '.git'))
      ? `secops-guard: ${cwd} has no .dockerignore, so \`docker build\` copies .env, .git and any local credentials into the build context and usually into an image layer. Add a .dockerignore containing at least \`.env*\`, \`.git\`, \`node_modules\`, then rebuild.`
      : null;
  }
  const lines = text.split('\n').map((l) => l.trim()).filter((l) => l && l[0] !== '#');
  const covers = (name) => lines.some((l) => l === name || l === `${name}*` || l === `**/${name}` || l === `${name}/` || l === '*');
  const missing = ['.env', '.git'].filter((n) => !covers(n));
  return missing.length
    ? `secops-guard: the .dockerignore in ${cwd} does not exclude ${missing.join(' or ')}, so \`docker build\` copies ${missing.length > 1 ? 'them' : 'it'} into the build context and usually into an image layer. Add ${missing.map((n) => `\`${n}${n === '.env' ? '*' : ''}\``).join(' and ')} to .dockerignore and rebuild.`
    : null;
}

// ---------- decide ----------

async function decide(payload, deps = {}) {
  const ti = (payload && payload.tool_input) || {};
  if (typeof ti.command !== 'string' || !ti.command.trim()) return null;
  const isPre = isPreToolUse(payload);
  if (!isPre && failed(payload.tool_response)) return null;

  const found = targets(ti.command, isPre);
  if (!found.length) return null;

  const d = withDeps(deps);
  const cwd = payload.cwd || process.cwd();
  const cfg = d.loadConfig();
  const context = [];

  if (!isPre) for (const t of found) if (t.docker) { const w = dockerignoreIssue(cwd); if (w) context.push(w); break; }

  const live = found.filter((t) => !(t.kind === 'image' && cfg.allow.has(`image:${t.tag}`)));
  const jobs = live.flatMap((t) => jobsFor(t, cwd).map((j) => ({ ...j, from: t.kind })));
  if (!jobs.length) return context.length ? { decision: 'context', context: context.join('\n') } : null;

  // checked before the cache so a "no scanner" verdict is never stored
  if (!d.findScanner()) return { decision: 'context', context: [...context, NO_SCANNER].join('\n') };

  const deadline = d.now() + budgetMs();
  const secrets = [];
  const vulns = [];
  let partial = false;
  let anyJs = false;

  for (const j of jobs) {
    const left = deadline - d.now();
    if (left < 2000) { partial = true; break; }
    const key = j.image
      ? `buildscan:image:${j.image}`
      : `buildscan:${j.scanners}:${d.fingerprintDir(j.path, j.skipDirs)}`;
    let res;
    try {
      res = await d.cached(key, TTL, () => (j.image
        ? d.scanImage(j.image, { timeoutMs: left })
        : d.scanFs(j.path, { scanners: j.scanners, skipDirs: j.skipDirs, timeoutMs: left })));
    } catch (e) {
      partial = true;
      context.push(`secops-guard: could not scan ${j.label} (${(e && e.message ? e.message : String(e)).slice(0, 200)}); the artifact is unchecked.`);
      continue;
    }
    if (!res) { partial = true; continue; } // scanner vanished between findScanner() and here
    if (j.from === 'js') anyJs = true;
    for (const s of res.secrets || []) secrets.push(s);
    if ((res.vulns || []).length) vulns.push({ label: j.label, list: res.vulns });
  }

  for (const v of vulns) {
    context.push(`secops-guard: build scan of ${v.label}: ${fmtVulns(v.list, cfg.imageSeverityBlock)}. Not blocking (report-only policy for CVEs) - tell the user and suggest updating the base image or the affected dependencies.`);
  }
  if (partial && !secrets.length) {
    context.push(`secops-guard: the Side B scan did not finish within ${Math.round(budgetMs() / 1000)}s, so ${isPre ? 'this publish was allowed' : 'this build was accepted'} unchecked for baked-in secrets. Re-run with a larger SECOPS_BUILD_BUDGET_MS, or scan manually with \`trivy fs --scanners secret .\`.`);
  }

  if (secrets.length) {
    const reason = `secops-guard: SECRET BAKED INTO THE BUILD ARTIFACT - ${secrets.length} finding(s): ${fmtSecrets(secrets)}. `
      + (isPre
        ? 'This publish is blocked: a pushed image layer or a published package cannot be unpublished. '
        : 'The build already wrote it to disk. Do NOT publish, push or deploy this artifact. ')
      + REMEDY + (anyJs ? JS_NOTE : '');
    return { decision: isPre ? 'deny' : 'block', reason, context: context.join('\n') || undefined };
  }
  return context.length ? { decision: 'context', context: context.join('\n') } : null;
}

function main() {
  if (process.env.SECOPS_DISABLE === '1') return;
  let payload;
  try { payload = JSON.parse(fs.readFileSync(0, 'utf8')); } catch { return; }
  if (!payload || (payload.tool_name !== 'Bash' && payload.tool_name !== 'PowerShell')) return;
  decide(payload).then((res) => {
    if (!res) return;
    const io = require('./lib/io');
    const full = res.context ? `${res.reason}\n${res.context}` : res.reason;
    if (res.decision === 'deny') io.preDeny(full);
    else if (res.decision === 'block') io.postBlock(full);
    else if (isPreToolUse(payload)) io.preContext(res.context);
    else io.postContext(res.context);
  }).catch((e) => {
    process.stderr.write(`secops-guard: build-gate error ${e && e.message}\n`);
  }).finally(() => process.stdout.write('', () => process.exit(0)));
}

module.exports = { decide, withDeps, buildKind, publishKind, targets, jobsFor, dockerignoreIssue };
if (require.main === module) main();
