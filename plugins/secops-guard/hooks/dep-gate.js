#!/usr/bin/env node
'use strict';
// PreToolUse (Bash|PowerShell): supply-chain gate for package, lockfile and image installs.
// Runs with onFailure:"block", so every error is caught here. Non-install commands exit with no output
// before any lib with network code is loaded.

const fs = require('node:fs');
const path = require('node:path');
const crypto = require('node:crypto');
const { parseInstallIntents, rewriteCommand, pinToken } = require('./lib/parse-command');

const HOUR = 3600e3;
const DAY = 24 * HOUR;
const CONFIG = '~/.claude/secops-guard/config.json';

// A gated install manager whose argument list contains a shell expansion. The parser cannot
// see what `$PKG` or `$(…)` becomes, so such a command must be denied rather than skipped.
// Package managers only; `node $SCRIPT`, `git clone $URL` and the like are none of our business.
const OBSCURED_INSTALL =
  /\b(?:npm|pnpm|yarn|bun|npx|pnpx|bunx|pip|pip3|pipx|uv|uvx|poetry|pipenv|cargo)\b[^;&|\n]{0,400}?\b(?:i|install|add|exec|dlx|x|sync|run)\b[^;&|\n]{0,400}?(?:\$\(|`|\$\{?[A-Za-z_])/;

// lazily required so the fast path and unit tests with injected fakes never load them
const LIB = {
  resolveVersion: () => require('./lib/registries').resolveVersion,
  queryPackages: () => require('./lib/osv').queryPackages,
  atLeast: () => require('./lib/osv').atLeast,
  satisfies: () => require('./lib/versions').satisfies,
  parseLockfile: () => require('./lib/lockfiles').parseLockfile,
  findLockfiles: () => require('./lib/lockfiles').findLockfiles,
  loadConfig: () => require('./lib/config').loadConfig,
  isAllowed: () => require('./lib/config').isAllowed,
  cached: () => require('./lib/cache').cached,
  runScanner: () => (image) => require('./lib/docker').scanImage(image, { timeoutMs: 90000 }),
  isFloatingTag: () => require('./lib/docker').isFloatingTag,
  composeImages: () => require('./lib/docker').composeImages,
  now: () => () => Date.now(),
};

function withDeps(deps = {}) {
  const d = { ...deps };
  for (const k of Object.keys(LIB)) if (!(k in d)) d[k] = LIB[k]();
  return d;
}

const errMsg = (e) => (e && e.message ? e.message : String(e)).slice(0, 200);
const exactOf = (spec) => {
  const s = String(spec || '').replace(/^(?:===?|=|v)/, '');
  return /^\d[\w.+!-]*$/.test(s) ? s : undefined;
};

function resolveReason(it, r, cfg) {
  const { ecosystem: eco, name, spec } = it;
  if (r.error === 'not_found' && /^invalid package name/.test(String(r.detail))) {
    return `secops-guard: ${JSON.stringify(name)} is not a valid ${eco} package name, so it was not looked up. Fix the package name (check for typos, stray quotes or shell characters) and retry.`;
  }
  if (r.error === 'not_found') {
    return `secops-guard: ${eco} package "${name}" does not exist (${r.detail}). It may be a hallucinated or slopsquatted name. `
      + 'Look up the exact package name in the official docs; do not guess alternatives. '
      + `If it is a private package, ask the user to add "${eco}:${name}" to "allow" in ${CONFIG}.`;
  }
  if (r.error === 'too_new') {
    const d = r.detail || {};
    return `secops-guard: ${name}@${d.version || spec} was published less than ${cfg.cooldownDays} days ago (supply-chain cooldown). `
      + (d.suggestion ? `Use ${name}@${d.suggestion} instead (newest version old enough). ` : 'No older stable version exists; choose another package. ')
      + `If the user needs this exact version, ask them to add "${eco}:${name}@${d.version || spec}" to "allow" in ${CONFIG}.`;
  }
  return `secops-guard: cannot verify ${name}${spec ? ` "${spec}"` : ''}: ${typeof r.detail === 'string' ? r.detail : r.error}. `
    + `Pick an exact version that exists and is at least ${cfg.cooldownDays} days old.`;
}

// Highest "fixed in" across advisories, so one upgrade clears all of them. Uses the shared
// comparator: a numeric-segment compare rated 2.0.0-rc1 above 2.0.0, so the deny message
// recommended a prerelease that the cooldown filter then refuses - advice that cannot be taken.
function maxFixed(list, eco) {
  const { compare } = require('./lib/versions');
  return list.filter(Boolean).reduce((m, v) => (m == null || compare(eco, v, m) > 0 ? v : m), null);
}

function vulnReason(r, bad, cfg) {
  const list = bad.slice(0, 8).map((v) => `${v.id} (${v.severity}${v.fixed ? `, fixed in ${v.fixed}` : ''})`).join(', ');
  const more = bad.length > 8 ? ` and ${bad.length - 8} more` : '';
  if (bad.some((v) => v.severity === 'MALICIOUS')) {
    return `secops-guard: ${r.name}@${r.version} is flagged MALICIOUS by OSV (${list}${more}). Do not install it or a lookalike; remove it from any manifest and tell the user.`;
  }
  const fixed = maxFixed(bad.map((v) => v.fixed), r.ecosystem);
  return `secops-guard: ${r.name}@${r.version} has known vulnerabilities: ${list}${more}. `
    + (fixed ? `Use version ${fixed} or newer that is at least ${cfg.cooldownDays} days old. ` : 'No fixed version is published; choose a different package. ')
    + `Only if the user accepts the risk, they can add "${r.ecosystem}:${r.name}@${r.version}" to "allow" in ${CONFIG}.`;
}

// items: [{ecosystem, name, spec}] -> same items + {version, allowed, deny?, note?}
async function checkPackages(items, cfg, d) {
  const opts = { now: d.now() };
  // Bounded: each npm lookup pulls the FULL registry document (needed for publish times),
  // which is tens of MB for a popular package. An unbounded Promise.all over `npm i a b c …`
  // spiked memory and stalled straight into the hook timeout, which denies.
  const { mapLimit } = require('./lib/osv');
  const res = await mapLimit(items, 6, async (it) => {
    const r = { ...it, version: null, allowed: d.isAllowed(cfg, it.ecosystem, it.name, exactOf(it.spec)) };
    let v;
    try {
      // allowlisted entries skip the cooldown but are still pinned when resolvable
      v = await d.resolveVersion(it.ecosystem, it.name, it.spec || '', r.allowed ? 0 : cfg.cooldownDays, opts);
    } catch (e) {
      if (!r.allowed) r.error = e;
      return r;
    }
    if (!v || v.error) {
      if (!r.allowed) r.deny = resolveReason(it, v || { error: 'no_match' }, cfg);
      return r;
    }
    r.version = v.version;
    if (!r.allowed) r.allowed = d.isAllowed(cfg, it.ecosystem, it.name, v.version);
    return r;
  });
  const toScan = res.filter((r) => r.version && !r.allowed);
  if (toScan.length) {
    try {
      const map = await d.queryPackages(toScan.map((r) => ({ ecosystem: r.ecosystem, name: r.name, version: r.version })), opts);
      for (const r of toScan) {
        const bad = (map.get(`${r.ecosystem}:${r.name}@${r.version}`) || [])
          .filter((v) => v.severity === 'MALICIOUS' || d.atLeast(v.severity, cfg.packageSeverityBlock));
        if (bad.length) r.deny = vulnReason(r, bad, cfg);
      }
    } catch (e) {
      for (const r of toScan) r.error = e;
    }
  }
  for (const r of res) {
    if (!r.error) continue;
    if (cfg.failOpen) r.note = `secops-guard: could not verify ${r.ecosystem}:${r.name} (${errMsg(r.error)}); allowed because failOpen is set. Treat this dependency with caution.`;
    else r.deny = `secops-guard: could not verify ${r.ecosystem}:${r.name} (${errMsg(r.error)}). Retry in a moment; if the registry or api.osv.dev stays unreachable, tell the user.`;
  }
  return res;
}

function registryAllowed(reg, cfg) {
  let host;
  try { host = new URL(/^[a-z][\w+.-]*:\/\//i.test(reg) ? reg : `https://${reg}`).hostname; } catch { return false; }
  return cfg.allowRegistries.includes(host);
}

function hasLocalBin(dir, pkgName) {
  const bin = pkgName.slice(pkgName.lastIndexOf('/') + 1);
  return ['', '.cmd'].some((e) => fs.existsSync(path.join(dir, 'node_modules', '.bin', bin + e)));
}

async function gateExplicit(intents, cfg, d, cwd, out) {
  const entries = [];
  for (const it of intents) {
    if (it.kind !== 'explicit') continue;
    for (const reg of it.registries || []) {
      if (!registryAllowed(reg, cfg)) {
        out.deny.push(`secops-guard: ${it.manager} is pointed at package index "${reg}", which is not in allowRegistries, so its packages cannot be verified. Use the default registry, or ask the user to add the host to "allowRegistries" in ${CONFIG}.`);
      }
    }
    const dir = path.resolve(cwd, it.cwd || '.');
    for (const p of it.packages) {
      // npx/bunx without a version runs the project's own binary; pinning would fetch a registry package instead
      if (it.runner && it.ecosystem === 'npm' && !p.spec && hasLocalBin(dir, p.name)) continue;
      entries.push({ it, p });
    }
  }
  if (!entries.length) return;
  const results = await checkPackages(entries.map(({ it, p }) => ({ ecosystem: it.ecosystem, name: p.name, spec: p.spec })), cfg, d);
  const pinned = [];
  results.forEach((r, i) => {
    const { p } = entries[i];
    if (r.deny) { out.deny.push(r.deny); return; }
    if (r.note) out.context.push(r.note);
    if (!r.version) return;
    const pin = pinToken(p, r.version);
    if (pin === p.raw) return;
    if (p.start == null) {
      out.deny.push(`secops-guard: ${p.name} checks out at ${r.version}, but this nested command cannot be rewritten safely. Re-run it with the package pinned as ${pin}.`);
    } else if (out.pins.has(p.raw) && out.pins.get(p.raw) !== pin) {
      out.deny.push(`secops-guard: "${p.raw}" is installed by two package managers in one command; run the installs as separate commands.`);
    } else if (!out.pins.has(p.raw)) {
      out.pins.set(p.raw, pin);
      pinned.push(`${p.raw} -> ${pin}`);
    }
  });
  if (pinned.length) out.context.push(`secops-guard: pinned ${pinned.join(', ')} (versions checked against cooldown and OSV).`);
}

const shortKey = (key) => key.slice(key.indexOf(':') + 1);

function formatFindings(list, max = 15) {
  const byPkg = new Map();
  for (const f of list) {
    if (!byPkg.has(f.pkg)) byPkg.set(f.pkg, []);
    byPkg.get(f.pkg).push(`${f.id} (${f.severity}${f.fixed ? `, fixed in ${f.fixed}` : ''})`);
  }
  const lines = [...byPkg].slice(0, max).map(([pkg, v]) => `${shortKey(pkg)}: ${v.slice(0, 5).join(', ')}${v.length > 5 ? ` +${v.length - 5}` : ''}`);
  if (byPkg.size > max) lines.push(`… and ${byPkg.size - max} more packages`);
  return lines.join('; ');
}

// verdict for one lockfile; cached by content hash unless fresh (post-install rescans)
async function scanLockfile(file, threshold, d, fresh = false) {
  const sha = crypto.createHash('sha256').update(fs.readFileSync(file)).digest('hex');
  const run = async () => {
    let pkgs;
    try { pkgs = d.parseLockfile(file); } catch (e) { return { count: 0, block: [], low: [], parseError: errMsg(e) }; }
    if (!pkgs.length) return { count: 0, block: [], low: [] };
    const map = await d.queryPackages(pkgs, { now: d.now() });
    const block = [];
    const low = [];
    for (const [pkg, vulns] of map) {
      for (const v of vulns) {
        (v.severity === 'MALICIOUS' || d.atLeast(v.severity, threshold) ? block : low).push({ pkg, id: v.id, severity: v.severity, fixed: v.fixed || null });
      }
    }
    return { count: pkgs.length, block, low };
  };
  return fresh ? run() : d.cached(`lockscan:v1:${threshold}:${sha}`, DAY, run);
}

const isFile = (f) => { try { return fs.statSync(f).isFile(); } catch { return false; } };

async function gateLockfiles(intents, cfg, d, cwd, out) {
  const files = new Map();
  for (const it of intents) {
    if (it.kind !== 'lockfile') continue;
    const dir = path.resolve(cwd, it.cwd || '.');
    const list = (it.files ? it.files.map((f) => path.resolve(dir, f)) : d.findLockfiles(dir, it.ecosystem)).filter(isFile);
    if (!list.length) {
      out.context.push(`secops-guard: no lockfile found for \`${it.manager}\` in ${dir}; transitive dependencies are unchecked until the post-install scan.`);
    }
    for (const f of list) files.set(f, it);
  }
  for (const [file] of files) {
    let v;
    try {
      v = await scanLockfile(file, cfg.lockfileSeverityBlock, d);
    } catch (e) {
      if (cfg.failOpen) out.context.push(`secops-guard: could not scan ${file} (${errMsg(e)}); allowed because failOpen is set.`);
      else out.deny.push(`secops-guard: could not scan ${file} against OSV (${errMsg(e)}). Retry in a moment; if api.osv.dev stays unreachable, tell the user.`);
      continue;
    }
    const name = path.basename(file);
    if (v.parseError) out.context.push(`secops-guard: could not parse ${name} (${v.parseError}); its packages were not checked.`);
    // A lockfile we understood but got nothing out of reads exactly like a clean one. Say so,
    // otherwise an unrecognised format or an all-unpinned requirements.txt looks verified.
    else if (!v.count) out.context.push(`secops-guard: found ${name} but read no pinned packages from it, so nothing in it was checked. If it has dependencies, the format may be unsupported (requirements.txt is only read for exact "name==version" lines, and -r includes are not followed). Tell the user it was not verified.`);
    if (v.block.length) {
      const mal = v.block.some((f) => f.severity === 'MALICIOUS');
      out.deny.push(`secops-guard: ${name} pins ${mal ? 'MALICIOUS and/or ' : ''}vulnerable packages at or above ${cfg.lockfileSeverityBlock}: ${formatFindings(v.block)}. `
        + 'Upgrade them to the fixed versions (bump the direct dependency, or add an override/constraint for transitive ones), regenerate the lockfile, then retry. '
        + (mal ? 'Remove any MALICIOUS package entirely and tell the user. ' : '')
        + `If the user accepts the risk, they can raise "lockfileSeverityBlock" in ${CONFIG}.`);
    } else if (v.low.length) {
      out.context.push(`secops-guard: ${name} has lower-severity advisories (allowed): ${formatFindings(v.low, 8)}. Mention them to the user.`);
    }
  }
}

async function gateImages(intents, cfg, d, cwd, out) {
  const images = new Set();
  for (const it of intents) {
    if (it.kind === 'image') images.add(it.image);
    if (it.kind === 'compose') for (const img of d.composeImages(path.resolve(cwd, it.cwd || '.'), it.files || [])) images.add(img);
  }
  let noScanner = false;
  for (const img of images) {
    if (d.isAllowed(cfg, 'image', img)) continue;
    if (d.isFloatingTag(img)) out.context.push(`secops-guard: image ${img} uses a floating tag; prefer a pinned version tag or an @sha256 digest.`);
    let res;
    try {
      // undefined (no scanner) is never cached, so installing grype takes effect at once
      res = await d.cached(`imagescan:v1:${img}`, 6 * HOUR, async () => (await d.runScanner(img)) || undefined);
    } catch (e) {
      if (cfg.failOpen) out.context.push(`secops-guard: could not scan image ${img} (${errMsg(e)}); allowed because failOpen is set.`);
      else out.deny.push(`secops-guard: could not scan image ${img} (${errMsg(e)}). Check the image name/tag and retry; if the scanner keeps failing, tell the user.`);
      continue;
    }
    if (!res) { noScanner = true; continue; }
    const bad = res.vulns.filter((v) => d.atLeast(v.severity, cfg.imageSeverityBlock));
    if (bad.length) {
      const ids = bad.slice(0, 10).map((v) => `${v.id} (${v.severity}${v.pkg ? `, ${v.pkg}` : ''})`).join(', ');
      out.deny.push(`secops-guard: image ${img} has ${bad.length} vulnerabilities at or above ${cfg.imageSeverityBlock} (${res.scanner}): ${ids}${bad.length > 10 ? ', …' : ''}. `
        + `Use a newer patched tag or a slimmer base image, or ask the user to add "image:${img}" to "allow" in ${CONFIG}.`);
    }
  }
  if (noScanner) out.context.push('secops-guard: no usable image scanner (grype, trivy, or docker scout with `docker login`) was found, so container images were not scanned. Recommend the user install grype (see setup/tools.md in the secops-guard plugin).');
}

// -> null | {decision:'deny', reason} | {decision:'allow', updatedInput, context?} | {decision:'context', context}
async function decide(payload, deps = {}, intents) {
  const ti = (payload && payload.tool_input) || {};
  const cmd = ti.command;
  const gated = (intents || parseInstallIntents(cmd)).filter((i) => i.kind !== 'build');
  // An install whose package name is produced by the shell cannot be checked: the parser sees
  // `$PKG`, not what it expands to, and would silently yield no intents at all - i.e. allow.
  // Fail closed instead, and say how to make it checkable.
  const obscured = typeof cmd === 'string' && OBSCURED_INSTALL.test(cmd);
  if (!gated.length && !obscured) return null;
  if (obscured) {
    return {
      decision: 'deny',
      reason: 'secops-guard: this install builds the package name with a shell variable or substitution, so the version cannot be checked against the cooldown and the advisory database before it installs. Write the package name and version literally, for example "npm install lodash@4.18.1".',
    };
  }
  const d = withDeps(deps);
  const cfg = d.loadConfig();
  const cwd = payload.cwd || process.cwd();
  const out = { deny: [], context: [], pins: new Map() };
  try {
    // Finish before the harness timeout in hooks.json (150s). Past that the hook is killed
    // and onFailure:"block" denies with a harness message, never consulting failOpen - so the
    // user's own setting would be ignored. Own the deadline here instead.
    const budget = Number(process.env.SECOPS_GATE_BUDGET_MS) || 120000;
    let timer;
    const expired = new Promise((_, rej) => { timer = setTimeout(() => rej(new Error(`verification exceeded ${Math.round(budget / 1000)}s`)), budget); });
    try {
      await Promise.race([(async () => {
        await gateExplicit(gated, cfg, d, cwd, out);
        await gateLockfiles(gated, cfg, d, cwd, out);
        await gateImages(gated, cfg, d, cwd, out);
      })(), expired]);
    } finally { clearTimeout(timer); }
  } catch (e) {
    (cfg.failOpen ? out.context : out.deny).push(`secops-guard: could not verify this install (${errMsg(e)}). Retry in a moment; if it keeps failing, tell the user.`);
  }
  if (out.deny.length) return { decision: 'deny', reason: [...new Set(out.deny)].join('\n') };
  const context = out.context.length ? [...new Set(out.context)].join('\n') : undefined;
  if (out.pins.size) {
    const command = rewriteCommand(cmd, out.pins);
    // rewriteCommand returns null when a pin is not safe to splice into a shell string, and
    // an unchanged string when an edit could not be placed. Either way we have NOT pinned, so
    // allowing here would let the unpinned install through. Deny and tell Claude what to run.
    if (command === null || command === cmd) {
      const pinned = [...out.pins.values()].join(', ');
      return {
        decision: 'deny',
        reason: `secops-guard: checked these versions but could not safely pin them in this command: ${pinned}. Re-run the install as a plain command with the version written literally, with no quoting, variables or substitutions around the package name.`,
      };
    }
    return { decision: 'allow', updatedInput: { ...ti, command }, context };
  }
  return context ? { decision: 'context', context } : null;
}

function emit(res) {
  if (!res) return;
  const io = require('./lib/io');
  if (res.decision === 'deny') io.preDeny(res.reason);
  else if (res.decision === 'allow') io.preAllowWithInput(res.updatedInput, res.context);
  else io.preContext(res.context);
}

function main() {
  if (process.env.SECOPS_DISABLE === '1') return;
  let payload;
  try { payload = JSON.parse(fs.readFileSync(0, 'utf8')); } catch { return; }
  if (!payload || (payload.tool_name !== 'Bash' && payload.tool_name !== 'PowerShell')) return;
  const cmd = payload.tool_input && payload.tool_input.command;
  if (typeof cmd !== 'string' || !cmd.trim()) return;
  let intents;
  try {
    intents = parseInstallIntents(cmd).filter((i) => i.kind !== 'build');
  } catch (e) {
    process.stderr.write(`secops-guard: parse error ${errMsg(e)}\n`);
    return;
  }
  if (!intents.length) return;
  decide(payload, {}, intents)
    .catch((e) => ({ decision: 'deny', reason: `secops-guard: could not verify this install (${errMsg(e)}). Retry in a moment; if it keeps failing, tell the user.` }))
    .then((res) => {
      try { emit(res); } catch (e) { process.stderr.write(`secops-guard: ${errMsg(e)}\n`); }
      // pending keep-alive sockets must not hold the hook open
      process.stdout.write('', () => process.exit(0));
    });
}

module.exports = { decide, checkPackages, scanLockfile, formatFindings, withDeps, registryAllowed, maxFixed, CONFIG };
if (require.main === module) main();
