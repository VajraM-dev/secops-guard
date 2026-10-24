#!/usr/bin/env node
'use strict';
// PostToolUse (Bash|PowerShell): after an install ran, rescan the lockfiles it touched (cache bypassed) and
// any image built with `docker build -t`. Cannot undo; a block pushes exact rollback steps back to Claude.
// Known limit: only lockfiles are rescanned, so a bare `pip install x` with no lockfile gets no transitive
// post-scan; its transitive deps stay unchecked until a lockfile exists (dep-gate checked only x itself).

const fs = require('node:fs');
const path = require('node:path');
const { parseInstallIntents } = require('./lib/parse-command');

const UNINSTALL = {
  npm: 'npm uninstall', pnpm: 'pnpm remove', yarn: 'yarn remove', bun: 'bun remove',
  pip: 'pip uninstall -y', 'uv pip': 'uv pip uninstall', 'uv add': 'uv remove', 'uv tool': 'uv tool uninstall',
  pipx: 'pipx uninstall', poetry: 'poetry remove', pipenv: 'pipenv uninstall',
  'cargo add': 'cargo remove', 'cargo install': 'cargo uninstall',
};

function failed(resp) {
  if (!resp || typeof resp !== 'object') return false;
  const code = resp.exitCode ?? resp.exit_code ?? resp.returnCode;
  return resp.interrupted === true || resp.is_error === true || resp.success === false || (Number.isInteger(code) && code !== 0);
}

function rollbackHint(installs) {
  const cmds = [];
  for (const it of installs) {
    if (it.kind !== 'explicit' || !UNINSTALL[it.manager]) continue;
    const g = it.global && it.ecosystem === 'npm' ? ' -g' : '';
    cmds.push(`${UNINSTALL[it.manager]}${g} ${it.packages.map((p) => p.name).join(' ')}`);
  }
  return cmds;
}

function fixHint(findings) {
  const { maxFixed } = require('./dep-gate');
  const fixes = new Map();
  for (const f of findings) {
    const n = f.pkg.slice(f.pkg.indexOf(':') + 1).replace(/@[^@]*$/, '');
    fixes.set(n, maxFixed([fixes.get(n), f.fixed]));
  }
  return [...fixes].filter(([, v]) => v).slice(0, 10).map(([n, v]) => `${n} -> ${v}`).join(', ');
}

async function decide(payload, deps = {}) {
  const ti = (payload && payload.tool_input) || {};
  if (typeof ti.command !== 'string') return null;
  const intents = parseInstallIntents(ti.command);
  const installs = intents.filter((i) => (i.kind === 'explicit' && !i.runner) || i.kind === 'lockfile');
  const builds = intents.filter((i) => i.kind === 'build');
  if ((!installs.length && !builds.length) || failed(payload.tool_response)) return null;

  const { scanLockfile, formatFindings, withDeps, CONFIG } = require('./dep-gate');
  const d = withDeps(deps);
  const cfg = d.loadConfig();
  const cwd = payload.cwd || process.cwd();
  const block = [];
  const context = [];

  const files = new Set();
  for (const it of installs) {
    if (it.global) continue;
    const dir = path.resolve(cwd, it.cwd || '.');
    for (const f of d.findLockfiles(dir, it.ecosystem)) files.add(f);
    for (const f of it.kind === 'lockfile' && it.files ? it.files : []) files.add(path.resolve(dir, f));
  }
  const rollback = rollbackHint(installs);
  for (const file of files) {
    let v;
    try { v = await scanLockfile(file, cfg.lockfileSeverityBlock, d, true); } catch (e) {
      context.push(`secops-guard: post-install scan of ${path.basename(file)} failed (${e && e.message}); run /secops-guard:dep-audit later.`);
      continue;
    }
    const name = path.basename(file);
    if (v.block.length) {
      const fixes = fixHint(v.block);
      block.push(`secops-guard: the install left ${v.block.some((f) => f.severity === 'MALICIOUS') ? 'MALICIOUS or ' : ''}vulnerable packages (>= ${cfg.lockfileSeverityBlock}) in ${name}: ${formatFindings(v.block)}. They are already installed. `
        + (rollback.length ? `Roll back with \`${rollback.join(' && ')}\`` : 'Roll back the change (restore the previous lockfile and reinstall)')
        + (fixes ? `, or pin fixed versions (${fixes}) and reinstall` : '')
        + '. Then tell the user what happened.');
    } else if (v.low.length) {
      context.push(`secops-guard: post-install scan of ${name}: lower-severity advisories ${formatFindings(v.low, 8)}. Mention them to the user.`);
    }
  }

  for (const b of builds) {
    let res;
    try { res = await d.runScanner(b.tag); } catch (e) {
      context.push(`secops-guard: could not scan built image ${b.tag} (${e && e.message}).`);
      continue;
    }
    if (!res) continue;
    const bad = res.vulns.filter((v) => d.atLeast(v.severity, cfg.imageSeverityBlock));
    if (bad.length) {
      block.push(`secops-guard: built image ${b.tag} has ${bad.length} vulnerabilities at or above ${cfg.imageSeverityBlock} (${res.scanner}): ${bad.slice(0, 10).map((v) => `${v.id} (${v.severity}, ${v.pkg})`).join(', ')}. `
        + `Update the base image and the vulnerable packages in the Dockerfile and rebuild; do not push or run this image. The user can allowlist it via "image:${b.tag}" in ${CONFIG}.`);
    }
  }
  if (block.length) return { decision: 'block', reason: block.join('\n'), context: context.join('\n') || undefined };
  return context.length ? { decision: 'context', context: context.join('\n') } : null;
}

function main() {
  if (process.env.SECOPS_DISABLE === '1') return;
  let payload;
  try { payload = JSON.parse(fs.readFileSync(0, 'utf8')); } catch { return; }
  if (!payload || (payload.tool_name !== 'Bash' && payload.tool_name !== 'PowerShell')) return;
  let intents;
  try { intents = parseInstallIntents((payload.tool_input || {}).command || ''); } catch { return; }
  if (!intents.some((i) => i.kind === 'explicit' || i.kind === 'lockfile' || i.kind === 'build')) return;
  decide(payload).then((res) => {
    if (!res) return;
    const io = require('./lib/io');
    if (res.decision === 'block') io.postBlock(res.context ? `${res.reason}\n${res.context}` : res.reason);
    else io.postContext(res.context);
  }).catch((e) => {
    process.stderr.write(`secops-guard: post-install-scan error ${e && e.message}\n`);
  }).finally(() => process.stdout.write('', () => process.exit(0)));
}

module.exports = { decide, failed, rollbackHint };
if (require.main === module) main();
