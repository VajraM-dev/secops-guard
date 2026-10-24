'use strict';
// plugin-audit: inventory hooks / MCP servers / scripts of installed Claude Code plugins and user config,
// then static red-flag scan. Read-only. Usage: node audit-plugins.js [--json] [--cwd <dir>] [--claude-home <dir>]

const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');

const SEV = ['NONE', 'LOW', 'MED', 'HIGH'];
const CODE_EXT = /\.(?:c?m?js|ts|py|sh|bash|zsh|ps1|psm1|cmd|bat)$/i;
const MAX_HITS_PER_RULE = 3;
const MAX_FILE = 2 * 1024 * 1024;

// Line-based rules. Single severities here; cross-rule combos are raised to HIGH in scanText.
const RULES = [
  { id: 'pipe-to-shell', sev: 'HIGH', desc: 'downloads and pipes into a shell', re: /\b(?:curl|wget|iwr|irm|Invoke-WebRequest|Invoke-RestMethod)\b[^|\n]{0,300}\|\s*(?:ba|z)?sh\b|\|\s*(?:iex|Invoke-Expression)\b/i },
  { id: 'dynamic-eval', sev: 'HIGH', desc: 'eval / new Function / Invoke-Expression', re: /\beval\s*\(|\bnew\s+Function\s*\(|\bInvoke-Expression\b/i },
  { id: 'network', sev: 'MED', desc: 'network call', re: /\bfetch\s*\(|\bhttps?\.(?:request|get)\s*\(|require\(\s*['"](?:node:)?(?:https?|net|dgram|tls)['"]\s*\)|\baxios\b|XMLHttpRequest|\bWebSocket\b|\bcurl\b|\bwget\b|Invoke-WebRequest|Invoke-RestMethod|\biwr\s|\brequests\.(?:get|post|put)\b|\burllib\b|\bhttpx\b|\bsocket\.socket\b|Net\.WebClient/i },
  { id: 'credential-path', sev: 'MED', desc: 'references credential files', re: /[\\/~]\.ssh\b|\bid_rsa\b|\bid_ed25519\b|[\\/]\.aws\b|\.npmrc\b|\.pypirc\b|\.netrc\b|\.git-credentials\b|[\\/]\.docker[\\/]config\.json|[\\/]\.kube[\\/]config/i },
  { id: 'env-dump', sev: 'MED', desc: 'dumps the whole environment', re: /JSON\.stringify\(\s*process\.env\s*\)|Object\.(?:entries|keys|values)\(\s*process\.env\s*\)|dict\(\s*os\.environ\s*\)|os\.environ\.copy\(\)|\bprintenv\b|(?:Get-ChildItem|gci|dir|ls)\s+env:/i },
  { id: 'claude-config-write', sev: 'HIGH', desc: 'writes Claude settings / other plugins', re: /(?:writeFile|appendFile|createWriteStream|copyFile|renameSync|unlink|rmSync|Set-Content|Add-Content|Out-File|Copy-Item|Move-Item|\b(?:cp|mv)\s|\bopen\([^)]{0,200}['"][wa]['"])[^\n]{0,300}(?:\.claude[\\/]+(?:settings(?:\.local)?\.json|plugins\b|hooks\b|CLAUDE\.md)|\.claude\.json|known_marketplaces)/i },
  // Shell redirect: operator first, then the target path (a bare '>' after the path is not a write to it).
  { id: 'claude-config-write', sev: 'HIGH', desc: 'writes Claude settings / other plugins', re: /(?:^|\s)(?:>>?|tee(?:\s+-a)?)\s*["']?[^\s"'|;&]{0,200}(?:\.claude[\\/]+(?:settings(?:\.local)?\.json|plugins[\\/]|hooks[\\/])|\.claude\.json)/i },
  { id: 'base64-decode', sev: 'LOW', desc: 'decodes base64', re: /\batob\s*\(|Buffer\.from\([^)]{0,200}['"]base64['"]|base64\s+(?:-d|--decode)\b|b64decode|FromBase64String/i },
  { id: 'exec', sev: 'LOW', desc: 'spawns processes', re: /\bchild_process\b|\bexecSync\b|\bexecFile(?:Sync)?\b|\bspawn(?:Sync)?\s*\(|\bsubprocess\b|\bos\.system\b|\bos\.popen\b|\bStart-Process\b/i },
];

function maxSev(a, b) { return SEV.indexOf(a) >= SEV.indexOf(b) ? a : b; }

function countOf(line, needle) {
  let n = 0;
  for (let i = line.indexOf(needle); i !== -1; i = line.indexOf(needle, i + needle.length)) n++;
  return n;
}

// Returns [{sev, rule, desc, file, line}] for one file's text.
function scanText(text, file) {
  const hits = [];
  const perRule = {};
  const add = (sev, rule, desc, line) => {
    perRule[rule] = (perRule[rule] || 0) + 1;
    if (perRule[rule] <= MAX_HITS_PER_RULE) hits.push({ sev, rule, desc, file, line });
  };
  const lines = text.split(/\r?\n/);
  lines.forEach((ln, i) => {
    const n = i + 1;
    // Whole-line comments never execute; they were the main false-positive source (install docs, rationale notes).
    if (/^\s*(?:\/\/|#|\*|\/\*|REM\s|::)/i.test(ln)) return;
    const seen = new Set();
    for (const r of RULES) {
      if (!seen.has(r.id) && r.re.test(ln)) { seen.add(r.id); add(r.sev, r.id, r.desc, n); }
    }
    if (ln.length > 2000) add('MED', 'minified', `minified/one-liner line (${ln.length} chars)`, n);
    if (!ln.includes('data:image') && /[A-Za-z0-9+/]{200,}={0,2}/.test(ln)) add('MED', 'blob', 'base64/hex blob > 200 chars', n);
    if (countOf(ln, '\\x') + countOf(ln, '\\u00') >= 20) add('HIGH', 'escape-obfuscation', 'dense \\x / \\u escapes', n);
  });
  const has = (r) => perRule[r] > 0;
  if (has('network') && (has('credential-path') || has('env-dump'))) add('HIGH', 'exfil-combo', 'credentials/env + network in same file (possible exfiltration)', 0);
  if ((has('blob') || has('base64-decode') || has('escape-obfuscation')) && (has('dynamic-eval') || has('exec'))) add('HIGH', 'decode-exec-combo', 'decoded/obfuscated data + code execution in same file', 0);
  for (const r of Object.keys(perRule)) {
    if (perRule[r] > MAX_HITS_PER_RULE) hits.push({ sev: 'LOW', rule: r, desc: `+${perRule[r] - MAX_HITS_PER_RULE} more ${r} hits`, file, line: 0 });
  }
  return hits;
}

function packageJsonFlags(text, file) {
  const out = [];
  try {
    const scripts = JSON.parse(text).scripts || {};
    const lines = text.split(/\r?\n/);
    for (const k of ['preinstall', 'install', 'postinstall', 'prepare']) {
      if (!scripts[k]) continue;
      const line = lines.findIndex((l) => l.includes(`"${k}"`)) + 1;
      out.push({ sev: 'MED', rule: 'install-script', desc: `npm ${k} script: ${String(scripts[k]).slice(0, 80)}`, file, line });
    }
  } catch { /* not json */ }
  return out;
}

// Token-shaped runs only; '/' excluded so file paths stay readable.
const redact = (s) => String(s)
  .replace(/((?:token|secret|password|passwd|pwd|api[-_]?key|access[-_]?key|auth(?:orization)?|bearer)["']?\s*[=:\s]\s*["']?(?:(?:Bearer|Basic|Token)\s+)?)[^\s"'&,;]{4,}/gi, '$1<redacted>')
  .replace(/\b(?:gh[pousr]_|github_pat_|sk-|xox[baprs]-|AKIA|glpat-|npm_|hf_)[A-Za-z0-9_-]{8,}/g, '<redacted>')
  .replace(/[A-Za-z0-9_\-+=]{32,}/g, '<redacted>');

// hooks.json shape: {hooks:{Event:[{matcher, hooks:[{type, command, args}]}]}} or the inner map directly.
function hookEntries(hooksObj) {
  const out = [];
  const map = hooksObj && typeof hooksObj === 'object' ? (hooksObj.hooks && typeof hooksObj.hooks === 'object' && !Array.isArray(hooksObj.hooks) ? hooksObj.hooks : hooksObj) : {};
  for (const [event, groups] of Object.entries(map)) {
    if (!Array.isArray(groups)) continue;
    for (const g of groups) {
      for (const h of (g && g.hooks) || []) {
        const cmd = [h.command, ...(Array.isArray(h.args) ? h.args : [])].filter(Boolean).join(' ') || h.url || h.prompt || h.type || '';
        out.push({ event, matcher: (g && g.matcher) || '*', type: h.type || 'command', command: redact(cmd).slice(0, 200) });
      }
    }
  }
  return out;
}

// MCP server: summarise without secrets; flag unpinned package runners and plaintext remote URLs.
function mcpEntries(mcpObj, source) {
  const out = [];
  const servers = mcpObj && typeof mcpObj === 'object' ? (mcpObj.mcpServers && typeof mcpObj.mcpServers === 'object' ? mcpObj.mcpServers : mcpObj) : {};
  for (const [name, s] of Object.entries(servers)) {
    if (!s || typeof s !== 'object') continue;
    const args = Array.isArray(s.args) ? s.args.map(String) : [];
    const flags = [];
    const runner = String(s.command || '').replace(/\\/g, '/').split('/').pop().replace(/\.(?:cmd|exe)$/i, '');
    if (['npx', 'bunx', 'pnpx', 'uvx', 'pipx'].includes(runner) || (runner === 'pnpm' && args[0] === 'dlx')) {
      const pkg = args.find((a, i) => !a.startsWith('-') && !(runner === 'pnpm' && i === 0) && a !== 'run');
      const pinned = pkg && (/^@?[^@]+@\d/.test(pkg) || /==\d/.test(pkg) || args.some((a) => /==\d/.test(a)));
      if (pkg && !pinned) flags.push({ sev: 'MED', rule: 'mcp-unpinned', desc: `${runner} ${pkg} not pinned to a version` });
    }
    const url = s.url || s.serverUrl || '';
    if (url && /^http:/i.test(url) && !/^http:\/\/(?:localhost|127\.0\.0\.1)/i.test(url)) flags.push({ sev: 'MED', rule: 'mcp-plaintext', desc: 'remote MCP over plain http' });
    out.push({
      source, name, type: s.type || (url ? 'http' : 'stdio'),
      command: redact([s.command, ...args].filter(Boolean).join(' ')).slice(0, 200),
      url: url ? redact(url.replace(/\?.*$/, '?<query redacted>')) : '',
      envKeys: Object.keys(s.env || {}), headerKeys: Object.keys(s.headers || {}), flags,
    });
  }
  return out;
}

function readText(p) {
  try {
    const st = fs.statSync(p);
    if (!st.isFile() || st.size > MAX_FILE) return null;
    return fs.readFileSync(p, 'utf8');
  } catch { return null; }
}
function readJson(p) {
  const t = readText(p);
  if (t == null) return null;
  try { return JSON.parse(t); } catch { return null; }
}

function scanFile(abs, label) {
  const text = readText(abs);
  if (text == null) return [];
  if (path.basename(abs) === 'package.json') return packageJsonFlags(text, label);
  return scanText(text, label);
}

// Tests/benchmarks/examples do not run from hooks; one step lower keeps them visible without drowning hook code.
const NONRUNTIME = /(?:^|\/)(?:tests?|__tests__|spec|benchmarks?|examples?|docs?|fixtures)\//i;
const demote = (h) => ({ ...h, sev: SEV[Math.max(1, SEV.indexOf(h.sev) - 1)], desc: `${h.desc} [non-runtime path]` });

function riskOf(findings) {
  return findings.reduce((acc, f) => maxSev(acc, f.sev), 'NONE');
}

function marketplaceFindings(settings, known, risky) {
  const all = { ...(known || {}), ...((settings && settings.extraKnownMarketplaces) || {}) };
  const auto = new Set((risky || []).map((r) => r.name));
  for (const [name, m] of Object.entries(known || {})) if (m && m.autoUpdate) auto.add(name);
  return Object.entries(all).map(([name, m]) => {
    const src = (m && m.source) || {};
    const flags = [];
    if (auto.has(name)) flags.push({ sev: 'MED', rule: 'auto-update', desc: 'autoUpdate on: new upstream code runs without review' });
    if ((src.source === 'github' || src.source === 'git') && !src.ref && !src.sha) flags.push({ sev: 'LOW', rule: 'unpinned-source', desc: 'source not pinned to a ref/sha' });
    return { name, repo: src.repo || src.url || src.path || '', ref: src.ref || src.sha || '', risk: riskOf(flags), flags };
  });
}

function auditAll(opts, deps) {
  const claudeHome = opts.claudeHome || path.join(os.homedir(), '.claude');
  const cwd = opts.cwd || process.cwd();
  const res = { claudeHome, plugins: [], user: { hooks: [], hookFiles: [], mcp: [], findings: [] }, marketplaces: [], errors: [] };

  let snap = null;
  if (deps.snapshotPlugins) {
    try { snap = deps.snapshotPlugins(claudeHome); } catch (e) { res.errors.push(`snapshotPlugins: ${e.message}`); }
  } else res.errors.push('hooks/plugin-integrity.js unavailable; plugin inventory skipped');

  for (const [key, p] of Object.entries((snap && snap.plugins) || {})) {
    if (key === 'user/hooks') continue; // covered by the user-config section below
    const files = Object.keys(p.files || {});
    const findings = [];
    const scripts = files.filter((f) => CODE_EXT.test(f) || /^bin\//.test(f.replace(/\\/g, '/')));
    for (const f of scripts) findings.push(...scanFile(path.join(p.root, f), f).map((h) => (NONRUNTIME.test(f.replace(/\\/g, '/')) ? demote(h) : h)));
    findings.push(...scanFile(path.join(p.root, 'package.json'), 'package.json'));
    const hooks = hookEntries(p.hooks);
    for (const h of hooks) for (const f of scanText(h.command, `hooks.json[${h.event}]`)) if (f.sev !== 'LOW') findings.push(f);
    const mcp = mcpEntries(p.mcp, '.mcp.json');
    for (const m of mcp) for (const f of m.flags) findings.push({ ...f, file: `.mcp.json[${m.name}]`, line: 0 });
    res.plugins.push({ key, root: p.root, risk: riskOf(findings), hooks, mcp, scripts, findings });
  }
  res.plugins.sort((a, b) => SEV.indexOf(b.risk) - SEV.indexOf(a.risk) || a.key.localeCompare(b.key));

  const settings = readJson(path.join(claudeHome, 'settings.json')) || {};
  for (const sf of ['settings.json', 'settings.local.json']) {
    const s = sf === 'settings.json' ? settings : readJson(path.join(claudeHome, sf));
    for (const h of hookEntries(s && s.hooks)) {
      res.user.hooks.push({ ...h, source: sf });
      for (const f of scanText(h.command, `${sf} hooks[${h.event}]`)) if (f.sev !== 'LOW') res.user.findings.push(f);
    }
  }
  const hookDir = path.join(claudeHome, 'hooks');
  let names = [];
  try { names = fs.readdirSync(hookDir); } catch { /* none */ }
  for (const n of names) {
    const abs = path.join(hookDir, n);
    if (readText(abs) == null) continue;
    res.user.hookFiles.push(`hooks/${n}`);
    res.user.findings.push(...scanFile(abs, `~/.claude/hooks/${n}`));
  }

  const claudeJson = readJson(opts.claudeJson || path.join(path.dirname(claudeHome), '.claude.json')) || {};
  res.user.mcp.push(...mcpEntries(claudeJson.mcpServers, '~/.claude.json'));
  const proj = claudeJson.projects || {};
  const norm = (s) => path.resolve(s).replace(/\\/g, '/').toLowerCase();
  for (const [dir, pc] of Object.entries(proj)) {
    if (norm(dir) === norm(cwd) && pc && pc.mcpServers) res.user.mcp.push(...mcpEntries(pc.mcpServers, `~/.claude.json projects[${dir}]`));
  }
  res.user.mcp.push(...mcpEntries(readJson(path.join(cwd, '.mcp.json')), `${cwd.replace(/\\/g, '/')}/.mcp.json`));
  for (const m of res.user.mcp) for (const f of m.flags) res.user.findings.push({ ...f, file: `${m.source}[${m.name}]`, line: 0 });
  res.user.risk = riskOf(res.user.findings);

  let risky = [];
  try { if (deps.riskyMarketplaces) risky = deps.riskyMarketplaces(settings) || []; } catch (e) { res.errors.push(`riskyMarketplaces: ${e.message}`); }
  res.marketplaces = marketplaceFindings(settings, readJson(path.join(claudeHome, 'plugins', 'known_marketplaces.json')), risky);
  return res;
}

// One entry per (severity, rule): first locations plus a count, highest severity first.
function reasons(findings, limit = 6) {
  const groups = new Map();
  for (const f of findings) {
    if (!f.line && /^\+\d+ more/.test(f.desc)) continue;
    const k = `${f.sev}|${f.rule}`;
    if (!groups.has(k)) groups.set(k, { sev: f.sev, desc: f.desc.replace(/ \(\d+ chars\)$/, ''), locs: [] });
    groups.get(k).locs.push(`${f.file}${f.line ? `:${f.line}` : ''}`);
  }
  const list = [...groups.values()].sort((a, b) => SEV.indexOf(b.sev) - SEV.indexOf(a.sev));
  const shown = list.filter((g) => g.sev !== 'LOW' || list.length <= limit).slice(0, limit);
  const txt = shown.map((g) => `${g.sev} ${g.desc} x${g.locs.length} (${g.locs.slice(0, 2).join(', ')}${g.locs.length > 2 ? ', …' : ''})`);
  if (list.length > shown.length) txt.push(`+${list.length - shown.length} more rules`);
  return txt.join('; ') || '-';
}

function formatReport(r) {
  const L = [`# plugin-audit (${r.claudeHome.replace(/\\/g, '/')})`, ''];
  const cnt = (s) => r.plugins.filter((p) => p.risk === s).length;
  L.push(`plugins: ${r.plugins.length} | HIGH ${cnt('HIGH')} | MED ${cnt('MED')} | LOW ${cnt('LOW')} | NONE ${cnt('NONE')}`, '');
  L.push('## Plugins', '| plugin | risk | hooks | mcp | scripts | reasons (file:line) |', '|---|---|---|---|---|---|');
  for (const p of r.plugins) L.push(`| ${p.key} | ${p.risk} | ${p.hooks.length} | ${p.mcp.length} | ${p.scripts.length} | ${reasons(p.findings).replace(/\|/g, '/')} |`);
  const withHooks = r.plugins.filter((p) => p.hooks.length || p.mcp.length);
  if (withHooks.length) {
    L.push('', '## Hook commands and MCP servers');
    for (const p of withHooks) {
      L.push(`- ${p.key} (${p.root.replace(/\\/g, '/')})`);
      for (const h of p.hooks) L.push(`  - hook ${h.event} [${h.matcher}]: ${h.command}`);
      for (const m of p.mcp) L.push(`  - mcp ${m.name} (${m.type}): ${m.url || m.command}${m.envKeys.length ? ` env:{${m.envKeys.join(',')}}` : ''}`);
    }
  }
  L.push('', `## User config (risk ${r.user.risk})`);
  for (const h of r.user.hooks) L.push(`- ${h.source} hook ${h.event} [${h.matcher}]: ${h.command}`);
  if (r.user.hookFiles.length) L.push(`- ~/.claude/hooks files: ${r.user.hookFiles.join(', ')}`);
  for (const m of r.user.mcp) L.push(`- mcp ${m.name} (${m.source}, ${m.type}): ${m.url || m.command}${m.envKeys.length ? ` env:{${m.envKeys.join(',')}}` : ''}${m.headerKeys.length ? ` headers:{${m.headerKeys.join(',')}}` : ''}`);
  if (r.user.findings.length) L.push(`- findings: ${reasons(r.user.findings, 10)}`);
  if (r.marketplaces.length) {
    L.push('', '## Marketplaces', '| marketplace | repo | ref | risk | flags |', '|---|---|---|---|---|');
    for (const m of r.marketplaces) L.push(`| ${m.name} | ${m.repo} | ${m.ref || '-'} | ${m.risk} | ${m.flags.map((f) => f.desc).join('; ') || '-'} |`);
  }
  if (r.errors.length) L.push('', '## Errors', ...r.errors.map((e) => `- ${e}`));
  return L.join('\n');
}

function loadDeps() {
  try {
    const m = require(path.join(__dirname, '../../../hooks/plugin-integrity.js'));
    return { snapshotPlugins: m.snapshotPlugins, riskyMarketplaces: m.riskyMarketplaces };
  } catch {
    return {};
  }
}

function main() {
  try {
    const argv = process.argv.slice(2);
    const val = (flag) => { const i = argv.indexOf(flag); return i !== -1 ? argv[i + 1] : undefined; };
    const r = auditAll({ cwd: val('--cwd'), claudeHome: val('--claude-home') }, loadDeps());
    process.stdout.write(`${argv.includes('--json') ? JSON.stringify(r, null, 2) : formatReport(r)}\n`);
  } catch (e) {
    process.stdout.write(`plugin-audit error: ${e && e.message}\n`);
  }
  process.exitCode = 0;
}

module.exports = { scanText, packageJsonFlags, hookEntries, mcpEntries, marketplaceFindings, auditAll, formatReport, riskOf, RULES };

if (require.main === module) main();
