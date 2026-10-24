#!/usr/bin/env node
'use strict';

// Shared by install.ps1 and install.sh: JSON deep-merge is the one part of the
// installer that is genuinely painful to write twice (PowerShell 5.1 and bash),
// so both shell out to this. Node is already required by the plugin's hooks.
//
// Usage:
//   node merge-settings.js <settings.json> <snippet.json> [options]
// Options:
//   --apply                 write the file (default: print the diff and exit)
//   --remove                subtract the snippet instead of merging it (uninstall)
//   --enable <pluginKey>    set enabledPlugins[key] = true
//   --marketplace <n>=<p>   add extraKnownMarketplaces[n] from a local directory
//   --quiet                 only print the summary line

const fs = require('fs');
const path = require('path');

function die(msg) {
  process.stderr.write('secops-guard: ' + msg + '\n');
  process.exit(1);
}

function parseArgs(argv) {
  const out = { positional: [], apply: false, remove: false, quiet: false, enable: null, marketplace: null };
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    if (a === '--apply') out.apply = true;
    else if (a === '--remove') out.remove = true;
    else if (a === '--quiet') out.quiet = true;
    else if (a === '--no-snippet') out.noSnippet = true;
    else if (a === '--enable') out.enable = argv[++i];
    else if (a === '--marketplace') out.marketplace = argv[++i];
    else if (a.startsWith('--')) die('unknown option ' + a);
    else out.positional.push(a);
  }
  return out;
}

function readJson(file, fallback) {
  if (!fs.existsSync(file)) return fallback;
  const raw = fs.readFileSync(file, 'utf8');
  if (raw.trim() === '') return fallback;
  try {
    return JSON.parse(raw);
  } catch (e) {
    die(file + ' is not valid JSON (' + e.message + '). Fix it by hand before running the installer.');
  }
}

const isObj = (v) => v !== null && typeof v === 'object' && !Array.isArray(v);
const same = (a, b) => JSON.stringify(a) === JSON.stringify(b);

// Deep-merges src into dst in place. Objects merge key by key, arrays union by
// value (order preserved, existing entries first), scalars are only written when
// the key is absent - an existing user value is never overwritten.
function merge(dst, src, prefix, changes) {
  for (const key of Object.keys(src)) {
    const at = prefix + (/^[A-Za-z_][A-Za-z0-9_]*$/.test(key) ? '.' + key : '[' + JSON.stringify(key) + ']');
    const want = src[key];
    if (!(key in dst)) {
      // Seed an empty container first so the diff lists each added entry on its
      // own line instead of dumping one enormous array.
      if (isObj(want)) dst[key] = {};
      else if (Array.isArray(want)) dst[key] = [];
      else {
        dst[key] = want;
        changes.push('+ ' + at.slice(1) + ' = ' + JSON.stringify(want));
        continue;
      }
    }
    if (isObj(want) && isObj(dst[key])) {
      merge(dst[key], want, at, changes);
    } else if (Array.isArray(want) && Array.isArray(dst[key])) {
      for (const item of want) {
        if (!dst[key].some((existing) => same(existing, item))) {
          dst[key].push(item);
          changes.push('+ ' + at.slice(1) + '[] ' + JSON.stringify(item));
        }
      }
    } else if (!same(dst[key], want)) {
      // A scalar the user already set differently. Theirs wins - say so, do not clobber.
      changes.push('  (kept your value) ' + at.slice(1) + ' = ' + JSON.stringify(dst[key]) +
        '   [snippet wanted ' + JSON.stringify(want) + ']');
    }
  }
}

// Inverse of merge: drops exactly what the snippet contributes, leaves the rest.
function remove(dst, src, prefix, changes) {
  for (const key of Object.keys(src)) {
    if (!(key in dst)) continue;
    const at = prefix + (/^[A-Za-z_][A-Za-z0-9_]*$/.test(key) ? '.' + key : '[' + JSON.stringify(key) + ']');
    const want = src[key];
    if (isObj(want) && isObj(dst[key])) {
      remove(dst[key], want, at, changes);
      if (Object.keys(dst[key]).length === 0) delete dst[key];
    } else if (Array.isArray(want) && Array.isArray(dst[key])) {
      for (const item of want) {
        const i = dst[key].findIndex((existing) => same(existing, item));
        if (i >= 0) {
          dst[key].splice(i, 1);
          changes.push('- ' + at.slice(1) + '[] ' + JSON.stringify(item));
        }
      }
      if (dst[key].length === 0) delete dst[key];
    } else if (same(dst[key], want)) {
      delete dst[key];
      changes.push('- ' + at.slice(1));
    }
  }
}

function stamp() {
  const d = new Date();
  const p = (n) => String(n).padStart(2, '0');
  return '' + d.getFullYear() + p(d.getMonth() + 1) + p(d.getDate()) + p(d.getHours()) + p(d.getMinutes()) + p(d.getSeconds());
}

function main() {
  const args = parseArgs(process.argv.slice(2));
  const [settingsPath, snippetPath] = args.positional;
  if (!settingsPath || !snippetPath) die('usage: merge-settings.js <settings.json> <snippet.json> [--apply] [--remove] [--enable key] [--marketplace name=path]');
  if (!fs.existsSync(snippetPath)) die('snippet not found: ' + snippetPath);

  const settings = readJson(settingsPath, {});
  // --no-snippet: skip the permission deny rules but still allow --enable /
  // --marketplace to register the plugin in the same file.
  const snippet = args.noSnippet ? {} : readJson(snippetPath, {});

  // Plugin registration is part of the same file, so it rides along with the merge.
  if (args.enable) {
    snippet.enabledPlugins = Object.assign({}, snippet.enabledPlugins);
    snippet.enabledPlugins[args.enable] = true;
  }
  if (args.marketplace) {
    const eq = args.marketplace.indexOf('=');
    if (eq < 0) die('--marketplace expects <name>=<path>');
    const name = args.marketplace.slice(0, eq);
    const dir = path.resolve(args.marketplace.slice(eq + 1));
    snippet.extraKnownMarketplaces = Object.assign({}, snippet.extraKnownMarketplaces);
    // UNVERIFIED shape for a local directory source - `claude plugin marketplace add`
    // is the authoritative route and the installer prefers it when the CLI is present.
    snippet.extraKnownMarketplaces[name] = { source: { source: 'directory', path: dir } };
  }

  const changes = [];
  (args.remove ? remove : merge)(settings, snippet, '', changes);

  if (changes.length === 0) {
    if (!args.quiet) process.stdout.write('  no change needed: ' + settingsPath + '\n');
    return;
  }

  if (!args.quiet) {
    process.stdout.write('--- ' + settingsPath + '\n');
    process.stdout.write('+++ ' + settingsPath + '  (secops-guard ' + (args.remove ? 'uninstall' : 'merge') + ')\n');
    for (const c of changes) process.stdout.write('  ' + c + '\n');
  }

  if (!args.apply) {
    process.stdout.write('  [dry run] ' + changes.length + ' change(s) not written\n');
    return;
  }

  // Parse the exact bytes we are about to write BEFORE touching the file. This is the
  // highest-risk file on the machine - a corrupt settings.json breaks Claude Code at
  // next launch. If this throws, nothing has been written yet.
  const text = JSON.stringify(settings, null, 2) + '\n';
  try {
    JSON.parse(text);
  } catch (e) {
    die('refusing to write ' + settingsPath + ': the merged result does not parse (' + e.message + '). Nothing was changed.');
  }

  if (fs.existsSync(settingsPath)) {
    // Never clobber an existing backup: two runs inside the same second would
    // otherwise destroy the original copy.
    const base = settingsPath + '.secops-bak-' + stamp();
    let backup = base;
    for (let n = 2; fs.existsSync(backup); n++) backup = base + '-' + n;
    fs.copyFileSync(settingsPath, backup);
    process.stdout.write('  backup: ' + backup + '\n');
    process.stdout.write('  restore with: copy "' + backup + '" "' + settingsPath + '"\n');
  } else {
    fs.mkdirSync(path.dirname(settingsPath), { recursive: true });
  }
  fs.writeFileSync(settingsPath, text, 'utf8');
  // Read it back off disk too, so a truncated or re-encoded write is caught here.
  readJson(settingsPath, null);
  process.stdout.write('  wrote ' + settingsPath + ' (' + changes.length + ' change(s))\n');
}

if (require.main === module) main();
module.exports = { merge, remove };
