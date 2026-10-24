#!/usr/bin/env node
'use strict';
// PreToolUse hook: block dangerous shell commands (Bash and PowerShell tools).
// Deny is sent as JSON on stdout; always exits 0.
// A denylist for honest mistakes, not adversaries. Rules for every pattern:
//  - no `.*` chains or adjacent overlapping unbounded quantifiers (ReDoS = hook timeout = fail open);
//    "rest of command segment" is spelled SEG = [^;|&\n]* so it never crosses ; | & or newline.
//  - case-sensitive by default; 'i' only where the language is (PowerShell/cmd, DROP/ALTER).
//  - SQL DML (DELETE/UPDATE/TRUNCATE) is uppercase-only, so prose like `git commit -m "truncate long
//    names"` or "delete from list" passes; lowercase SQL slips through (accepted trade-off).

const R = String.raw;
const SEG = R`[^;|&\n]*`;
const END = R`(?=\s|$|[;&|])`; // end of a shell word
const PROTECTED = R`(?:main|master|release|prod|production)\b`;
const WIN_ROOT = R`["']?(?:[a-z]:[\\/]?|~[\\/]?|\$HOME[\\/]?|\$env:USERPROFILE[\\/]?)\*?["']?`;
const DANGEROUS_PATTERNS = [
  // ---------- Filesystem destroy (POSIX) ----------
  // any recursive flag form (-rf, -fr, -r -f, --recursive --force), target /, ~, $HOME, ., .., * (+ trailing / or /*)
  [R`\brm\s+(?=(?:-[\w-]+\s+)*(?:-[a-zA-Z]*[rR]|--recursive\b))(?:-[\w-]+\s+)+["']?(?:/|~|\$\{?HOME\}?|\.{1,2}|\*)/?\*?["']?${END}`, 'rm -rf on root/home/cwd/glob'],
  [R`--no-preserve-root`, 'rm safety bypass'],
  [R`\bfind\s+[^|;&\n]*\s-(delete|exec\s+rm)\b`, 'find with -delete or -exec rm'],
  [R`\bdd\s+[^|;&\n]*of=/dev/(sd|nvme|hd|xvd|vd)`, 'dd writing to raw block device'],
  [R`\bmkfs(\.\w+)?\s+/dev/`, 'mkfs on block device'],
  [R`\bshred\b`, 'shred (unrecoverable wipe)'],
  [R`\bchmod\s+-R\s+(000|777)\s+/`, 'chmod -R 000/777 on /'],
  [R`\bchown\s+-R\s+\S+\s+/`, 'chown -R on /'],
  [R`\bmv\s+/etc\b`, 'moving /etc'],
  [R`>\s*/etc/(passwd|shadow|sudoers|fstab|hosts)\b`, 'overwriting critical /etc file'],
  [R`\btruncate\s+-s\s*0\s+/etc/`, 'truncating /etc file'],

  // ---------- Windows destroy ----------
  [R`\b(?:del|erase)\s+(?:/[a-z]\s+)+${WIN_ROOT}${END}`, 'del /F /S /Q on drive root', 'i'],
  [R`\b(?:rmdir|rd)\s+(?:/[a-z]\s+)+${WIN_ROOT}${END}`, 'rmdir /S /Q on drive root', 'i'],
  [R`\bformat\s+[A-Za-z]:`, 'format drive', 'i'],
  // Remove-Item/ri/rm with -Recurse and -Force anywhere in the segment, any target position (incl. -Path X)
  [R`\b(?:Remove-Item|ri|rm)\b(?=${SEG}\s-r(?:ecurse)?\b)(?=${SEG}\s-fo(?:rce)?\b)[^;|&\n]*?\s${WIN_ROOT}${END}`, 'PowerShell recursive force delete on drive', 'i'],
  [R`\bcipher\s+/w:[A-Za-z]:`, 'cipher /w wipe', 'i'],

  // ---------- Git destroy (case-sensitive: -d vs -D, -f vs -F matter) ----------
  // --force / -f as a whole word anywhere in the segment; --force-with-lease never matches `--force${END}`
  [R`\bgit\s+push\b(?=${SEG}\s(?:--force|-f)${END})${SEG}[\s+:]${PROTECTED}`, 'git force-push to protected branch'],
  [R`\bgit\s+push\b${SEG}\s\+(?:[\w./-]*:)?${PROTECTED}`, 'git force-push to protected branch'],
  [R`\bgit\s+reset\s+--hard\b`, 'git reset --hard'],
  [R`\bgit\s+clean\s+(?:-[a-zA-Z]*[fdx]{2,}|-[fdx]\s+-[fdx])`, 'git clean -fdx'],
  [R`\bgit\s+checkout\s+\.(\s|$)`, 'git checkout . (discard all)'],
  [R`\bgit\s+restore\s+\.(\s|$)`, 'git restore . (discard all)'],
  [R`\bgit\s+branch\s+-D\b`, 'git branch -D (force delete unmerged)'],
  [R`\bgit\s+reflog\s+expire\b${SEG}--expire=now`, 'git reflog expire (destroy recovery)'],
  [R`\bgit\s+gc\b${SEG}--prune=now`, 'git gc --prune=now'],
  [R`\bgit\s+filter-(branch|repo)\b`, 'git history rewrite'],
  [R`\bgit\s+update-ref\s+-d\b`, 'git update-ref -d'],

  // ---------- Database destroy ----------
  // Table names may be schema-qualified/quoted. `(?![\w."])` stops the name from backtracking;
  // WHERE lookahead is bounded so it stays linear (WHERE >2000 chars away => blocked, fail-safe).
  [R`\bDROP\s+(DATABASE|SCHEMA|TABLE|INDEX)\b`, 'DROP statement', 'i'],
  [R`\bTRUNCATE\s+(TABLE\s+)?[\w."]+`, 'TRUNCATE table'],
  [R`\bDELETE\s+FROM\s+[\w."]+(?![\w."])(?![^;]{0,2000}\bWHERE\b)`, 'DELETE without WHERE'],
  [R`\bUPDATE\s+[\w."]+\s+SET\b(?![^;]{0,2000}\bWHERE\b)`, 'UPDATE without WHERE'],
  [R`\bALTER\s+TABLE\s+[\w."]+\s+DROP\s+COLUMN\b`, 'ALTER TABLE DROP COLUMN', 'i'],
  [R`\bdb\.dropDatabase\s*\(`, 'MongoDB dropDatabase'],
  [R`\.remove\s*\(\s*\{\s*\}\s*\)`, 'Mongo remove({}) all docs'],
  [R`\.deleteMany\s*\(\s*\{\s*\}\s*\)`, 'Mongo deleteMany({}) all docs'],

  // ---------- Process / system ----------
  [R`\bkill\s+-9\s+1\b`, 'kill -9 1 (init)'],
  [R`:\(\)\s*\{\s*:\s*\|\s*:\s*&\s*\}\s*;\s*:`, 'fork bomb'],
  [R`\biptables\s+-F\b`, 'iptables flush'],
  [R`\bufw\s+disable\b`, 'ufw disable'],
  [R`\bsystemctl\s+(stop|disable)\s+(sshd|ssh)\b`, 'stop/disable sshd'],
  [R`\bcrontab\s+-r\b`, 'crontab -r (wipe all cron)'],
  [R`\bpasswd\s+root\b`, 'change root password'],

  // ---------- Package / dependency ----------
  [R`\bcurl\s+[^|;&\n]*\|\s*(sudo\s+)?(bash|sh|zsh|python3?|node|pwsh)\b`, 'curl piped to shell'],
  [R`\bwget\s+[^|;&\n]*-O-\s*\|\s*(sudo\s+)?(bash|sh|zsh|python3?|node|pwsh)\b`, 'wget piped to shell'],
  [R`\b(?:iwr|irm|Invoke-WebRequest|Invoke-RestMethod)\b[^|;&\n]*\|\s*(?:iex|Invoke-Expression)\b`, 'download piped to iex', 'i'],
  [R`\brm\s+-rf?\s+(node_modules|package-lock\.json|yarn\.lock|pnpm-lock\.yaml)\b${SEG}(package-lock|yarn\.lock|pnpm-lock|node_modules)`, 'wiping node_modules + lockfile'],

  // ---------- Cloud / infra ----------
  [R`\bterraform\s+destroy\b`, 'terraform destroy'],
  [R`\bkubectl\s+delete\s+(ns|namespace)\s+(prod|production)`, 'kubectl delete prod namespace'],
  [R`\bkubectl\s+delete\s+--all\b`, 'kubectl delete --all'],
  [R`\baws\s+s3\s+rb\s+s3://\S+\s+--force\b`, 'aws s3 rb --force'],
  [R`\baws\s+s3\s+rm\s+s3://\S+\s+--recursive\b`, 'aws s3 rm --recursive'],
  [R`\bgcloud\s+projects\s+delete\b`, 'gcloud projects delete'],
  [R`\baz\s+group\s+delete\b`, 'az group delete'],
  [R`\bdocker\s+system\s+prune\b${SEG}\s--volumes\b`, 'docker system prune --volumes'],
  [R`\bdocker\s+rm\s+-f\s+\$\(\s*docker\s+ps\s+-aq\s*\)`, 'docker rm -f all containers'],
  [R`\bdocker\s+volume\s+rm\s+\$\(\s*docker\s+volume\s+ls\s+-q\s*\)`, 'docker volume rm all'],
];

const PATTERNS = DANGEROUS_PATTERNS.map(([src, reason, flags = '']) => [new RegExp(src, flags), reason]);

const MAX_LINE = 10000; // per-line cap bounds worst-case regex work; overlong tail of a line is not checked

function check(command) {
  const text = command.split('\n').map((l) => l.slice(0, MAX_LINE)).join('\n');
  for (const [re, reason] of PATTERNS) {
    const m = re.exec(text);
    if (m) return { reason, matched: m[0] };
  }
  return null;
}

function main() {
  try {
    const payload = JSON.parse(require('node:fs').readFileSync(0, 'utf8'));
    if (payload.tool_name !== 'Bash' && payload.tool_name !== 'PowerShell') return; // null payload throws -> caught
    const command = (payload.tool_input || {}).command;
    if (typeof command !== 'string' || !command.trim()) return;
    const hit = check(command);
    if (!hit) return;
    process.stdout.write(JSON.stringify({
      hookSpecificOutput: {
        hookEventName: 'PreToolUse',
        permissionDecision: 'deny',
        permissionDecisionReason:
          `Blocked by block-dangerous hook: ${hit.reason}. ` +
          `Matched pattern fragment: '${hit.matched.slice(0, 120)}'. ` +
          'If intentional, run manually outside Claude Code.',
      },
    }));
  } catch {
    // malformed input or any error -> never block
  }
}

module.exports = { PATTERNS, check };
if (require.main === module) main();
