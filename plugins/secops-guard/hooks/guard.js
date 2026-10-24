#!/usr/bin/env node
'use strict';
// PreToolUse hook: block an agent reaching for credentials, shipping local files off the box,
// running code it never wrote to disk, installing persistence, or lowering the machine's defenses.
// Deny is sent as JSON on stdout; always exits 0.
//
// This is a guardrail against an agent going off-task, the way a linter is a guardrail against a
// typo. It matches the SHAPE of a command, not a working payload. It is NOT a malware scanner and
// NOT a boundary against a determined attacker: anything here can be spelled around by someone who
// wants to. False positives cost more than misses, so ambiguous shapes are left out.
//
// Regex rules (same as the block-dangerous.js hook):
//  - no `.*` chains or adjacent unbounded quantifiers (ReDoS = hook timeout = fail open);
//    "rest of command segment" is SEG = [^;|&\n]*, so a match never crosses ; | & or newline.
//  - patterns are non-global (exec is stateless).
//  - 'i' is used freely here: these are Windows paths and PowerShell cmdlets, which are
//    case-insensitive in practice, and none of the tokens collide with English prose.

const R = String.raw;
const SEG = R`[^;|&\n]*`;
const TAIL = R`(?![\w.-])`; // file name ends here -> `credentials.example` / `id_rsa.pub` never match
const P = R`(?:^|[\s"'=(@/~])`; // start of a path-ish token (`@` for curl's -d @file form)
// A home directory, however it is spelled. Backslashes are normalised to `/` before matching.
const HOMEP = R`(?:^|[\s"'=(@])(?:~|\$\{?HOME\}?|\$env:USERPROFILE|%USERPROFILE%|/home/[^/\s"']+|(?:[A-Za-z]:)?/[Uu]sers/[^/\s"']+)`;
const PASTE = R`(?:pastebin\.com|paste\.ee|hastebin\.com|dpaste\.(?:com|org)|ix\.io|0x0\.st|termbin\.com|transfer\.sh|file\.io|anonfiles\.com|gofile\.io|bashupload\.com|oshi\.at|webhook\.site|requestbin\.[\w.]+|pipedream\.net|interact\.sh|oast\.(?:pro|live|site|online|fun|me)|burpcollaborator\.net)`;

// The only files in ~/.ssh that are not secret.
const SSH_PUBLIC = R`(?:[^/\s"']+\.pub|known_hosts(?:\.old|2)?|authorized_keys|config|environment|rc)`;

// ---------------------------------------------------------------- 1. credential stores
// Path tails only. Each is a file whose sole purpose is holding a secret.
// Names that are also common project-local files (.npmrc, .netrc, …) require a home prefix.
const CRED_PATHS = [
  // Inverted for ~/.ssh: keys are routinely named after the host or account they belong to
  // (`work_github`), so everything directly in that directory is key material unless it is on the
  // allow set. The trailing (?![\w./-]) keeps it off subdirectories like ~/.ssh/sockets/.
  [R`${P}\.ssh/(?!${SSH_PUBLIC}(?![\w.-]))[^/\s"']+(?![\w./-])`, 'reads a file under ~/.ssh (SSH private key material)'],
  [R`${P}\.aws/credentials${TAIL}`, 'reads the AWS credentials file'],
  [R`${P}\.aws/sso/cache`, 'reads the AWS SSO token cache'],
  [R`${P}\.azure/[^/\s"']*(?:token|credential|service_principal)`, 'reads an Azure token cache or service-principal secret'],
  [R`${P}\.config/gcloud/(?:credentials\.db|access_tokens\.db|application_default_credentials\.json|legacy_credentials)`, 'reads a gcloud credential store'],
  [R`${P}\.kube/config${TAIL}`, 'reads the kubeconfig (cluster credentials)'],
  [`${HOMEP}/\\.docker/config\\.json${TAIL}`, 'reads the Docker registry auth file'],
  [`${HOMEP}/\\.npmrc${TAIL}`, 'reads the npm auth token file (~/.npmrc)'],
  [`${HOMEP}/\\.pypirc${TAIL}`, 'reads the PyPI auth file (~/.pypirc)'],
  [`${HOMEP}/[._]netrc${TAIL}`, 'reads netrc credentials'],
  [`${HOMEP}/\\.git-credentials${TAIL}`, 'reads stored git credentials'],
  [`${HOMEP}/\\.config/gh/hosts\\.yml${TAIL}`, 'reads the GitHub CLI token store'],
  [`${HOMEP}/\\.cargo/credentials\\.toml${TAIL}`, 'reads the crates.io token'],
  [R`(?:Chrome|Chromium|Edge|BraveSoftware|Brave-Browser|Mozilla|Firefox)/[^;|&\n]*/(?:Login Data|Cookies|Local State|logins\.json|key4\.db)${TAIL}`, 'reads a browser saved-login/cookie store'],
];

// Shell verbs that mean "give me the bytes of this file". The HTTP clients are here because an
// upload is only interesting when what it sends is a secret — see EXFIL_CMDS.
const READ_VERB = R`(?:cat|bat|tac|head|tail|less|more|strings|xxd|od|base64|grep|rg|sed|awk|cp|scp|rsync|type|Get-Content|gc|Select-String|sls|Copy-Item|cpi|curl|wget|Invoke-WebRequest|Invoke-RestMethod|iwr|irm|Upload(?:File|String|Data|Values))`;
const CRED_CMDS = [
  ...CRED_PATHS.map(([src, reason]) => [R`\b${READ_VERB}\b${SEG}${src}`, reason]),
  [R`\bcmdkey\b${SEG}\s/list`, 'lists stored Windows credentials (cmdkey /list)'],
  [R`\bvaultcmd(?:\.exe)?\b`, 'lists Windows Credential Manager vaults (vaultcmd)'],
  [R`\bsecurity\s+(?:find-generic-password|find-internet-password|dump-keychain)\b`, 'dumps macOS keychain secrets'],
  // -y reads a private key to print its public half; -t/-f alone create one, which is fine.
  [R`\bssh-keygen\b(?=${SEG}\s-y\b)${SEG}${P}\.ssh/`, 'reads an SSH private key with ssh-keygen -y'],
];

// ---------------------------------------------------------------- 2. local data leaving the machine
// An upload is NOT denied on shape alone: posting a build artifact or a JSON body to an API is
// ordinary development, and denying it costs more than it saves. An upload is denied only when the
// file being sent is a credential store (the HTTP clients are in READ_VERB, so category 1 catches
// it) or when the destination is a throwaway paste/callback service. Accepted gap: exfiltration of
// ordinary project files to an arbitrary host is not caught.
const EXFIL_CMDS = [
  [R`https?://(?:[\w-]{1,63}\.){0,8}${PASTE}`, 'sends data to a throwaway paste/callback service'],
  [R`https?://(?:[\w-]{1,63}\.){0,3}discord(?:app)?\.com/api/webhooks/`, 'sends data to a Discord webhook'],
  [R`https?://api\.telegram\.org/bot`, 'sends data to the Telegram bot API'],
  // a shell that connects outward and reads from the socket
  [R`/dev/tcp/[^\s/]+/\d+`, 'opens a raw outbound socket with bash /dev/tcp'],
  [R`\bn(?:c|cat|etcat)\b${SEG}\s(?:-[A-Za-z]*e[A-Za-z]*\s|--exec\b|--sh-exec\b|--lua-exec\b)`, 'runs a program over a netcat socket (reverse shell shape)'],
  [R`\bsocat\b${SEG}\b(?:exec|system):`, 'runs a program over a socat socket (reverse shell shape)'],
  [R`\bNet\.Sockets\.TcpClient\b(?=[^\n]{0,400}GetStream)`, 'opens a TCP client and reads its stream (reverse shell shape)'],
];

// ---------------------------------------------------------------- 3. code that never hits disk
// `curl | bash` is already covered by the block-dangerous.js hook.
const EXEC_CMDS = [
  [R`\bbase64\s+(?:-d|-D|--decode)\b[^;|&\n]*\|\s*(?:sudo\s+)?(?:bash|sh|zsh|dash|python3?|node|perl|ruby|php|pwsh|powershell)\b`, 'pipes a base64-decoded blob into an interpreter'],
  [R`\bopenssl\s+(?:base64|enc)\b[^;|&\n]*\s-d\b[^;|&\n]*\|\s*(?:sudo\s+)?(?:bash|sh|zsh|python3?|node|pwsh)\b`, 'pipes an openssl-decoded blob into an interpreter'],
  [R`\b(?:powershell(?:\.exe)?|pwsh)\b${SEG}\s-e(?:c|nc|ncodedcommand)?[\s:]+["']?[A-Za-z0-9+/=]{20,}`, 'runs a PowerShell -EncodedCommand blob'],
  [R`\b(?:iex|Invoke-Expression)\b${SEG}(?:DownloadString|DownloadFile|DownloadData|Invoke-WebRequest|Invoke-RestMethod|\biwr\b|\birm\b|Net\.WebClient|https?://)`, 'runs a downloaded payload through Invoke-Expression'],
  [R`(?:DownloadString|DownloadData|Invoke-WebRequest|Invoke-RestMethod)${SEG}\|\s*(?:iex|Invoke-Expression)\b`, 'pipes a download into Invoke-Expression'],
  [R`\[ScriptBlock\]::Create\b${SEG}(?:DownloadString|Invoke-WebRequest|Invoke-RestMethod|\biwr\b|\birm\b|https?://)`, 'builds a script block from a download'],
  [R`\bcertutil(?:\.exe)?\b${SEG}\s[-/](?:urlcache|decode|decodehex)\b`, 'uses certutil as a downloader/decoder'],
  [R`\bbitsadmin(?:\.exe)?\b${SEG}\s/transfer\b`, 'downloads with bitsadmin /transfer'],
  [R`\bmshta(?:\.exe)?\b${SEG}\s["']?(?:https?|javascript|vbscript):`, 'runs remote or inline script through mshta'],
  [R`\bregsvr32(?:\.exe)?\b${SEG}/i:[^\s;|&]*http`, 'loads a remote scriptlet through regsvr32'],
  [R`\brundll32(?:\.exe)?\b${SEG}\bjavascript:`, 'runs inline script through rundll32'],
  // The -c/-e argument is one shell word that may itself contain `;`, so the lookaheads use a
  // bounded line window instead of SEG.
  [R`\bpython3?(?:\.exe)?\b${SEG}\s-c[\s'"](?=[^\n]{0,400}(?:urlopen|urlretrieve|requests\.get|httpx\.get))(?=[^\n]{0,400}(?:exec\(|eval\(|compile\())`, 'python -c that fetches and executes remote code'],
  [R`\bnode(?:\.exe)?\b${SEG}\s-e[\s'"](?=[^\n]{0,400}(?:fetch\(|https?\.get|axios\.get|require\(["']https))(?=[^\n]{0,400}(?:eval\(|new Function|child_process))`, 'node -e that fetches and executes remote code'],
];

// ---------------------------------------------------------------- 4. things that run again later
const PERSIST_CMDS = [
  [R`\bschtasks(?:\.exe)?\b${SEG}\s/create\b`, 'creates a scheduled task'],
  [R`\bRegister-ScheduledTask\b`, 'registers a scheduled task'],
  [R`\breg(?:\.exe)?\s+add\b${SEG}CurrentVersion/Run`, 'writes a Run-key autostart entry'],
  [R`\b(?:New|Set)-ItemProperty\b${SEG}CurrentVersion/Run`, 'writes a Run-key autostart entry'],
  [R`Start Menu/Programs/Startup`, 'writes into the Windows Startup folder'],
  [R`\bsc(?:\.exe)?\s+create\b`, 'creates a Windows service'],
  [R`\bNew-Service\b`, 'creates a Windows service'],
  [R`\b(?:__EventFilter|CommandLineEventConsumer|ActiveScriptEventConsumer)\b`, 'creates a WMI permanent event subscription'],
  [R`\bcrontab\s+-(?=\s|$)`, 'replaces the crontab from stdin'],
  [R`/Library/Launch(?:Agents|Daemons)/`, 'writes a macOS launch job'],
  [R`\blaunchctl\s+(?:load|bootstrap)\b`, 'loads a macOS launch job'],
  [R`/\.config/systemd/user/`, 'installs a user systemd unit'],
  [R`\bsystemctl\s+--user\s+enable\b`, 'enables a user systemd unit'],
  // rc files: only when the appended content fetches or decodes something. A PATH or alias edit is fine.
  [R`\b(?:curl|wget|iwr|irm|Invoke-WebRequest|Invoke-RestMethod|base64|certutil|iex|Invoke-Expression)\b${SEG}>>?\s*["']?[^\s;|&"']*(?:\.bashrc|\.zshrc|\.bash_profile|\.zprofile|\.profile|\$PROFILE|_profile\.ps1)`, 'appends fetch/decode code to a shell startup file'],
  // `| tee <rc file>` is the same write; the fetch sits in the previous segment, so SEG cannot see it.
  [R`\b(?:curl|wget|iwr|irm|Invoke-WebRequest|Invoke-RestMethod|base64|certutil|iex|Invoke-Expression)\b[^\n]{0,300}\|\s*tee\s+(?:-a\s+)?["']?[^\s;|&"']*(?:\.bashrc|\.zshrc|\.bash_profile|\.zprofile|\.profile|\$PROFILE|_profile\.ps1)`, 'pipes fetch/decode code into a shell startup file'],
];

// ---------------------------------------------------------------- 5. lowered defenses / untrusted index
const WEAKEN_CMDS = [
  [R`\b(?:Set|Add)-MpPreference\b`, 'changes Microsoft Defender preferences or exclusions'],
  [R`\bDisableRealtimeMonitoring\b`, 'disables Defender real-time protection'],
  [R`\bnetsh\s+advfirewall\s+set\b${SEG}\bstate\s+off\b`, 'disables the Windows firewall'],
  [R`\bSet-NetFirewallProfile\b${SEG}-Enabled\s+False\b`, 'disables the Windows firewall'],
  [R`\bsystemctl\s+(?:stop|disable)\s+(?:firewalld|ufw)\b`, 'disables the host firewall'],
  [R`\bbcdedit(?:\.exe)?\b${SEG}\s/(?:set|delete|deletevalue|create|import)\b`, 'changes boot configuration (bcdedit)'],
  [R`\bvssadmin\b${SEG}\bdelete\s+shadows\b`, 'deletes volume shadow copies'],
  [R`\bwmic\b${SEG}\bshadowcopy\b${SEG}\bdelete\b`, 'deletes volume shadow copies'],
  [R`\bwevtutil(?:\.exe)?\s+cl\b`, 'clears an event log'],
  [R`\bClear-EventLog\b`, 'clears an event log'],
  [R`\bauditpol(?:\.exe)?\b${SEG}\s/clear\b`, 'clears the audit policy'],
  [R`\bSet-ExecutionPolicy\b(?![^;|&\n]*-Scope\s+(?:Process|CurrentUser))${SEG}\b(?:Bypass|Unrestricted)\b`, 'sets a machine-wide ExecutionPolicy of Bypass/Unrestricted'],
  [R`\bspctl\s+--master-disable\b`, 'disables macOS Gatekeeper'],
  [R`\bcsrutil\s+disable\b`, 'disables macOS System Integrity Protection'],
  [R`\bsetenforce\s+0\b`, 'puts SELinux into permissive mode'],
  [R`\bnpm\s+config\s+set\s+ignore-scripts\s+false\b`, 're-enables npm lifecycle scripts'],
  [R`\bstrict-ssl[\s=]+false\b`, 'disables npm TLS verification (strict-ssl false)'],
  [R`\bNODE_TLS_REJECT_UNAUTHORIZED\s*=\s*["']?0`, 'disables Node TLS verification'],
  [R`\bGIT_SSL_NO_VERIFY\s*=\s*["']?(?:1|true)`, 'disables git TLS verification'],
  [R`\bgit\s+config\b${SEG}\bhttp\.sslverify\s+false\b`, 'disables git TLS verification'],
  [R`--allow-insecure-host\b`, 'disables host verification for a package index'],
  [R`--index-strategy[\s=]+unsafe-best-match\b`, 'uses an unsafe uv index strategy (dependency confusion)'],
];

const SELF_CMDS = [
  [R`\bclaude\s+plugin\s+(?:disable|uninstall|remove)\b${SEG}secops-guard`, 'disables or uninstalls secops-guard'],
  [R`\bSECOPS_DISABLE\b\s*=`, 'sets SECOPS_DISABLE to turn secops-guard off'],
  [R`\bsetx\s+SECOPS_DISABLE\b`, 'sets SECOPS_DISABLE to turn secops-guard off'],
];

// Target paths an agent may never write, whatever the content.
const WRITE_PATHS = [
  [R`Start Menu/Programs/Startup/`, 'writes into the Windows Startup folder'],
  [R`/Library/Launch(?:Agents|Daemons)/`, 'writes a macOS launch job plist'],
  [R`/\.config/systemd/user/`, 'installs a user systemd unit'],
  // Writing these redirects every later install in that tree: the registry, the integrity
  // checks and the cooldown all come from here, and dep-gate reads none of them.
  [R`(?:^|/)(?:\.npmrc|\.yarnrc\.yml|pip\.conf|pip\.ini|uv\.toml|\.pypirc|config\.toml)$`, 'writes a package-manager config, which can redirect the registry or disable integrity checks for every later install'],
];

const ADVICE = {
  cred: 'Credential stores are off-limits to the agent. Ask the user for the value, or read the file yourself outside Claude Code.',
  exfil: 'Local data should not leave this machine as part of a coding task. If the upload is the task, run it yourself outside Claude Code.',
  exec: 'Download to a file, read it, then run it, so the code is reviewable first.',
  persist: 'Nothing should keep running after the task ends. If persistence is the goal, set it up yourself outside Claude Code.',
  weaken: 'Leave the machine\'s defaults alone. For a package index, ask the user to add its host to allowRegistries in ~/.claude/secops-guard/config.json.',
  self: 'secops-guard cannot turn itself off. Two manual escape hatches: edit the file directly outside Claude Code, or set SECOPS_DISABLE=1 in your own shell.',
};

const compile = (list, kind) =>
  list.map(([src, text]) => [new RegExp(src, 'i'), `secops-guard: ${text}. ${ADVICE[kind]}`]);

const CMD_PATTERNS = [
  ...compile(CRED_CMDS, 'cred'),
  ...compile(EXFIL_CMDS, 'exfil'),
  ...compile(EXEC_CMDS, 'exec'),
  ...compile(PERSIST_CMDS, 'persist'),
  ...compile(WEAKEN_CMDS, 'weaken'),
  ...compile(SELF_CMDS, 'self'),
];
const CRED_PATH_PATTERNS = compile(CRED_PATHS, 'cred');
const WRITE_PATH_PATTERNS = compile(WRITE_PATHS, 'persist');
const PATTERNS = [...CMD_PATTERNS, ...CRED_PATH_PATTERNS, ...WRITE_PATH_PATTERNS];

// Example/template/fixture copies of credential files are documentation, not secrets.
const ALLOW_PATH = /(?:example|sample|template|fixture|mock|dummy|\/tests?\/|__tests__|\.dist(?![\w.-]))/i;
const RC_FILE = /(?:\/\.(?:bashrc|zshrc|bash_profile|zprofile|profile)|_profile\.ps1|\/profile\.ps1)$/i;
const SETTINGS_FILE = /\/(?:settings|settings\.local|managed-settings)\.json$/i;
const RC_FETCH = /\b(?:curl|wget|iwr|irm|Invoke-WebRequest|Invoke-RestMethod|certutil|DownloadString|iex|Invoke-Expression)\b|base64\s+(?:-d|-D|--decode)|eval\s+"?\$\(/i;
const MANAGED = /managed-settings\.json(?![\w.-])/i;
// Shell verbs that change or destroy a file (plus any redirect).
// Interpreters are write verbs too: `node -e 'fs.writeFileSync(<state dir>/cache/x, …)'` edits
// our files without ever using a shell redirect, and a poisoned cache turns a deny into an allow.
const MUTATE = /\b(?:rm|rmdir|unlink|shred|mv|move|cp|copy|dd|chmod|chown|attrib|truncate|tee|Remove-Item|Move-Item|Copy-Item|Set-Content|Add-Content|Out-File|New-Item|ni|git)\b|>|\binline_code\b/i;
// An interpreter given code ON THE COMMAND LINE is a write verb: `node -e 'fs.writeFileSync(…)'`
// edits our files with no shell redirect, and a poisoned cache turns a deny into an allow.
// Running a script file (`node guard.js`) is not - that is how these hooks are invoked.
const INLINE_CODE = /\b(?:node|deno|python[\d.]*|py|perl|ruby|php|pwsh|powershell)\b[^\n]{0,80}?\s-(?:e|c|p|-eval|-command|-Command|-EncodedCommand)\b/i;

const MAX_LINE = 10000; // bounds worst-case regex work; an overlong tail of a line is not checked
const clip = (s) => s.split('\n').map((l) => l.slice(0, MAX_LINE)).join('\n');
// Backslashes become `/` so one set of path patterns covers Windows and POSIX.
const slash = (s) => String(s).replace(/\\/g, '/');

// --- writing ABOUT a risky command is not running it ----------------------------------------
// This plugin's own docs, tests and security write-ups are full of the strings it matches, and a
// guardrail that blocks the user's documentation work gets the whole plugin turned off. So a
// pattern only counts when it appears in command position.
// A heredoc body is data the shell never executes, so it is dropped before matching.
const HEREDOC = /<<-?\s*(['"]?)([A-Za-z_]\w*)\1[^\n]*\n[\s\S]{0,20000}?\n[ \t]*\2(?=\s|$)/g;
// ...unless an interpreter is reading it, where the body IS the program: `bash <<EOF` runs it.
const INTERPRETER = /(?:^|[;|&]|\s)\s*(?:sudo\s+)?(?:bash|sh|dash|ksh|zsh|python[\d.]*|node|deno|perl|ruby|php|pwsh|powershell)\b[^\n]{0,200}<</i;
const stripHeredocs = (s) => (INTERPRETER.test(s) ? s : s.replace(HEREDOC, (m) => m.slice(0, m.indexOf('\n'))));
// Commands that only emit or search text: their quoted arguments are strings, not commands.
// awk and sed are NOT here: their quoted argument is a program, not a string, so blanking it
// would hide `awk 'BEGIN{system("…")}'`. tee is out too - its argument is a destination path.
const TEXT_TOOL = /^\s*(?:sudo\s+)?(?:[A-Za-z_]\w*=\S*\s+)*(?:#|(?:echo|printf|jq|yq|grep|egrep|fgrep|rg|ag|ack|diff|comm|Write-Host|Write-Output|Write-Error|Write-Information|git\s+(?:commit|tag|notes)|gh\s+(?:issue|pr)\s+(?:create|comment|review|edit)|gh\s+(?:release|gist)\s+create)\b)/;
const QUOTED = /'[^']*'|"[^"]*"/g;
// Quoted text is only inert if the shell will not evaluate it: `echo "$(cat ~/.ssh/id_rsa)"`
// runs the substitution before echo ever sees it.
const SUBST = /\$\(|`|\$\{?[A-Za-z_]/;

// Split on ; | & and newline, keeping the separator, without splitting inside quotes.
function segments(s) {
  const out = [];
  let cur = '';
  let q = null;
  for (const ch of s) {
    if (q) { cur += ch; if (ch === q) q = null; continue; }
    if (ch === '"' || ch === "'") { q = ch; cur += ch; continue; }
    if (ch === ';' || ch === '|' || ch === '&' || ch === '\n') { out.push([cur, ch]); cur = ''; continue; }
    cur += ch;
  }
  out.push([cur, '']);
  return out;
}

// Blank the quoted arguments of a text-producing segment — unless it redirects to a file, where
// the text is being persisted somewhere that may run it later.
const maskDescriptions = (s) => segments(s)
  .map(([text, sep]) => (TEXT_TOOL.test(text) && !SUBST.test(text) && !/>/.test(text.replace(QUOTED, ' ')) ? text.replace(QUOTED, ' ') : text) + sep)
  .join('');

const DEFAULT_REGISTRIES = ['registry.npmjs.org', 'pypi.org', 'files.pythonhosted.org', 'download.pytorch.org', 'crates.io', 'index.crates.io'];
const LOCAL_HOSTS = new Set(['localhost', '127.0.0.1', '::1', '[::1]', 'host.docker.internal']);

let _cfg;
function cfg() {
  if (_cfg) return _cfg;
  try {
    _cfg = require('./lib/config.js').loadConfig();
  } catch {
    const os = require('node:os');
    const path = require('node:path');
    _cfg = { allowRegistries: DEFAULT_REGISTRIES, stateDir: process.env.SECOPS_STATE_DIR || path.join(os.homedir(), '.claude', 'secops-guard') };
  }
  if (!Array.isArray(_cfg.allowRegistries) || !_cfg.allowRegistries.length) _cfg.allowRegistries = DEFAULT_REGISTRIES;
  return _cfg;
}

function homeDir() {
  try { return slash(require('node:os').homedir()); } catch { return ''; }
}

// Paths this hook protects from the agent: the LIVE install only. A development checkout anywhere
// else is ordinary source code — refusing to edit it would make this repo unmaintainable through
// Claude Code and would protect nothing, since that copy is not the one guarding the machine.
// `hooks/secops-guard/` covers a plain (non-plugin) install: hook files copied straight into
// ~/.claude/hooks/ and wired up in settings.json. Without it the installed hooks do not
// protect themselves, which is how this was found.
const SELF_INSTALL = /\/\.claude\/(?:secops-guard\/|hooks\/secops-guard\/|plugins\/(?:[^\n]{0,300}\/)?secops-guard\/)/i;
function selfPaths() {
  const claudeHome = `${homeDir().toLowerCase()}/.claude`;
  const out = [];
  for (const p of [cfg().stateDir, process.env.CLAUDE_PLUGIN_ROOT || require('node:path').join(__dirname, '..')]) {
    const n = slash(p).toLowerCase().replace(/\/+$/, '');
    if (n && n.startsWith(`${claudeHome}/`)) out.push(n);
  }
  return out;
}

const hostOf = (v) => {
  const m = /^(?:[a-z][a-z0-9+.-]*:\/\/)?(?:[^/@\s]*@)?([^/:\s]+)/i.exec(v);
  return m ? m[1].toLowerCase() : '';
};

// --registry / --index-url / … pointed at a host the user has not vouched for.
function checkRegistry(norm) {
  const allow = cfg().allowRegistries.map((h) => String(h).toLowerCase());
  for (const seg of norm.split(/[;|&\n]/)) {
    const flags = [...seg.matchAll(/(?:--registry|--index-url|--extra-index-url|--default-index|--trusted-host)[=\s]+["']?([^\s"';|&]+)/gi)];
    if (/\b(?:pip3?|uv|uvx|pipx|poetry)\b/i.test(seg)) {
      flags.push(...seg.matchAll(/(?:^|\s)-i[=\s]+["']?([^\s"';|&-][^\s"';|&]*)/g));
    }
    // Env vars and alternate config files redirect the registry just as well as a flag, and
    // were invisible here: the version gets verified against npmjs while the bytes come from
    // somewhere else. npm maps any npm_config_<key>, so this covers --registry's env form too.
    for (const m of seg.matchAll(/(?:^|\s)(?:npm_config_registry|NPM_CONFIG_REGISTRY|PIP_INDEX_URL|PIP_EXTRA_INDEX_URL|UV_INDEX_URL|UV_DEFAULT_INDEX|POETRY_REPOSITORIES_[A-Z0-9_]+_URL)=["']?([^\s"';|&]+)/g)) {
      const h = hostOf(m[1]);
      if (!h || LOCAL_HOSTS.has(h) || allow.includes(h)) continue;
      return `secops-guard: redirects the package registry to an untrusted host (${h}) with an environment variable. ${ADVICE.weaken}`;
    }
    if (/(?:^|\s)--(?:userconfig|globalconfig)[=\s]/i.test(seg) && /\b(?:npm|pnpm|yarn|bun)\b/i.test(seg)) {
      return `secops-guard: points npm at a different config file, which can change the registry and the integrity settings for this install. ${ADVICE.weaken}`;
    }
    for (const m of flags) {
      const h = hostOf(m[1]);
      if (!h || LOCAL_HOSTS.has(h) || allow.includes(h)) continue;
      return `secops-guard: points a package manager at an untrusted index host (${h}). ${ADVICE.weaken}`;
    }
  }
  return null;
}

function checkCommand(command) {
  if (typeof command !== 'string' || !command.trim()) return null;
  const base = maskDescriptions(stripHeredocs(slash(clip(command))));
  // `ssh -i ~/.ssh/id_ed25519 host` and `-o IdentityFile=…` are using a key, not reading it.
  // Only for the ssh family: elsewhere `-i` is a package index, which checkRegistry needs intact.
  // Per segment: the bare word `rsync` in an echo must not disarm `-i <index>` checking for a
  // pip install later in the same line. Only a segment that IS an ssh-family command is neutered.
  const norm = segments(base)
    .map(([text, sep]) => (/^\s*(?:sudo\s+)?(?:ssh|scp|sftp|rsync)\b/i.test(text)
      ? text.replace(/(^|\s)-i\s+\S+/g, '$1-i ').replace(/IdentityFile=\S+/gi, 'IdentityFile=')
      : text) + sep)
    .join('');
  for (const [re, reason] of CMD_PATTERNS) if (re.test(norm)) return reason;
  const home = homeDir().toLowerCase();
  const lower = home
    ? norm.toLowerCase().replace(/~\//g, `${home}/`).replace(/\$\{?home\}?\//g, `${home}/`)
    : norm.toLowerCase();
  // Only when something is actually being written: `grep -r disableAllHooks .` is research.
  // Per segment, so the write verb and the target must be in the SAME command: otherwise
  // `rm -rf build && cat <installed>/guard.js` reads as a rewrite of guard.js.
  for (const [rawSeg] of segments(norm)) {
    // Discarding output is not a write: `diff a b > /dev/null` and `cmd 2>&1` must not read
    // as mutation just because they contain a redirect operator.
    const seg = rawSeg.replace(/\d?>>?\s*\/dev\/null/g, ' ').replace(/\d?>&\d/g, ' ');
    if (!MUTATE.test(seg) && !INLINE_CODE.test(seg)) continue;
    const segLower = home
      ? seg.toLowerCase().replace(/~\//g, `${home}/`).replace(/\$\{?home\}?\//g, `${home}/`)
      : seg.toLowerCase();
    if (/\bdisableAllHooks\b/i.test(seg)) return `secops-guard: turns off all Claude Code hooks. ${ADVICE.self}`;
    if (MANAGED.test(seg)) return `secops-guard: rewrites Claude Code managed settings. ${ADVICE.self}`;
    if (SELF_INSTALL.test(segLower) || selfPaths().some((p) => segLower.includes(p))) {
      return `secops-guard: rewrites or deletes the installed secops-guard. ${ADVICE.self}`;
    }
  }
  return checkRegistry(norm);
}

function checkPaths(tool, input) {
  const home = homeDir();
  const raw = [input.file_path, input.path, input.notebook_path, input.pattern];
  const paths = raw.filter((v) => typeof v === 'string' && v).map((v) => {
    const s = slash(v);
    return home && s.toLowerCase().startsWith(home.toLowerCase()) ? `~${s.slice(home.length)}` : s;
  });
  const writing = tool !== 'Read' && tool !== 'Grep' && tool !== 'Glob';

  for (const p of paths) {
    if (ALLOW_PATH.test(p)) continue;
    if (!writing) {
      for (const [re, reason] of CRED_PATH_PATTERNS) if (re.test(p)) return reason;
      continue;
    }
    for (const [re, reason] of WRITE_PATH_PATTERNS) if (re.test(p)) return reason;
    if (MANAGED.test(p)) return `secops-guard: edits Claude Code managed settings. ${ADVICE.self}`;
    const lower = p.toLowerCase();
    const abs = (home && lower.startsWith('~') ? home.toLowerCase() + lower.slice(1) : lower);
    if (SELF_INSTALL.test(abs) || selfPaths().some((s) => abs.startsWith(`${s}/`))) {
      return `secops-guard: edits the installed secops-guard. ${ADVICE.self}`;
    }
  }
  if (!writing) return null;

  // Content is only inspected for the two cases where the file itself makes code run again: a
  // settings file and a shell startup file. Documentation that describes an attack is not one.
  const body = newContent(input);
  if (!body) return null;
  if (paths.some((p) => SETTINGS_FILE.test(p)) && /\bdisableAllHooks\b/i.test(body)) {
    return `secops-guard: turns off all Claude Code hooks. ${ADVICE.self}`;
  }
  if (paths.some((p) => RC_FILE.test(p)) && RC_FETCH.test(clip(body))) {
    return `secops-guard: adds fetch/decode code to a shell startup file, so it runs in every future shell. ${ADVICE.persist}`;
  }
  return null;
}

function newContent(input) {
  const parts = [input.content, input.new_string, input.new_source];
  if (Array.isArray(input.edits)) for (const e of input.edits) if (e && typeof e.new_string === 'string') parts.push(e.new_string);
  return parts.filter((v) => typeof v === 'string').join('\n');
}

function check(payload) {
  try {
    if (process.env.SECOPS_DISABLE === '1') return null;
    if (!payload || typeof payload !== 'object') return null;
    const tool = payload.tool_name;
    const input = payload.tool_input;
    if (!input || typeof input !== 'object') return null;
    if (tool === 'Bash' || tool === 'PowerShell') return checkCommand(input.command);
    if (tool === 'Read' || tool === 'Grep' || tool === 'Glob' || tool === 'Edit' || tool === 'Write' || tool === 'MultiEdit' || tool === 'NotebookEdit') {
      return checkPaths(tool, input);
    }
    return null;
  } catch {
    return null; // a guardrail that crashes the tool call is worse than a miss
  }
}

function main() {
  try {
    const payload = JSON.parse(require('node:fs').readFileSync(0, 'utf8'));
    const reason = check(payload);
    if (!reason) return;
    try {
      require('./lib/io.js').preDeny(reason);
    } catch {
      process.stdout.write(JSON.stringify({
        hookSpecificOutput: { hookEventName: 'PreToolUse', permissionDecision: 'deny', permissionDecisionReason: reason },
      }));
    }
  } catch {
    // malformed input or any error -> never block
  }
}

module.exports = { PATTERNS, CMD_PATTERNS, CRED_PATH_PATTERNS, WRITE_PATH_PATTERNS, check, checkCommand };
if (require.main === module) main();
