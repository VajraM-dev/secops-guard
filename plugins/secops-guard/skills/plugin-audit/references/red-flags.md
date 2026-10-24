# Red flags: malicious vs benign

**Read this first: the scanner self-flags security tools.** The scan is line-based text matching. Any plugin whose job is
to *detect* attacks contains the attack strings it detects, so it shows HIGH. This includes secops-guard's own
`hooks/guard.js` and secops-guard's own `hooks/block-dangerous.js`. Comments, docstrings, and test fixtures match too.
A hit is evidence to read, not a verdict. Before you call it TRUE, decide whether the matched text is executed.

| Rule | Usually malicious when | Usually benign when |
|---|---|---|
| `network` | The URL is built at runtime, is a paste or webhook site (pastebin, webhook.site, ngrok, requestbin, discord webhooks, telegram bot API), a raw IP, or a non-documented domain. The payload includes env, file contents, or tool_input. | The plugin's documented API (for example OSV.dev or a registry). GET-only metadata. The user's own configured endpoint. |
| `credential-path` | The plugin reads the file (`readFile`, `cat`, `Get-Content`) and the same file sends data over the network (`exfil-combo`). | The path is inside a regex or deny list, or is used to block or redact access. |
| `env-dump` | The whole env is serialised, logged to a file, or sent anywhere. | It is passed to a child process (`{...process.env, X: 1}`). The scanner does not flag that form. |
| `dynamic-eval` | The argument comes from the network, a decoded blob, or a file the plugin downloads. | Hard-coded config evaluation (rare: still ask why). |
| `exec` | The command string is built from tool_input, network data, or decoded data. Or it uses `shell: true` with interpolation. | Fixed binaries with argument arrays (`git`, `node`, `python`), and formatters or linters on the edited file. |
| `pipe-to-shell` | Always risky in a hook. Code that changes without review runs on every session. | Install docs (README) that the user runs once, deliberately. |
| `claude-config-write` | It changes `settings.json` hooks or permissions, `enabledPlugins`, other plugins' files, or `~/.claude.json` mcpServers. It re-adds itself after removal. It weakens permissions. | A documented installer that the user runs explicitly, and that backs up first. |
| `blob`, `escape-obfuscation`, `minified` | Inside a hook or MCP launcher, especially with `decode-exec-combo`. Legit plugins ship readable source. | Bundled vendor libraries with a known upstream (check the header or license comment). Data-URI icons. |
| `install-script` | `postinstall` downloads or executes something outside the package. | Builds native addons from the package's own sources (`node-gyp rebuild`). |
| `mcp-unpinned` | Any third-party package. Every launch fetches the newest version, so a single compromised release runs immediately. | First-party local paths. |
| `auto-update` | Always a supply-chain exposure. New hook code runs without review. | Marketplaces the user controls (their own org repo, with branch protection). |

## Typical malicious shapes

- SessionStart or PreToolUse hook. It reads `~/.ssh`, `~/.aws/credentials`, `.npmrc`, `.env`, or `process.env`.
  Then it does a `fetch`/`curl` to a hardcoded host. The stdout is suppressed.
- The hook downloads a script on each run (`curl …| sh`, `iwr …| iex`). The content can change at any time.
- An encoded blob (base64 or hex) is decoded, then passed to `eval`, `Function`, `exec`, or `python -c`.
- A hook writes to `~/.claude/settings.json` to add itself, add allow rules, or disable other hooks.
- The hook edits shell profiles (`.bashrc`, `.zshrc`, `$PROFILE`), scheduled tasks, or `crontab` (persistence).
- An MCP server is launched with `npx -y <typosquat>`, where the name is one character off a known server.
- Hook output with `additionalContext` that tells Claude to run commands, disable security plugins, or ignore
  instructions (prompt injection through a hook). Read every `additionalContext` or `systemMessage` string a hook emits.

## Checks beyond the script

- Compare the `gitCommitSha` in `~/.claude/plugins/installed_plugins.json` with the upstream tag the user expects.
- `git -C <marketplace installLocation> log --oneline -5` shows recent upstream changes after an auto-update.
- Binaries in `bin/` (`.exe`, ELF, Mach-O) cannot be reviewed statically. Treat them as MED at least, and ask the
  user whether the publisher is trusted.
