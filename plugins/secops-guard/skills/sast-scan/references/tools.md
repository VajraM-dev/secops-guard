# Tool commands

`$OUT` is the scratchpad directory. `<dir>` is the scan root.
Diff mode: pass the changed-file list instead of `<dir>` where the tool accepts paths.

## Pinning ephemeral tools

Never run an unpinned `uvx tool` or a `:latest` image. First resolve the newest version that is at least 7 days old:

```bash
node -e "require(process.argv[1]).resolveVersion('pypi',process.argv[2],'*',7).then(r=>console.log(JSON.stringify(r)))" "${CLAUDE_PLUGIN_ROOT}/hooks/lib/registries.js" semgrep
```

Use the `version` it prints as `<VER>` below. The secops-guard dep-gate hook checks `uvx` and `docker run`
the same way. If it denies or rewrites a command, follow it.

Persistent installs change the machine. **Ask the user first.**

| Tool | Windows | macOS / Linux |
|---|---|---|
| semgrep (native on Windows since the Fall 2025 release) | `uv tool install semgrep==<VER>` | same, or `brew install semgrep` |
| osv-scanner | `winget install Google.OSVScanner` | `brew install osv-scanner` |
| grype | `winget install Anchore.Grype` | `brew install grype` |
| syft (SBOM) | `winget install Anchore.syft` | `brew install syft` |
| gitleaks (security-patch-only maintenance) | `winget install Gitleaks.Gitleaks` | `brew install gitleaks` |
| guarddog | Docker only: `docker run --rm ghcr.io/datadog/guarddog:<TAG> <args>` | `uv tool install guarddog==<VER>` |
| trivy | **pin v0.69.3 or earlier** (see warning below) | same |

**Pinning:** `<VER>` and `<TAG>` above are deliberately unfilled — no version here has been verified against the
registry, and a stale number in a doc is worse than none. Resolve the current version at run time (the `dep-audit`
script's `resolveVersion` applies the same 7-day cooldown), or read it from the tool's releases page, then pin it.
Never install a scanner from a mutable `latest` tag: a security tool runs with your privileges and reads your source.

**Trivy warning:** trivy v0.69.4, v0.69.5 and v0.69.6 were malicious releases (supply-chain compromise, CVE-2026-33634).
Never install or recommend them. Pin trivy to v0.69.3 or earlier. In CI, pin `aquasecurity/trivy-action` by commit SHA
(v0.35.0 is the safe tag), never by a mutable tag. If any of these versions is on PATH, report it as an incident:
remove it, and rotate the credentials it could reach.

## semgrep

| Situation | Command |
|---|---|
| Installed | `semgrep scan --config p/default --config p/secrets --json -o "$OUT/semgrep.json" --metrics=off <dir>` |
| Ephemeral (Windows, macOS, Linux) | `uvx --from "semgrep==<VER>" semgrep scan --config p/default --config p/secrets --json -o "$OUT/semgrep.json" --metrics=off <dir>` |
| Docker | `docker run --rm -v "<dir>:/src" semgrep/semgrep:<VER> semgrep scan --config p/default --config p/secrets --json --metrics=off /src > "$OUT/semgrep.json"` |
| Diff | add `--baseline-commit "$(git merge-base HEAD origin/main)"` |

Registry configs (`p/...`) are downloaded from semgrep.dev, so they need network.
Extra packs by stack: `p/python`, `p/javascript`, `p/typescript`, `p/react`, `p/django`, `p/flask`,
`p/fastapi`, `p/nodejs`, `p/golang`, `p/java`, `p/terraform`, `p/kubernetes`, `p/dockerfile`.
Docker on Windows Git Bash: prefix the command with `MSYS_NO_PATHCONV=1`, and use `-v "$(pwd -W):/src"`.

## bandit (Python)

`bandit -r <dir> -f json -o "$OUT/bandit.json" -x ./.venv,./tests` (ephemeral: `uvx --from "bandit==<VER>" bandit …`).
Bandit is noisy: `B101` (assert), `B311` (random, unless used for tokens), and `B404`/`B603` (subprocess import or list-args)
are usually FALSE.

## gitleaks (secrets)

| Situation | Command |
|---|---|
| Installed | `gitleaks git <dir> --report-format json --report-path "$OUT/gitleaks.json" --redact` (includes history) |
| Working tree only | `gitleaks dir <dir> --report-format json --report-path "$OUT/gitleaks.json" --redact` |

Always pass `--redact`. No Docker image is listed here because no pinned tag was verified. Without a local install, use the regex fallback below.

## IaC

- `checkov -d <dir> -o json --compact --quiet > "$OUT/checkov.json"` (ephemeral: `uvx --from "checkov==<VER>" checkov …`)
- `trivy config --format json -o "$OUT/trivy-config.json" <dir>` (only if `trivy --version` reports v0.69.3 or earlier; v0.69.4 to v0.69.6 are malicious)
- Manual review checklist: public buckets or ACLs, `0.0.0.0/0` ingress on admin ports, wildcard IAM
  (`Action: "*"`, `Resource: "*"`), unencrypted storage, `privileged: true`, `hostPath`, `runAsUser: 0`,
  no resource limits, `latest` images, secrets in env or ConfigMaps, `allowPrivilegeEscalation` not false.

## Secret regex fallback (no gitleaks)

Use the Grep tool (ripgrep syntax) with `output_mode: "content"`.
Exclude `node_modules`, `.venv`, `vendor`, `dist`, `*.lock`, `*-lock.json`, `*.min.js`, and test fixtures.
Then confirm each hit by reading the file: it must not be a placeholder, an example, a test, or an env lookup.

Patterns are in code spans; a `|` inside them is regex alternation.

- AWS access key id: `\b(?:AKIA|ASIA|ABIA|ACCA)[0-9A-Z]{16}\b`
- AWS secret (assigned): `(?i)aws.{0,20}secret.{0,20}['"][0-9a-zA-Z/+]{40}['"]`
- GitHub token: `\bgh[pousr]_[0-9A-Za-z]{36,255}\b` · fine-grained `\bgithub_pat_[0-9A-Za-z_]{82}\b`
- GitLab token: `\bglpat-[0-9A-Za-z_-]{20}\b`
- Slack: `\bxox[baprs]-[0-9A-Za-z-]{10,72}\b` · webhook `hooks\.slack\.com/services/T[0-9A-Z]+/B[0-9A-Z]+/[0-9A-Za-z]+`
- Stripe: `\b[sr]k_live_[0-9A-Za-z]{24,99}\b`
- Google API key: `\bAIza[0-9A-Za-z_-]{35}\b`
- GCP service account: `"type":\s*"service_account"` (then check for `private_key`)
- OpenAI: `\bsk-(?:proj-|svcacct-|admin-)?[A-Za-z0-9_-]{20,}T3BlbkFJ[A-Za-z0-9_-]{20,}\b` · generic `\bsk-[A-Za-z0-9]{48}\b`
- Anthropic: `\bsk-ant-(?:api|admin)[0-9]{2}-[A-Za-z0-9_-]{80,}\b`
- Azure storage conn string: `DefaultEndpointsProtocol=https?;AccountName=[^;]+;AccountKey=[A-Za-z0-9+/=]{80,}`
- Azure / generic client secret: `(?i)(?:client_?secret|azure.{0,20}(?:key|secret))\s*[:=]\s*['"][A-Za-z0-9~._-]{30,}['"]`
- Twilio: `\bSK[0-9a-fA-F]{32}\b`
- SendGrid: `\bSG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43}\b`
- npm token: `\bnpm_[A-Za-z0-9]{36}\b` · `_authToken\s*=\s*[^\s$]{20,}`
- PyPI token: `\bpypi-AgEIcHlwaS5vcmc[A-Za-z0-9_-]{50,}\b`
- Hugging Face: `\bhf_[A-Za-z]{34}\b`
- Private key: `-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP |ENCRYPTED )?PRIVATE KEY`
- JWT (hardcoded): `\beyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b`
- DB URL with password: `(?i)\b(?:postgres(?:ql)?|mysql|mongodb(?:\+srv)?|redis|amqp)://[^:\s/@]+:[^@\s/]{3,}@`
- Generic assignment: `(?i)\b(?:password|passwd|pwd|secret|api_?key|access_?token|auth_?token)\s*[:=]\s*['"][^'"\s$<{]{8,}['"]` (low precision: always read the file)

Also check these for tracked secret files: `git ls-files | grep -iE '(^|/)(\.env(\..+)?|id_rsa|id_ed25519|.*\.pem|.*\.p12|.*\.pfx|credentials(\.json)?|\.npmrc|\.pypirc)$'`.
To search history (slow): `git log -p -S '<prefix>' --all` for a specific prefix only. Never dump the whole history.
