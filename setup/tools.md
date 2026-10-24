# Scanner tools

The hooks work with **zero** scanners installed - every dependency check runs against
OSV.dev over the network. Scanners add local SAST, container scanning and secret
detection. Everything on this page is **optional**. The installer never installs any
of it; it only prints the commands.

Install one at a time, and only the ones you will use. Every extra binary is one more
thing with an update channel someone could compromise - which is the whole point of
this plugin.

## Matrix

| Tool | What it is for | Used by | Windows | macOS | Linux |
|---|---|---|---|---|---|
| **osv-scanner** | Dependency CVEs from a lockfile or directory. The single most useful one. | `dep-audit` skill, `post-install-scan` | `winget install Google.OSVScanner` | `brew install osv-scanner` | release binary from `github.com/google/osv-scanner/releases`, or `go install github.com/google/osv-scanner/v2/cmd/osv-scanner@latest` |
| **semgrep** | SAST: code-level bug and injection patterns. Native Windows support since Fall 2025. | `sast-scan` skill | `uv tool install semgrep` | `brew install semgrep` | `uv tool install semgrep` |
| **grype** | Container image and filesystem CVEs. | `dep-gate` Docker checks | `winget install Anchore.Grype` | `brew install grype` | `curl -sSfL https://raw.githubusercontent.com/anchore/grype/main/install.sh \| sh -s -- -b /usr/local/bin` |
| **syft** | SBOM generator, feeds grype. | optional | `winget install Anchore.syft` | `brew install syft` | same install.sh pattern as grype |
| **docker scout** | Image CVEs, bundled with Docker Desktop >= 4.17. Nothing to install. | `dep-gate` Docker checks | `docker scout cves <image>` | same | same |
| **bandit** | Python-specific SAST. | `sast-scan` skill | `uv tool install bandit` | `uv tool install bandit` | `uv tool install bandit` |
| **checkov** | IaC scanning (Terraform, CloudFormation, K8s). | `sast-scan` skill | `uv tool install checkov` | `uv tool install checkov` | `uv tool install checkov` |
| **gitleaks** | Secret detection in git history. See the maintenance note below. | `sast-scan` skill | `winget search gitleaks` first - the ID `Gitleaks.Gitleaks` is **UNVERIFIED** | `brew install gitleaks` | release binary |
| **guarddog** | Heuristic malware detection in npm/PyPI packages. | manual | Docker only: `docker run --rm ghcr.io/datadog/guarddog` | `uv tool install guarddog` | `uv tool install guarddog` |
| **trivy** | Image + filesystem CVEs, secrets, IaC misconfig. The Side B engine. **READ THE WARNING BELOW BEFORE INSTALLING.** | `build-gate` (all of Side B), `dep-gate` Docker checks | `winget install AquaSecurity.Trivy` (ID verified; installed v0.76.1 here) | `brew install trivy` | release binary |

`dep-gate.js` picks whichever of grype / trivy / docker scout is available for IMAGE
scanning. `build-gate.js` (Side B) needs **trivy specifically**: only trivy does
filesystem and secret scanning, so with grype or docker scout alone, image CVE checks
still run but everything else in Side B is inactive. Neither hook blocks for lack of a
scanner - they emit a note instead.

Both hooks and `setup/verify.js` also look outside `PATH`: the winget Packages directory
on Windows (where `winget install` puts trivy, invisible to an already-open shell) and
`~/.local/bin` (where `uv tool install` puts semgrep).

## Trivy: versions 0.69.4, 0.69.5 and 0.69.6 are malicious

In **March 2026** (CVE-2026-33634) the published Trivy binaries and container images
for **v0.69.4, v0.69.5 and v0.69.6** were replaced with malicious builds, and the
`trivy-action` GitHub Action tags were force-pushed to point at them.

- Install a **current release (>= v0.70)**. Everything from v0.70 onward was published
  after remediation. Do **not** pin to v0.69.3 to "stay before the incident": trivy's
  vulnerability DB has a schema version tied to the binary, so an old binary can fail to
  pull a current DB and then silently report nothing - a scanner that finds nothing is
  worse than no scanner. Verified working here: **v0.76.1**.
- In CI, pin `aquasecurity/trivy-action` to **v0.35.0 by commit SHA**, never by tag.
- If any of those three versions is on a machine, remove it and treat the machine's
  credentials as exposed.

`setup/verify.js` fails loudly if it finds one of those three versions on PATH.

## gitleaks is in maintenance mode

Upstream gitleaks is maintenance-only: it still works, but do not expect new rules.
Its winget package ID is unverified here - run `winget search gitleaks` and use
whatever ID that prints rather than trusting the one in the table.

## Socket Firewall (`sfw`) - optional, not open source

`sfw` wraps a package manager and blocks known-malicious fetches at the network layer:

```
npm i -g sfw
npm cache clean --force      # required: sfw only sees actual network fetches
sfw npm install
sfw pnpm install
sfw pip install requests
sfw uv sync
sfw cargo build
```

No API key for the free tier. **Licence caveat: PolyForm Shield, which is not an OSI
open-source licence** - read it before using it at work. It is complementary to this
plugin, not a replacement: it sees fetches, the hooks see intent.

## Verifying a downloaded binary

Never pipe a release tarball straight into your shell without checking it first.

**Checksum (every project above publishes one):**

```powershell
# Windows
Get-FileHash .\grype_0.100.0_windows_amd64.zip -Algorithm SHA256
# compare against the checksums.txt from the same release page
```

```bash
# macOS / Linux
shasum -a 256 grype_0.100.0_linux_amd64.tar.gz
sha256sum -c checksums.txt --ignore-missing
```

**Signature (cosign, when the project publishes one - anchore and osv-scanner do):**

```bash
cosign verify-blob \
  --certificate checksums.txt.pem \
  --signature checksums.txt.sig \
  --certificate-identity-regexp 'https://github\.com/anchore/grype/.*' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  checksums.txt
```

**npm provenance**, for anything installed globally with npm:

```
npm audit signatures
```

That verifies the registry signature and, where present, the Sigstore provenance
attestation tying the tarball to the build that produced it.
