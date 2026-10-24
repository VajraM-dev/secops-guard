#Requires -Version 5.1
<#
.SYNOPSIS
  secops-guard machine setup: package-manager cooldown configs + Claude Code settings.

.DESCRIPTION
  DRY RUN BY DEFAULT. Prints every change it would make and exits. Pass -Apply to write.
  Never needs admin. Never touches managed-settings.json. Backs up every file it writes.

.EXAMPLE
  pwsh -File setup\install.ps1
  pwsh -File setup\install.ps1 -Apply
  pwsh -File setup\install.ps1 -Apply -CooldownDays 14 -SkipIgnoreScripts
  pwsh -File setup\install.ps1 -Uninstall -Apply
#>
[CmdletBinding()]
param(
  [switch]$Apply,
  [switch]$DryRun,
  [int]$CooldownDays = 7,
  [switch]$SkipIgnoreScripts,
  [switch]$NoPluginInstall,
  [switch]$NoDenyRules,
  [switch]$Uninstall,
  [switch]$RestoreBackups,
  [switch]$Quiet
)

$ErrorActionPreference = 'Stop'
if ($DryRun) { $Apply = $false }
if ($CooldownDays -lt 0) { throw 'secops-guard: -CooldownDays must be >= 0' }

$SetupDir   = $PSScriptRoot
$RepoRoot   = Split-Path -Parent $SetupDir
$ConfigDir  = Join-Path $SetupDir 'configs'
$ClaudeHome = Join-Path $env:USERPROFILE '.claude'
$Stamp      = Get-Date -Format 'yyyyMMddHHmmss'

$script:Applied = @()
$script:Skipped = @()
$script:Failed  = @()

function Say([string]$Text) { if (-not $Quiet) { Write-Host $Text } }
function Head([string]$Text) { if (-not $Quiet) { Write-Host ''; Write-Host $Text -ForegroundColor Cyan } }
function Warn([string]$Text) { Write-Host "  ! $Text" -ForegroundColor Yellow }

# ---------------------------------------------------------------- tool versions

function Get-ToolVersion([string]$Exe, [string[]]$VersionArgs) {
  if (-not (Get-Command $Exe -ErrorAction SilentlyContinue)) { return $null }
  try {
    $out = & $Exe @VersionArgs 2>&1 | Out-String
  } catch { return $null }
  # Two components are enough: pip reports "pip 26.1", so a three-part pattern never matched
  # it and the pip cooldown was silently skipped as "not installed".
  $m = [regex]::Match($out, '(\d+)\.(\d+)(\.(\d+))?')
  if ($m.Success) { return $m.Value }
  return $null
}

function Test-VersionAtLeast([string]$Have, [string]$Min) {
  if (-not $Have) { return $false }
  try { return ([version]$Have -ge [version]$Min) } catch { return $false }
}

# ------------------------------------------------------------------ file helpers

function Get-FileLines([string]$Path) {
  if (-not (Test-Path -LiteralPath $Path)) { return @() }
  $raw = [System.IO.File]::ReadAllText($Path)
  if ($raw -eq '') { return @() }
  return [regex]::Split($raw.TrimEnd("`r", "`n"), "`r`n|`n|`r")
}

function Set-FileLines([string]$Path, [string[]]$Lines) {
  $dir = Split-Path -Parent $Path
  if ($dir -and -not (Test-Path -LiteralPath $dir)) { New-Item -ItemType Directory -Path $dir -Force | Out-Null }
  # No BOM: npm's ini parser and uv's toml parser both choke on one.
  $text = ($Lines -join "`r`n") + "`r`n"
  [System.IO.File]::WriteAllText($Path, $text, (New-Object System.Text.UTF8Encoding $false))
}

function Backup-File([string]$Path) {
  if (-not (Test-Path -LiteralPath $Path)) { return $null }
  # Never clobber an existing backup: two runs inside the same second would
  # otherwise destroy the original copy.
  $backup = "$Path.secops-bak-$Stamp"
  $n = 1
  while (Test-Path -LiteralPath $backup) { $n++; $backup = "$Path.secops-bak-$Stamp-$n" }
  Copy-Item -LiteralPath $Path -Destination $backup -Force
  Say "  backup: $backup"
  Say "  restore with: Copy-Item -LiteralPath `"$backup`" -Destination `"$Path`" -Force"
  return $backup
}

function Get-NewestBackup([string]$Path) {
  $leaf = Split-Path -Leaf $Path
  $dir = Split-Path -Parent $Path
  if (-not (Test-Path -LiteralPath $dir)) { return $null }
  $hits = @(Get-ChildItem -LiteralPath $dir -Filter "$leaf.secops-bak-*" -ErrorAction SilentlyContinue | Sort-Object Name -Descending)
  if ($hits.Count -gt 0) { return $hits[0].FullName }
  return $null
}

# ------------------------------------------------------------- snippet handling

# A snippet line is `key = value`, `key: value` or `key=value`, optionally under a
# `[section]` header. Comments (#) are documentation only and are not written.
function Read-Snippet([string]$Name) {
  $path = Join-Path $ConfigDir $Name
  if (-not (Test-Path -LiteralPath $path)) { throw "secops-guard: missing snippet $path" }
  $minutes = [long]$CooldownDays * 1440
  $seconds = [long]$CooldownDays * 86400
  $section = $null
  $entries = @()
  foreach ($raw in (Get-FileLines $path)) {
    $line = $raw.Trim()
    if ($line -eq '' -or $line.StartsWith('#')) { continue }
    if ($line -match '^\[(.+)\]$') { $section = $Matches[1]; continue }
    $line = $line.Replace('@DAYS@', "$CooldownDays").Replace('@MINUTES@', "$minutes").Replace('@SECONDS@', "$seconds")
    $sep = $line.IndexOfAny([char[]]@('=', ':'))
    if ($sep -lt 1) { throw "secops-guard: cannot parse snippet line in ${path}: $raw" }
    $entries += @{ Section = $section; Key = $line.Substring(0, $sep).Trim(); Line = $line }
  }
  return $entries
}

# Upserts each snippet entry into $Target. Returns the diff lines; writes only with -Apply.
function Merge-Snippet([string]$Target, $Entries) {
  $lines = [System.Collections.Generic.List[string]]::new()
  foreach ($l in (Get-FileLines $Target)) { [void]$lines.Add($l) }
  $existed = Test-Path -LiteralPath $Target
  $diff = @()

  foreach ($e in $Entries) {
    $start = 0
    $end = $lines.Count     # exclusive

    if ($e.Section) {
      $hdr = -1
      for ($i = 0; $i -lt $lines.Count; $i++) {
        if ($lines[$i].Trim() -eq "[$($e.Section)]") { $hdr = $i; break }
      }
      if ($hdr -lt 0) {
        if ($lines.Count -gt 0 -and $lines[$lines.Count - 1].Trim() -ne '') { [void]$lines.Add('') }
        [void]$lines.Add("[$($e.Section)]")
        $diff += "+[$($e.Section)]"
        $hdr = $lines.Count - 1
      }
      $start = $hdr + 1
      $end = $lines.Count
      for ($i = $start; $i -lt $lines.Count; $i++) {
        if ($lines[$i].TrimStart().StartsWith('[')) { $end = $i; break }
      }
    }

    $keyRe = '^\s*' + [regex]::Escape($e.Key) + '\s*[:=]'
    $found = -1
    for ($i = $start; $i -lt $end; $i++) {
      if ($lines[$i] -match $keyRe) { $found = $i; break }
    }

    if ($found -ge 0) {
      if ($lines[$found].Trim() -eq $e.Line) { continue }   # already correct - idempotent
      $diff += "-$($lines[$found])"
      $diff += "+$($e.Line)"
      $lines[$found] = $e.Line
    } elseif ($e.Section) {
      $lines.Insert($end, $e.Line)
      $diff += "+$($e.Line)"
    } else {
      # Flat file: insert at the top, below any leading comment block, so the key
      # can never end up swallowed by a later [section].
      $at = 0
      while ($at -lt $lines.Count -and ($lines[$at].Trim() -eq '' -or $lines[$at].TrimStart().StartsWith('#') -or $lines[$at].TrimStart().StartsWith(';'))) { $at++ }
      $lines.Insert($at, $e.Line)
      $diff += "+$($e.Line)"
    }
  }

  if ($diff.Count -eq 0) { return @() }

  Say "--- $Target$(if (-not $existed) { '  (new file)' })"
  Say "+++ $Target  (secops-guard)"
  foreach ($d in $diff) { Say "  $d" }
  if ($Apply) {
    Backup-File $Target | Out-Null
    Set-FileLines $Target $lines
    Say "  wrote $Target"
  }
  return $diff
}

# Deletes exactly the keys this installer writes. Surgical on purpose: restoring a
# backup wholesale would also revert unrelated edits made since.
function Remove-Snippet([string]$Target, $Entries) {
  if (-not (Test-Path -LiteralPath $Target)) { return @() }
  $lines = [System.Collections.Generic.List[string]]::new()
  foreach ($l in (Get-FileLines $Target)) { [void]$lines.Add($l) }
  $diff = @()
  foreach ($e in $Entries) {
    $keyRe = '^\s*' + [regex]::Escape($e.Key) + '\s*[:=]'
    for ($i = $lines.Count - 1; $i -ge 0; $i--) {
      if ($lines[$i] -match $keyRe) { $diff += "-$($lines[$i])"; $lines.RemoveAt($i) }
    }
  }
  if ($diff.Count -eq 0) { return @() }
  Say "--- $Target"
  Say "+++ $Target  (secops-guard uninstall)"
  foreach ($d in $diff) { Say "  $d" }
  $bak = Get-NewestBackup $Target
  if ($bak) { Say "  newest backup kept: $bak" ; Say "  full restore: Copy-Item -LiteralPath `"$bak`" -Destination `"$Target`" -Force" }
  if ($Apply) {
    Backup-File $Target | Out-Null
    Set-FileLines $Target $lines
    Say "  wrote $Target"
  }
  return $diff
}

# Full rollback to the oldest state this installer ever saw. Only with
# -Uninstall -RestoreBackups, because it also reverts edits you made since.
function Restore-Backup([string]$Target) {
  $hits = @()
  $leaf = Split-Path -Leaf $Target
  $dir = Split-Path -Parent $Target
  if (Test-Path -LiteralPath $dir) {
    $hits = @(Get-ChildItem -LiteralPath $dir -Filter "$leaf.secops-bak-*" -ErrorAction SilentlyContinue | Sort-Object Name)
  }
  if ($hits.Count -eq 0) { Say "  no backup to restore for $Target"; return @() }
  $oldest = $hits[0].FullName
  Say "--- $Target"
  Say "+++ $oldest  (full restore - DISCARDS every change made since)"
  if ($Apply) {
    Backup-File $Target | Out-Null
    Copy-Item -LiteralPath $oldest -Destination $Target -Force
    Say "  restored $Target from $oldest"
  }
  return @("restore $Target")
}

# ------------------------------------------------------------------ the matrix

$npmV   = Get-ToolVersion 'npm'   @('-v')
$pnpmV  = Get-ToolVersion 'pnpm'  @('-v')
$uvV    = Get-ToolVersion 'uv'    @('--version')
$pipV   = Get-ToolVersion 'pip'   @('--version')
$cargoV = Get-ToolVersion 'cargo' @('--version')
$yarnV  = Get-ToolVersion 'yarn'  @('-v')
$bunV   = Get-ToolVersion 'bun'   @('-v')
$nodeV  = Get-ToolVersion 'node'  @('-v')

$Matrix = @(
  @{ Id = 'npm-cooldown';   Tool = 'npm';   Have = $npmV;   Min = '11.10.0'; Snippet = 'npm.npmrc';
     Target = (Join-Path $env:USERPROFILE '.npmrc');
     Upgrade = 'npm i -g npm@latest'; Note = 'min-release-age (days)' },
  @{ Id = 'npm-no-scripts'; Tool = 'npm';   Have = $npmV;   Min = '0.0.0';   Snippet = 'npm-ignore-scripts.npmrc';
     Target = (Join-Path $env:USERPROFILE '.npmrc');
     Upgrade = ''; Note = 'ignore-scripts (blocks preinstall worms)'; Optional = $true },
  @{ Id = 'pnpm-cooldown';  Tool = 'pnpm';  Have = $pnpmV;  Min = '10.16.0'; Snippet = 'pnpm-config.yaml';
     Target = (Join-Path $env:LOCALAPPDATA 'pnpm\config\config.yaml');
     Upgrade = 'npm i -g pnpm@latest'; Note = 'minimumReleaseAge (minutes)' },
  @{ Id = 'uv-cooldown';    Tool = 'uv';    Have = $uvV;    Min = '0.9.17';  Snippet = 'uv.toml';
     Target = (Join-Path $env:APPDATA 'uv\uv.toml');
     Upgrade = 'uv self update'; Note = 'exclude-newer (relative duration)' },
  @{ Id = 'pip-cooldown';   Tool = 'pip';   Have = $pipV;   Min = '26.1.0';  Snippet = 'pip.ini';
     Target = (Join-Path $env:APPDATA 'pip\pip.ini');
     Upgrade = 'python -m pip install --upgrade pip'; Note = 'uploaded-prior-to (P<n>D)' },
  @{ Id = 'cargo-cooldown'; Tool = 'cargo'; Have = $cargoV; Min = '1.100.0'; Snippet = 'cargo-config.toml';
     Target = (Join-Path $env:USERPROFILE '.cargo\config.toml');
     Upgrade = 'rustup update  (Rust 1.100, due 2026-11-12) - until then: cargo install cargo-cooldown';
     Note = 'global-min-publish-age' },
  @{ Id = 'yarn-cooldown';  Tool = 'yarn';  Have = $yarnV;  Min = '4.10.0';  Snippet = 'yarnrc.yml';
     Target = (Join-Path $env:USERPROFILE '.yarnrc.yml');
     Upgrade = 'corepack enable; yarn set version stable'; Note = 'npmMinimalAgeGate (unit UNVERIFIED)' },
  @{ Id = 'bun-cooldown';   Tool = 'bun';   Have = $bunV;   Min = '1.3.0';   Snippet = 'bunfig.toml';
     Target = (Join-Path $env:USERPROFILE '.bunfig.toml');
     Upgrade = 'bun upgrade'; Note = 'minimumReleaseAge (seconds)' }
)

# ------------------------------------------------------------------------ run

Say ''
Say "secops-guard setup  -  cooldown $CooldownDays day(s)  -  $(if ($Uninstall) { 'UNINSTALL' } elseif ($Apply) { 'APPLY' } else { 'DRY RUN (nothing will be written)' })"
Say "repo: $RepoRoot"

Head '(a) preflight - detected versions and support matrix'
if (-not $Quiet) {
  $rows = foreach ($m in $Matrix) {
    $status =
      if (-not $m.Have) { 'not installed' }
      elseif ($m.Id -eq 'npm-no-scripts' -and $SkipIgnoreScripts) { 'opted out' }
      elseif (Test-VersionAtLeast $m.Have $m.Min) { 'supported' }
      else { "needs >= $($m.Min)" }
    [pscustomobject]@{
      Setting = $m.Id; Tool = $m.Tool
      Installed = $(if ($m.Have) { $m.Have } else { '-' })
      Requires = $(if ($m.Min -eq '0.0.0') { 'any' } else { $m.Min })
      Status = $status
    }
  }
  $rows | Format-Table -AutoSize | Out-String | Write-Host
  Write-Host "  node $nodeV  (required by the plugin hooks)"
}

Head "(b) package-manager configs"
foreach ($m in $Matrix) {
  try {
    if (-not $m.Have) { $script:Skipped += "$($m.Id): $($m.Tool) is not installed"; continue }
    # yarn: the unit of npmMinimalAgeGate is disputed. Writing the wrong form could
    # make `yarn install` fail, so it is printed as a manual suggestion, never written.
    if ($m.Id -eq 'yarn-cooldown') {
      Warn "yarn-cooldown: NOT written - the npmMinimalAgeGate unit is unverified. Add this to $($m.Target) by hand if you want it:"
      foreach ($e in (Read-Snippet $m.Snippet)) { Say "      $($e.Line)" }
      Say '      then check it with: yarn config get npmMinimalAgeGate'
      $script:Skipped += 'yarn-cooldown: unit unverified - printed as a manual suggestion instead'
      continue
    }
    if ($m.Id -eq 'npm-no-scripts' -and $SkipIgnoreScripts) { $script:Skipped += "$($m.Id): opted out with -SkipIgnoreScripts"; continue }
    if (-not (Test-VersionAtLeast $m.Have $m.Min)) {
      Warn "$($m.Id): $($m.Tool) $($m.Have) is older than $($m.Min) - key NOT written. Upgrade: $($m.Upgrade)"
      $script:Skipped += "$($m.Id): $($m.Tool) $($m.Have) < $($m.Min) - upgrade with: $($m.Upgrade)"
      continue
    }
    $entries = Read-Snippet $m.Snippet
    $diff = if ($Uninstall -and $RestoreBackups) { Restore-Backup $m.Target }
            elseif ($Uninstall) { Remove-Snippet $m.Target $entries }
            else { Merge-Snippet $m.Target $entries }
    if ($diff.Count -gt 0) { $script:Applied += "$($m.Id) -> $($m.Target)" }
    else { Say "  already correct: $($m.Id) ($($m.Target))" }
  } catch {
    Warn "$($m.Id) FAILED: $($_.Exception.Message)"
    $script:Failed += "$($m.Id): $($_.Exception.Message)"
  }
}

Head '(c) Claude Code settings merge'
$settingsPath = Join-Path $ClaudeHome 'settings.json'
$snippetPath  = Join-Path $SetupDir 'settings.snippet.json'
$mergeJs      = Join-Path $SetupDir 'merge-settings.js'
$hasNode      = [bool](Get-Command 'node' -ErrorAction SilentlyContinue)

function Invoke-Merge($ExtraArgs) {
  if (-not $hasNode) {
    Warn 'node is not on PATH - cannot touch settings.json. Install Node 18+ and re-run.'
    $script:Failed += 'settings.json merge: node not found'
    return
  }
  $a = @($mergeJs, $settingsPath, $snippetPath)
  if ($Apply) { $a += '--apply' }
  if ($Uninstall) { $a += '--remove' }
  if ($NoDenyRules) { $a += '--no-snippet' }
  $a += $ExtraArgs
  & node @a 2>&1 | ForEach-Object { Say "  $_" }
  if ($LASTEXITCODE -ne 0) {
    Warn "settings.json merge FAILED (exit $LASTEXITCODE)"
    $script:Failed += "settings.json merge: merge-settings.js exited $LASTEXITCODE"
  } else {
    $script:Applied += "settings.json merged ($settingsPath)"
  }
}

if ($Uninstall -and $RestoreBackups) {
  if ((Restore-Backup $settingsPath).Count -gt 0) { $script:Applied += "restored $settingsPath" }
} elseif ($NoDenyRules) {
  Say '  -NoDenyRules: skipping the permission deny rules. The guard.js hook still covers'
  Say "  these paths; the rules are the backstop for when hooks are off. See $snippetPath"
  $script:Skipped += 'permission deny rules: declined with -NoDenyRules'
} else {
  Invoke-Merge @()
  $script:Applied += 'permission deny rules (decline them with -NoDenyRules)'
}

Head '(d) marketplace + plugin registration'
$claudeCli = Get-Command 'claude' -ErrorAction SilentlyContinue
if ($Uninstall) {
  Say '  leaving the plugin registered. Remove it yourself with:'
  Say '    claude plugin uninstall secops-guard@secops-guard'
} else {
  Say "    claude plugin marketplace add `"$RepoRoot`""
  Say '    claude plugin install secops-guard@secops-guard'
  if ($NoPluginInstall) {
    Say '  -NoPluginInstall: run the two commands above yourself.'
  } elseif (-not $claudeCli) {
    Warn 'the `claude` CLI is not on PATH - writing the settings.json entries instead'
    Invoke-Merge @('--enable', 'secops-guard@secops-guard', '--marketplace', "secops-guard=$RepoRoot")
  } elseif ($Apply) {
    & claude plugin marketplace add "$RepoRoot" 2>&1 | ForEach-Object { Say "    $_" }
    $ok = ($LASTEXITCODE -eq 0)
    if ($ok) {
      & claude plugin install 'secops-guard@secops-guard' 2>&1 | ForEach-Object { Say "    $_" }
      $ok = ($LASTEXITCODE -eq 0)
    }
    if ($ok) {
      $script:Applied += 'plugin registered via the claude CLI'
    } else {
      Warn 'the claude CLI failed - falling back to settings.json entries'
      Invoke-Merge @('--enable', 'secops-guard@secops-guard', '--marketplace', "secops-guard=$RepoRoot")
    }
  }
}

Head '(e) optional scanners (nothing is installed for you)'
Say '    winget install Google.OSVScanner     # dependency CVEs - most useful one'
Say '    winget install Anchore.Grype         # container image CVEs'
Say '    winget install Anchore.syft          # SBOM for the above'
Say '    uv tool install semgrep              # SAST'
Say '    uv tool install bandit               # python SAST'
Say '    docker scout cves <image>            # bundled with Docker Desktop >= 4.17'
Say "    full matrix, caveats and the Trivy malware warning: $(Join-Path $SetupDir 'tools.md')"

Head '(f) summary'
Say "  applied:  $($script:Applied.Count)"
foreach ($x in $script:Applied) { Say "    + $x" }
Say "  skipped:  $($script:Skipped.Count)"
foreach ($x in $script:Skipped) { Say "    - $x" }
Say "  failed:   $($script:Failed.Count)"
foreach ($x in $script:Failed) { Write-Host "    x $x" -ForegroundColor Red }
if (-not $Apply) { Say ''; Say '  DRY RUN - nothing was written. Re-run with -Apply to make these changes.' }
Say ''
Say "  verify afterwards with: node `"$(Join-Path $SetupDir 'verify.js')`""
Say ''

if ($script:Failed.Count -gt 0) { exit 1 }
exit 0
