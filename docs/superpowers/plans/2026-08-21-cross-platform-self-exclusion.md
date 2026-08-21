# Cross-Platform Scanner Self-Exclusion Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Prevent each scanner from reporting its currently executing source file during full-root or containing-directory scans while leaving other same-named copies eligible for findings.

**Architecture:** Each platform captures the executing script path once, removes that path from recursive inventories before metadata stages see it, and retains a defensive guard in the central content-scanning function. Bash compares filesystem identity; PowerShell and strict CMD use normalized case-insensitive Windows paths.

**Tech Stack:** Bash 4+, POSIX filesystem tools, Windows PowerShell 5.1+, Windows CMD built-ins

**Spec:** `docs/superpowers/specs/2026-08-21-cross-platform-self-exclusion-design.md`

## Global Constraints

- Exclude only the currently executing script; another copy with the same basename remains scannable.
- Cover metadata-only findings and content findings during full-root scans.
- Keep `credshunter.bat` strictly CMD-only with no PowerShell, .NET, or helper dependency.
- Do not change matchers, severity accounting, Git discovery, environment discovery, or unrelated exclusions.
- Self-path resolution is best effort and must never abort a scan.

---

### Task 1: Bash identity-based self-exclusion

**Files:**
- Modify: `credshunter.sh:66`
- Modify: `credshunter.sh:1378-1396`
- Modify: `credshunter.sh:1972-2133`

**Interfaces:**
- Consumes: `${BASH_SOURCE[0]}` and candidate filesystem paths.
- Produces: `is_self_file <path>`, returning status 0 only when the candidate and executing script identify the same file.

- [ ] **Step 1: Reproduce the failure before editing**

```bash
tmp=$(mktemp -d)
mkdir -p "$tmp/runner" "$tmp/copy"
cp credshunter.sh "$tmp/runner/credshunter.sh"
cp credshunter.sh "$tmp/copy/credshunter.sh"
chmod +x "$tmp/runner/credshunter.sh"
result=$(mktemp)
(cd "$tmp/runner" && ./credshunter.sh --all --no-stage1 --no-stage2 --no-stage4 --no-stage6 --no-stage7 -p "$tmp" -o "$result" >/dev/null 2>&1 || true)
grep -F "$tmp/runner/credshunter.sh" "$result"
```

Expected before the fix: `grep` succeeds because the executing source is reported.

- [ ] **Step 2: Add the identity helper and portable initialization**

Replace the GNU-specific initialization and add the helper immediately after it:

```bash
SCRIPT_PATH=$(readlink -f "${BASH_SOURCE[0]}" 2>/dev/null || printf '%s' "${BASH_SOURCE[0]}")

is_self_file() {
    local candidate="$1"
    [ -n "${SCRIPT_PATH:-}" ] &&
        [ -e "$candidate" ] &&
        [ -e "$SCRIPT_PATH" ] &&
        [ "$candidate" -ef "$SCRIPT_PATH" ]
}
```

- [ ] **Step 3: Apply the helper to every Stage 2-5 path**

Add `is_self_file "$f" && continue` before Stage 2, Stage 3, and Stage 4 record their findings. Replace the string comparison at the start of `scan_file` with:

```bash
is_self_file "$file" && return
```

Filter the Stage 5 NUL stream after `find` and before it is written to `CANDIDATE_FILES`:

```bash
while IFS= read -r -d '' candidate; do
    is_self_file "$candidate" || printf '%s\0' "$candidate"
done
```

- [ ] **Step 4: Validate syntax and behavior**

```bash
bash -n credshunter.sh
rm -f "$result"
(cd "$tmp/runner" && ./credshunter.sh --all --no-stage1 --no-stage2 --no-stage4 --no-stage6 --no-stage7 -p "$tmp" -o "$result" >/dev/null 2>&1 || true)
! grep -F "$tmp/runner/credshunter.sh" "$result"
grep -F "$tmp/copy/credshunter.sh" "$result"
ln "$tmp/runner/credshunter.sh" "$tmp/runner/hardlink.sh"
hardlink_result=$(mktemp)
(cd "$tmp" && runner/hardlink.sh --all --no-stage1 --no-stage2 --no-stage4 --no-stage6 --no-stage7 -p "$tmp" -o "$hardlink_result" >/dev/null 2>&1 || true)
! grep -F "$tmp/runner/credshunter.sh" "$hardlink_result"
```

Expected: syntax passes; the executing inode is absent; the separate copy remains reportable.

- [ ] **Step 5: Commit the Bash change**

```bash
git add credshunter.sh
git commit -m "fix: exclude running Bash scanner from findings"
```

### Task 2: PowerShell normalized-path self-exclusion

**Files:**
- Modify: `credshunter.ps1:194-199`
- Modify: `credshunter.ps1:1559-1561`
- Modify: `credshunter.ps1:2728-2815`
- Modify: `credshunter.ps1:2868-2883`

**Interfaces:**
- Consumes: `$PSCommandPath`, `$MyInvocation.MyCommand.Path`, and candidate paths.
- Produces: `Test-IsSelfPath -Path <string> -> bool`.

- [ ] **Step 1: Record the pre-fix Windows reproduction**

```powershell
$root = Join-Path $env:TEMP 'credshunter-self-test'
$result = Join-Path $env:TEMP 'credshunter-self-result.txt'
Remove-Item $root -Recurse -Force -ErrorAction SilentlyContinue
Remove-Item $result -Force -ErrorAction SilentlyContinue
New-Item "$root\runner", "$root\copy" -ItemType Directory -Force | Out-Null
Copy-Item .\credshunter.ps1 "$root\runner\credshunter.ps1"
Copy-Item .\credshunter.ps1 "$root\copy\credshunter.ps1"
& "$root\runner\credshunter.ps1" -Path $root -All -NoStage1 -NoStage2 -NoStage4 -NoStage6 -NoStage7 -OutputFile $result -Quiet
Select-String -SimpleMatch "$root\runner\credshunter.ps1" $result
```

Expected before the fix: the executing script path is present.

- [ ] **Step 2: Normalize the self path and add the predicate**

Resolve the first available invocation path through `[System.IO.Path]::GetFullPath()`. Add:

```powershell
function Test-IsSelfPath {
    param([string]$Path)
    if ([string]::IsNullOrEmpty($script:SelfPath) -or [string]::IsNullOrEmpty($Path)) { return $false }
    try {
        $candidate = [System.IO.Path]::GetFullPath($Path)
        return $candidate.Equals($script:SelfPath, [System.StringComparison]::OrdinalIgnoreCase)
    } catch {
        return $false
    }
}
```

- [ ] **Step 3: Filter the shared inventory and retain a defensive guard**

Before each file descriptor is added by `Get-WalkedFiles`, skip it with:

```powershell
if (Test-IsSelfPath -Path $fi.FullName) { continue }
```

At the start of `Invoke-ScanFile`, use:

```powershell
if (Test-IsSelfPath -Path $FullPath) { return }
```

Remove the Stage 4 basename-only `$selfName` calculation and comparison because the shared inventory now excludes only the exact running path.

- [ ] **Step 4: Run Windows PowerShell validation**

```powershell
$errors = $null
[void][System.Management.Automation.Language.Parser]::ParseFile((Resolve-Path .\credshunter.ps1), [ref]$null, [ref]$errors)
if ($errors.Count) { $errors | Format-List; exit 1 }
Remove-Item $result -Force -ErrorAction SilentlyContinue
& "$root\runner\credshunter.ps1" -Path $root -All -NoStage1 -NoStage2 -NoStage4 -NoStage6 -NoStage7 -OutputFile $result -Quiet
if (Select-String -Quiet -SimpleMatch "$root\runner\credshunter.ps1" $result) { throw 'running script was reported' }
if (-not (Select-String -Quiet -SimpleMatch "$root\copy\credshunter.ps1" $result)) { throw 'same-named copy was incorrectly excluded' }
```

- [ ] **Step 5: Commit the PowerShell change**

```bash
git add credshunter.ps1
git commit -m "fix: exclude running PowerShell scanner from findings"
```

### Task 3: Strict-CMD normalized-path self-exclusion

**Files:**
- Modify: `credshunter.bat:22-35`
- Modify: `credshunter.bat:427-434`
- Modify: `credshunter.bat:977-1007`
- Modify: `credshunter.bat:1764-1767`

**Interfaces:**
- Consumes: `%~f0`, `%%~fF`, and `%~f1`.
- Produces: `SELF_PATH`, the normalized path used by inventory and scan guards.

- [ ] **Step 1: Record the pre-fix CMD reproduction**

```bat
set "ROOT=%TEMP%\credshunter-self-test"
set "RESULT=%TEMP%\credshunter-self-result.txt"
rmdir /S /Q "%ROOT%" 2>nul
del "%RESULT%" 2>nul
mkdir "%ROOT%\runner" "%ROOT%\copy"
copy /Y credshunter.bat "%ROOT%\runner\credshunter.bat" >nul
copy /Y credshunter.bat "%ROOT%\copy\credshunter.bat" >nul
call "%ROOT%\runner\credshunter.bat" -Path "%ROOT%" -All -NoStage1 -NoStage2 -NoStage4 -NoStage6 -NoStage7 -OutputFile "%RESULT%" -Quiet
findstr /I /L /C:"%ROOT%\runner\credshunter.bat" "%RESULT%"
```

Expected before the fix: `findstr` succeeds.

- [ ] **Step 2: Capture and apply the normalized executing path**

Before scanner-owned path variables are created, add:

```bat
set "SELF_PATH=%~f0"
```

In `:WalkDir`, omit a candidate when `!fp!` equals `!SELF_PATH!` using `if /I`. For a directly supplied file at the initial `FILELIST` construction, normalize it through `%%~fP` and apply the same comparison before writing it.

- [ ] **Step 3: Add the defensive content-scan guard**

At `:ScanFile`, normalize the argument and return for the executing path:

```bat
for %%I in ("%~1") do set "sPath=%%~fI"
if /I "!sPath!"=="!SELF_PATH!" goto :EOF
set "sLabel=%~2"
```

- [ ] **Step 4: Run native CMD validation**

```bat
del "%RESULT%" 2>nul
call "%ROOT%\runner\credshunter.bat" -Path "%ROOT%" -All -NoStage1 -NoStage2 -NoStage4 -NoStage6 -NoStage7 -OutputFile "%RESULT%" -Quiet
findstr /I /L /C:"%ROOT%\runner\credshunter.bat" "%RESULT%" && exit /b 1
findstr /I /L /C:"%ROOT%\copy\credshunter.bat" "%RESULT%" || exit /b 1
```

Expected: the running Batch path is absent and the separate copy is present. If no Windows host is available, record native CMD validation as unverified rather than claiming success.

- [ ] **Step 5: Commit the Batch change**

```bash
git add credshunter.bat
git commit -m "fix: exclude running CMD scanner from findings"
```

### Task 4: Cross-platform review and final verification

**Files:**
- Verify: `credshunter.sh`
- Verify: `credshunter.ps1`
- Verify: `credshunter.bat`
- Verify: `docs/superpowers/specs/2026-08-21-cross-platform-self-exclusion-design.md`

**Interfaces:**
- Consumes: the three platform-specific self-exclusion implementations.
- Produces: a verified change set with platform limitations stated accurately.

- [ ] **Step 1: Check scope and whitespace**

```bash
git diff --check
git diff --stat HEAD~3..HEAD
git status --short
```

- [ ] **Step 2: Re-run available local validation**

```bash
bash -n credshunter.sh
command -v shellcheck >/dev/null && shellcheck credshunter.sh || true
command -v pwsh >/dev/null && pwsh -NoProfile -Command '$e=$null; [void][System.Management.Automation.Language.Parser]::ParseFile((Resolve-Path ./credshunter.ps1),[ref]$null,[ref]$e); if($e.Count){$e; exit 1}' || true
```

Expected: Bash syntax succeeds; optional installed analyzers report no new errors. Do not interpret a missing `pwsh` or `cmd.exe` runtime as a successful native test.

- [ ] **Step 3: Review exact-path semantics**

Confirm that no implementation uses a basename-only rule to suppress all files named `credshunter.sh`, `credshunter.ps1`, or `credshunter.bat`, and that Stage 6 Git-marker behavior and Stage 7 environment behavior are unchanged.

- [ ] **Step 4: Report verification boundaries**

Report Bash runtime results, PowerShell parser/runtime results if available, and native CMD validation status separately. Include any unverified platform explicitly in the final response.
