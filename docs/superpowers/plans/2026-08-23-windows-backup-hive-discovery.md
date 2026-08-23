# Windows Backup Hive Discovery Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Extend the Windows scanners to find readable SAM/SYSTEM/SECURITY hive copies and tightly-gated `ntds.dit` backups on fixed local disks without creating a noisy whole-disk filename hunt.

**Architecture:** Keep the existing direct `%SystemRoot%` / `$env:SystemRoot` probes, then add two bounded discovery layers: Windows-root discovery across fixed local disks and a tight loose-backup pass gated by exact filenames plus backup-like path tokens. Reuse the current Stage 1 reporting flow, but make Batch perform real readability checks before emitting readable findings and give `ntds.dit` its own labels.

**Tech Stack:** PowerShell 5.1+, Windows Batch (`cmd.exe`), existing scanner helper functions and labels, `Test-Path`, `[System.IO.File]::OpenRead`, `wmic logicaldisk`, `dir /s /b`, `findstr`, `git diff --check`, Python 3 for static validation on macOS.

**Spec:** `/Users/illnino/Project/oscp/Credential-Hunting/docs/superpowers/specs/2026-08-23-windows-backup-hive-discovery-design.md`

## Global Constraints

- Update only the Windows scanners:
  - `/Users/illnino/Project/oscp/Credential-Hunting/credshunter.ps1`
  - `/Users/illnino/Project/oscp/Credential-Hunting/credshunter.bat`
- Keep the existing direct checks against the live Windows root.
- Extend Stage 1 to detect backup or migrated copies of:
  - `SAM`
  - `SYSTEM`
  - `SECURITY`
  - `ntds.dit`
- Search fixed local disks only.
- Prefer structure-aware Windows-root discovery plus a tight loose-backup pass.
- Respect existing default exclusions for the new recursive pass, except for explicit Windows-root probes that are intentionally targeted.
- Report `readable_*` findings only after a real readability/open check.
- Keep Bash unchanged.

---

### Task 1: Refactor PowerShell Stage 1.10 into direct probes plus bounded backup discovery

**Files:**
- Modify: `/Users/illnino/Project/oscp/Credential-Hunting/credshunter.ps1`

**Interfaces:**
- Consumes: Existing `Add-Checked -Label <string> -Path <string>`, `Add-Interesting -Category <string> -Path <string>`, `Add-Finding -Bucket <string> -Label <string> -Path <string> -LineNumber <int> -Preview <string>`, and `Invoke-Stage1Check { Test-SAMHives }`.
- Produces: `Test-SAMHives` that emits `sam_hive`, `readable_hive`, `readable_sam_hive`, `ntds_file`, `readable_ntds`, and `readable_ntds_dit`; helper functions for fixed-drive enumeration, backup-token checks, Windows-root discovery, and NTDS path gating.

- [ ] **Step 1: Capture the current PowerShell Stage 1.10 block before edits**

Run:

```bash
cd /Users/illnino/Project/oscp/Credential-Hunting
sed -n '2230,2265p' credshunter.ps1
```

Expected: The output shows the current `Test-SAMHives` function using only `$env:SystemRoot`, `repair`, and `RegBack`.

- [ ] **Step 2: Add focused helper functions above `Test-SAMHives`**

Implement small PowerShell helpers near the Stage 1 Windows checks:

```powershell
function Get-FixedDriveRoots {
    Get-CimInstance Win32_LogicalDisk -ErrorAction SilentlyContinue |
        Where-Object { $_.DriveType -eq 3 -and $_.DeviceID } |
        ForEach-Object { $_.DeviceID + '\' }
}

function Test-BackupTokenPath {
    param([string]$Path)
    return $Path -match '(?i)(\\|/)(backup|bak|old|image|snapshot|copy|export|dump)(\\|/|$)'
}

function Test-NtdsBackupPath {
    param([string]$Path)
    return (Test-BackupTokenPath -Path $Path) -and ($Path -match '(?i)(ntds|active directory|windows)')
}
```

Then add a Windows-root discovery helper that:

```powershell
function Get-CandidateWindowsRoots {
    $roots = New-Object 'System.Collections.Generic.HashSet[string]' ([System.StringComparer]::OrdinalIgnoreCase)
    if ($env:SystemRoot) { [void]$roots.Add($env:SystemRoot) }
    foreach ($drive in Get-FixedDriveRoots) {
        foreach ($candidate in @(
            (Join-Path $drive 'Windows'),
            (Join-Path $drive 'Windows.old\Windows')
        )) {
            if (Test-Path -LiteralPath $candidate) { [void]$roots.Add($candidate) }
        }
        Get-ChildItem -LiteralPath $drive -Directory -Force -ErrorAction SilentlyContinue |
            Where-Object { Test-BackupTokenPath -Path $_.FullName } |
            ForEach-Object {
                Get-ChildItem -LiteralPath $_.FullName -Directory -Force -ErrorAction SilentlyContinue |
                    Where-Object { $_.Name -ieq 'Windows' } |
                    ForEach-Object { [void]$roots.Add($_.FullName) }
            }
    }
    return $roots
}
```

- [ ] **Step 3: Replace `Test-SAMHives` with direct probes plus bounded backup discovery**

Update `Test-SAMHives` so it:

```powershell
function Test-SAMHives {
    Write-Info "Stage 1.10 - SAM/SYSTEM/SECURITY/NTDS backup files"

    $hiveSuffixes = @(
        'System32\config\SAM',
        'System32\config\SYSTEM',
        'System32\config\SECURITY',
        'repair\SAM',
        'repair\SYSTEM',
        'repair\SECURITY',
        'System32\config\RegBack\SAM',
        'System32\config\RegBack\SYSTEM',
        'System32\config\RegBack\SECURITY'
    )

    $seen = New-Object 'System.Collections.Generic.HashSet[string]' ([System.StringComparer]::OrdinalIgnoreCase)
    foreach ($root in Get-CandidateWindowsRoots) {
        foreach ($suffix in $hiveSuffixes) {
            $h = Join-Path $root $suffix
            if (-not (Test-Path -LiteralPath $h)) { continue }
            if (-not $seen.Add($h)) { continue }
            Add-Checked -Label 'sam_hive' -Path $h
            try {
                $fs = [System.IO.File]::OpenRead($h)
                $fs.Close()
                Add-Interesting -Category 'readable_hive' -Path $h
                Add-Finding -Bucket Key -Label 'readable_sam_hive' -Path $h -LineNumber 0 -Preview "Hive readable - extract with secretsdump.py / impacket-secretsdump"
            } catch {}
        }

        $rootNtds = Join-Path $root 'NTDS\ntds.dit'
        if ((Test-Path -LiteralPath $rootNtds) -and $seen.Add($rootNtds)) {
            Add-Checked -Label 'ntds_file' -Path $rootNtds
            try {
                $fs = [System.IO.File]::OpenRead($rootNtds)
                $fs.Close()
                Add-Interesting -Category 'readable_ntds' -Path $rootNtds
                Add-Finding -Bucket Key -Label 'readable_ntds_dit' -Path $rootNtds -LineNumber 0 -Preview "NTDS.dit readable - extract with secretsdump.py / impacket-secretsdump"
            } catch {}
        }
    }
}
```

Then append a loose-backup pass driven by:

```powershell
foreach ($drive in Get-FixedDriveRoots) {
    Get-ChildItem -LiteralPath $drive -Recurse -Force -File -ErrorAction SilentlyContinue |
        Where-Object { $_.Name -cin @('SAM','SYSTEM','SECURITY','ntds.dit') } |
        Select-Object -First 500 |
        ForEach-Object {
            $path = $_.FullName
            if ($_.Name -ieq 'ntds.dit') {
                if (-not (Test-NtdsBackupPath -Path $path)) { return }
                if (-not $seen.Add($path)) { return }
                Add-Checked -Label 'ntds_file' -Path $path
                try {
                    $fs = [System.IO.File]::OpenRead($path)
                    $fs.Close()
                    Add-Interesting -Category 'readable_ntds' -Path $path
                    Add-Finding -Bucket Key -Label 'readable_ntds_dit' -Path $path -LineNumber 0 -Preview "NTDS.dit readable - extract with secretsdump.py / impacket-secretsdump"
                } catch {}
            } else {
                if (-not (Test-BackupTokenPath -Path $path)) { return }
                if (-not $seen.Add($path)) { return }
                Add-Checked -Label 'sam_hive' -Path $path
                try {
                    $fs = [System.IO.File]::OpenRead($path)
                    $fs.Close()
                    Add-Interesting -Category 'readable_hive' -Path $path
                    Add-Finding -Bucket Key -Label 'readable_sam_hive' -Path $path -LineNumber 0 -Preview "Hive readable - extract with secretsdump.py / impacket-secretsdump"
                } catch {}
            }
        }
}
```

Adjust the recursive enumeration to reuse any existing exclusion helper in the file if present; if no reusable helper exists, add a dedicated predicate that skips the same exclusion roots used elsewhere in the PowerShell scanner.

- [ ] **Step 4: Run a syntax-only sanity check on the edited PowerShell**

Run:

```bash
cd /Users/illnino/Project/oscp/Credential-Hunting
python3 - <<'PY'
from pathlib import Path
text = Path("credshunter.ps1").read_text()
assert "Stage 1.10 - SAM/SYSTEM/SECURITY/NTDS backup files" in text
for needle in ["Get-FixedDriveRoots", "Get-CandidateWindowsRoots", "readable_ntds_dit", "ntds_file"]:
    assert needle in text, needle
print("OK")
PY
```

Expected: `OK`

- [ ] **Step 5: Commit the PowerShell change**

```bash
cd /Users/illnino/Project/oscp/Credential-Hunting
git add credshunter.ps1
git commit -m "feat: expand PowerShell backup hive discovery"
```

### Task 2: Add equivalent bounded discovery and real readability checks to Batch Stage 1.10

**Files:**
- Modify: `/Users/illnino/Project/oscp/Credential-Hunting/credshunter.bat`

**Interfaces:**
- Consumes: Existing labels `:Stage1_SAM`, `:AddChecked`, `:AddInterest`, `:AddKey`; current delayed-expansion conventions from recent Stage 1 fixes.
- Produces: Batch helpers to enumerate fixed drives, gate backup-like paths, record deduped artifact hits, and attempt real readability checks before emitting `readable_hive`, `readable_sam_hive`, `readable_ntds`, and `readable_ntds_dit`.

- [ ] **Step 1: Capture the current Batch Stage 1.10 block and helper neighborhood**

Run:

```bash
cd /Users/illnino/Project/oscp/Credential-Hunting
sed -n '647,740p' credshunter.bat
```

Expected: The output shows simple existence-only checks against `%SystemRoot%`.

- [ ] **Step 2: Add small helper labels for fixed drives, backup-token gating, dedupe, and readability**

Implement helper labels near other support labels in `credshunter.bat`:

```bat
:CanReadBinary
set "CANREAD="
set "candidate=%~1"
2>nul (
    <"%candidate%" set /p "=."
) >nul && set "CANREAD=1"
goto :EOF

:PathHasBackupToken
set "PATHTOKEN="
echo;%~1| findstr /I /R "\\backup\\ \\bak\\ \\old\\ \\image\\ \\snapshot\\ \\copy\\ \\export\\ \\dump\\">nul && set "PATHTOKEN=1"
goto :EOF

:PathHasNtdsContext
set "NTDSTOKEN="
echo;%~1| findstr /I /R "ntds active directory windows">nul && set "NTDSTOKEN=1"
goto :EOF
```

Add fixed-drive enumeration using:

```bat
for /f "skip=1 tokens=1" %%D in ('wmic logicaldisk where "drivetype=3" get deviceid 2^>nul') do (
    if not "%%~D"=="" call :Stage1_SAM_Drive "%%~D\"
)
```

And add a dedupe label backed by a temp file or in-memory variable map so the same path is not reported twice.

- [ ] **Step 3: Rewrite `:Stage1_SAM` to combine direct probes, Windows-root discovery, and loose-backup search**

Update the stage banner and direct probes:

```bat
:Stage1_SAM
if not defined QUIET echo !CB![*] Stage 1.10 - SAM/SYSTEM/SECURITY/NTDS backup files!CNC!
for %%R in ("%SystemRoot%" "%SystemDrive%\Windows.old\Windows") do (
    set "samRoot=%%~R"
    if exist "!samRoot!\" call :Stage1_SAM_Root "!samRoot!"
)
for /f "skip=1 tokens=1" %%D in ('wmic logicaldisk where "drivetype=3" get deviceid 2^>nul') do (
    if not "%%~D"=="" call :Stage1_SAM_Drive "%%~D\"
)
goto :EOF
```

Implement `:Stage1_SAM_Root` to probe:

```bat
for %%S in (
    "System32\config\SAM"
    "System32\config\SYSTEM"
    "System32\config\SECURITY"
    "repair\SAM"
    "repair\SYSTEM"
    "repair\SECURITY"
    "System32\config\RegBack\SAM"
    "System32\config\RegBack\SYSTEM"
    "System32\config\RegBack\SECURITY"
) do (
    set "samCandidate=%~1\%%~S"
    call :Stage1_RecordHive "!samCandidate!"
)
set "ntdsCandidate=%~1\NTDS\ntds.dit"
call :Stage1_RecordNtds "!ntdsCandidate!"
```

Implement `:Stage1_SAM_Drive` to:

- probe `%%drive%%Windows\` and `%%drive%%Windows.old\Windows\` directly
- recursively enumerate exact names using `dir /s /b` with one pattern at a time:

```bat
for %%N in (SAM SYSTEM SECURITY ntds.dit) do (
    for /f "delims=" %%F in ('dir /s /b "%~1%%N" 2^>nul') do (
        call :Stage1_SAM_FilterLoose "%%~fF"
    )
)
```

` :Stage1_SAM_FilterLoose` must:

- reject duplicates
- reject excluded roots
- require `:PathHasBackupToken` for `SAM` / `SYSTEM` / `SECURITY`
- require both `:PathHasBackupToken` and `:PathHasNtdsContext` for `ntds.dit`
- call `:Stage1_RecordHive` or `:Stage1_RecordNtds`

` :Stage1_RecordHive` must:

```bat
if exist "%~1" (
    call :AddChecked "sam_hive" "%~1"
    call :CanReadBinary "%~1"
    if defined CANREAD (
        call :AddInterest "readable_hive" "%~1"
        call :AddKey "readable_sam_hive" "%~1" "0" "Hive readable - extract with secretsdump"
    )
)
goto :EOF
```

` :Stage1_RecordNtds` must:

```bat
if exist "%~1" (
    call :AddChecked "ntds_file" "%~1"
    call :CanReadBinary "%~1"
    if defined CANREAD (
        call :AddInterest "readable_ntds" "%~1"
        call :AddKey "readable_ntds_dit" "%~1" "0" "NTDS.dit readable - extract with secretsdump"
    )
)
goto :EOF
```

- [ ] **Step 4: Run static Batch checks after the rewrite**

Run:

```bash
cd /Users/illnino/Project/oscp/Credential-Hunting
python3 - <<'PY'
from pathlib import Path
import re
text = Path("credshunter.bat").read_text()
for needle in [
    "Stage 1.10 - SAM/SYSTEM/SECURITY/NTDS backup files",
    ":Stage1_RecordHive",
    ":Stage1_RecordNtds",
    "readable_ntds_dit",
    "wmic logicaldisk where \"drivetype=3\" get deviceid"
]:
    assert needle in text, needle
labels = {m.group(1).lower() for m in re.finditer(r"^:([A-Za-z0-9_]+)$", text, re.M)}
for call in re.finditer(r"call\\s+:([A-Za-z0-9_]+)", text, re.I):
    assert call.group(1).lower() in labels, call.group(1)
print("OK")
PY
git diff --check
```

Expected: `OK`, and `git diff --check` prints nothing.

- [ ] **Step 5: Commit the Batch change**

```bash
cd /Users/illnino/Project/oscp/Credential-Hunting
git add credshunter.bat
git commit -m "feat: expand batch backup hive discovery"
```

### Task 3: Validate scope, exclusion behavior, and final handoff notes

**Files:**
- Modify: `/Users/illnino/Project/oscp/Credential-Hunting/credshunter.ps1`
- Modify: `/Users/illnino/Project/oscp/Credential-Hunting/credshunter.bat`

**Interfaces:**
- Consumes: Completed PowerShell and Batch Stage 1.10 implementations from Tasks 1 and 2.
- Produces: Final validation evidence that Bash was untouched, stage wording is updated, fixed-drive-only logic exists, and the recursive pass stays tight.

- [ ] **Step 1: Review the cross-file diff and confirm only Windows scanners changed**

Run:

```bash
cd /Users/illnino/Project/oscp/Credential-Hunting
git diff --stat HEAD~2..HEAD
git diff --name-only HEAD~2..HEAD
```

Expected: Only `credshunter.ps1` and `credshunter.bat` appear in the code-change commits for this feature.

- [ ] **Step 2: Re-scan for the agreed labels, stage text, and fixed-drive-only logic**

Run:

```bash
cd /Users/illnino/Project/oscp/Credential-Hunting
rg -n "SAM/SYSTEM/SECURITY/NTDS backup files|readable_ntds|readable_ntds_dit|ntds_file|DriveType -eq 3|drivetype=3" credshunter.ps1 credshunter.bat
```

Expected: Matches exist in both Windows scanners.

- [ ] **Step 3: Re-scan for Bash changes**

Run:

```bash
cd /Users/illnino/Project/oscp/Credential-Hunting
git diff --name-only HEAD~2..HEAD -- credshunter.sh
```

Expected: No output.

- [ ] **Step 4: Record the native-runtime limitation honestly**

Use this exact final note unless a Windows runtime execution is later performed:

```text
Native Windows runtime validation is still unverified locally; the implementation is backed by static review and needs a real PowerShell/cmd.exe run on Windows to confirm backup-folder and ntds.dit coverage.
```

- [ ] **Step 5: Commit any final cleanup only if the validation step forced a source edit**

```bash
cd /Users/illnino/Project/oscp/Credential-Hunting
git status --short
```

Expected: No uncommitted source changes remain beyond the intended plan/spec docs if validation did not require fixes.

## Self-Review

- Spec coverage: Task 1 covers Windows-root discovery, fixed-drive-only enumeration, NTDS labels, and readability-first PowerShell reporting; Task 2 covers the equivalent Batch behavior plus the required readability hardening; Task 3 covers the explicit NTDS stage text, exclusion/scope checks, and Bash non-change validation.
- Placeholder scan: No incomplete placeholder markers or vague “handle appropriately” instructions remain; each task names exact files, helper labels/functions, commands, and expected outcomes.
- Type consistency: The same labels (`sam_hive`, `readable_hive`, `readable_sam_hive`, `ntds_file`, `readable_ntds`, `readable_ntds_dit`) are used consistently across tasks, and the fixed-drive-only logic is named consistently in both Windows implementations.
