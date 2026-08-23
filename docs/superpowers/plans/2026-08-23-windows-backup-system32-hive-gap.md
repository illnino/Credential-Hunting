# Windows Backup System32 Hive Gap Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Extend the Windows structured backup-root probes so they also detect `SAM`, `SYSTEM`, and `SECURITY` copied directly under `System32`, covering paths like `C:\Windows.old\Windows\System32\SAM` without broadening the recursive search.

**Architecture:** Keep the existing Windows-root discovery, recursive loose-backup logic, and reporting unchanged, but extend the structured suffix lists used by `Test-SAMHives` in PowerShell and `:Stage1ProbeWindowsRoot` in Batch. This is a narrow probe-list correction, not a discovery redesign.

**Tech Stack:** PowerShell 5.1+, Windows Batch (`cmd.exe`), existing Stage 1 helper functions/labels, `git diff --check`, Python 3 for static validation on macOS.

**Spec:** `/Users/illnino/Project/oscp/Credential-Hunting/docs/superpowers/specs/2026-08-23-windows-backup-system32-hive-gap-design.md`

## Global Constraints

- Update only the Windows scanners:
  - `/Users/illnino/Project/oscp/Credential-Hunting/credshunter.ps1`
  - `/Users/illnino/Project/oscp/Credential-Hunting/credshunter.bat`
- Keep the current direct live-root probes and backup-root discovery.
- Add explicit structured probes for backup-copy hive layouts under discovered Windows roots:
  - `System32\SAM`
  - `System32\SYSTEM`
  - `System32\SECURITY`
- Keep the existing `System32\config\...`, `repair\...`, `RegBack\...`, and `NTDS\ntds.dit` checks.
- Keep Bash unchanged.
- Do not broaden the recursive loose-backup search in this patch.
- Do not change labels, severities, or stage numbering in this patch.

---

### Task 1: Extend the PowerShell structured hive suffix list

**Files:**
- Modify: `/Users/illnino/Project/oscp/Credential-Hunting/credshunter.ps1`

**Interfaces:**
- Consumes: Existing `Test-SAMHives`, `$hiveSuffixes`, `Add-HiveArtifactResult`, and Windows-root discovery helpers already in place.
- Produces: A PowerShell structured probe list that includes both `System32\config\...` and direct `System32\...` hive layouts.

- [ ] **Step 1: Inspect the current PowerShell Stage 1.10 suffix list**

Run:

```bash
cd /Users/illnino/Project/oscp/Credential-Hunting
sed -n '2350,2385p' credshunter.ps1
```

Expected: The `$hiveSuffixes` array currently contains only `System32\config\...`, `repair\...`, and `RegBack\...`.

- [ ] **Step 2: Add the three direct `System32\...` suffixes without removing any existing entries**

Edit the `$hiveSuffixes` array in `credshunter.ps1` so it becomes:

```powershell
$hiveSuffixes = @(
    'System32\config\SAM'
    'System32\config\SYSTEM'
    'System32\config\SECURITY'
    'System32\SAM'
    'System32\SYSTEM'
    'System32\SECURITY'
    'repair\SAM'
    'repair\SYSTEM'
    'repair\SECURITY'
    'System32\config\RegBack\SAM'
    'System32\config\RegBack\SYSTEM'
    'System32\config\RegBack\SECURITY'
)
```

Do not change:

```text
- stage text
- NTDS logic
- recursive loose-backup pass
- readability-first reporting
- finding labels
```

- [ ] **Step 3: Run a static PowerShell content check**

Run:

```bash
cd /Users/illnino/Project/oscp/Credential-Hunting
python3 - <<'PY'
from pathlib import Path
text = Path("credshunter.ps1").read_text()
for needle in [
    "System32\\config\\SAM",
    "System32\\config\\SYSTEM",
    "System32\\config\\SECURITY",
    "System32\\SAM",
    "System32\\SYSTEM",
    "System32\\SECURITY",
    "NTDS\\ntds.dit"
]:
    assert needle in text, needle
print("ps1-gap-check: OK")
PY
git diff --check -- credshunter.ps1
```

Expected: `ps1-gap-check: OK`, and `git diff --check` prints nothing.

- [ ] **Step 4: Commit the PowerShell gap fix**

```bash
cd /Users/illnino/Project/oscp/Credential-Hunting
git add credshunter.ps1
git commit -m "fix: probe direct System32 backup hives in PowerShell"
```

### Task 2: Extend the Batch structured hive suffix list

**Files:**
- Modify: `/Users/illnino/Project/oscp/Credential-Hunting/credshunter.bat`

**Interfaces:**
- Consumes: Existing `:Stage1ProbeWindowsRoot`, `:Stage1RecordHiveArtifact`, `:Stage1RecordNtdsArtifact`, and the current Windows-root discovery helpers.
- Produces: A Batch structured probe loop that includes both `System32\config\...` and direct `System32\...` hive layouts.

- [ ] **Step 1: Inspect the current Batch structured probe loop**

Run:

```bash
cd /Users/illnino/Project/oscp/Credential-Hunting
sed -n '700,728p' credshunter.bat
```

Expected: The `for %%H in (...)` list inside `:Stage1ProbeWindowsRoot` currently contains only `System32\config\...`, `repair\...`, and `RegBack\...`.

- [ ] **Step 2: Add the three direct `System32\...` paths to the Batch probe list**

Edit the `for %%H in (...)` block in `credshunter.bat` so it becomes:

```bat
for %%H in (
    "!probeWindowsRoot!\System32\config\SAM"
    "!probeWindowsRoot!\System32\config\SYSTEM"
    "!probeWindowsRoot!\System32\config\SECURITY"
    "!probeWindowsRoot!\System32\SAM"
    "!probeWindowsRoot!\System32\SYSTEM"
    "!probeWindowsRoot!\System32\SECURITY"
    "!probeWindowsRoot!\repair\SAM"
    "!probeWindowsRoot!\repair\SYSTEM"
    "!probeWindowsRoot!\repair\SECURITY"
    "!probeWindowsRoot!\System32\config\RegBack\SAM"
    "!probeWindowsRoot!\System32\config\RegBack\SYSTEM"
    "!probeWindowsRoot!\System32\config\RegBack\SECURITY"
) do (
    if exist "%%~H" call :Stage1RecordHiveArtifact "%%~H" "%~2"
)
```

Do not change:

```text
- stage text
- NTDS logic
- loose-backup recursion
- exclusion logic
- readability check behavior
- finding labels
```

- [ ] **Step 3: Run static Batch checks**

Run:

```bash
cd /Users/illnino/Project/oscp/Credential-Hunting
python3 - <<'PY'
from pathlib import Path
import re
text = Path("credshunter.bat").read_text()
for needle in [
    "!probeWindowsRoot!\\System32\\config\\SAM",
    "!probeWindowsRoot!\\System32\\config\\SYSTEM",
    "!probeWindowsRoot!\\System32\\config\\SECURITY",
    "!probeWindowsRoot!\\System32\\SAM",
    "!probeWindowsRoot!\\System32\\SYSTEM",
    "!probeWindowsRoot!\\System32\\SECURITY",
    "!probeWindowsRoot!\\NTDS\\ntds.dit"
]:
    assert needle in text, needle
labels = {m.group(1).lower() for m in re.finditer(r'^:([A-Za-z0-9_]+)$', text, re.M)}
for call in re.finditer(r'call\\s+:([A-Za-z0-9_]+)', text, re.I):
    assert call.group(1).lower() in labels, call.group(1)
print("bat-gap-check: OK")
PY
git diff --check -- credshunter.bat
```

Expected: `bat-gap-check: OK`, and `git diff --check` prints nothing.

- [ ] **Step 4: Commit the Batch gap fix**

```bash
cd /Users/illnino/Project/oscp/Credential-Hunting
git add credshunter.bat
git commit -m "fix: probe direct System32 backup hives in batch"
```

### Task 3: Validate scope and confirm no discovery broadening

**Files:**
- Modify: `/Users/illnino/Project/oscp/Credential-Hunting/credshunter.ps1`
- Modify: `/Users/illnino/Project/oscp/Credential-Hunting/credshunter.bat`

**Interfaces:**
- Consumes: Completed PowerShell and Batch structured-probe list updates from Tasks 1 and 2.
- Produces: Final validation evidence that only the suffix lists changed for this gap fix and that recursive logic was not broadened.

- [ ] **Step 1: Review the cross-file diff**

Run:

```bash
cd /Users/illnino/Project/oscp/Credential-Hunting
git diff --stat HEAD~2..HEAD
git diff --name-only HEAD~2..HEAD
```

Expected: Only `credshunter.ps1` and `credshunter.bat` changed in the implementation commits for this gap fix.

- [ ] **Step 2: Confirm both new direct `System32\...` probes exist and recursive logic remains present, not widened**

Run:

```bash
cd /Users/illnino/Project/oscp/Credential-Hunting
rg -n "System32\\\\SAM|System32\\\\SYSTEM|System32\\\\SECURITY|System32\\\\config\\\\SAM|NTDS\\\\ntds.dit|Get-BackupArtifactCandidates|Stage1LooseBackupDrive" credshunter.ps1 credshunter.bat
```

Expected: Matches show the new direct `System32\...` probes plus the pre-existing recursive loose-backup entry points, with no new recursive function names added by this patch.

- [ ] **Step 3: Confirm Bash was not modified**

Run:

```bash
cd /Users/illnino/Project/oscp/Credential-Hunting
git diff --name-only HEAD~2..HEAD -- credshunter.sh
```

Expected: No output.

- [ ] **Step 4: Record the runtime note honestly**

Use this exact final note unless a Windows runtime execution is performed later:

```text
Native Windows runtime validation is still unverified locally; this narrow fix is statically reviewed and should be re-tested on Windows with a real path such as C:\Windows.old\Windows\System32\SAM.
```

- [ ] **Step 5: Commit any cleanup only if validation forced a source edit**

```bash
cd /Users/illnino/Project/oscp/Credential-Hunting
git status --short
```

Expected: No uncommitted source changes remain beyond the intended plan/spec docs if validation did not require fixes.

## Self-Review

- Spec coverage: Task 1 and Task 2 add the required `System32\SAM|SYSTEM|SECURITY` structured probes while preserving existing `config`, `repair`, `RegBack`, and `NTDS` checks; Task 3 confirms no Bash changes and no recursive broadening.
- Placeholder scan: No incomplete placeholder markers or vague “handle appropriately” instructions remain; each task includes exact paths, code snippets, commands, and expected outcomes.
- Type consistency: The same existing reporting interfaces and labels are preserved across both tasks, and the new probe paths are named consistently in both Windows implementations.
