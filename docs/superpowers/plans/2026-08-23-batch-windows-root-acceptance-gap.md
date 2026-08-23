# Batch Windows Root Acceptance Gap Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Fix `credshunter.bat` so discovered backup Windows roots like `C:\Windows.old\Windows` are accepted and probed when they contain direct `System32\SAM|SYSTEM|SECURITY` artifacts, even if `System32\config\` is absent.

**Architecture:** Keep the existing Batch fixed-drive discovery, `%SystemDrive%` fallback, structured probe list, loose-backup recursion, and reporting unchanged. Narrow the patch to `:Stage1RecordWindowsRoot` by replacing its single `System32\config\` gate with a multi-path acceptance check that mirrors the structured layouts the script already probes later.

**Tech Stack:** Windows Batch (`cmd.exe`), existing Stage 1 helper labels, `findstr`, `git diff --check`, Python 3 for static validation on macOS.

**Spec:** `/Users/illnino/Project/oscp/Credential-Hunting/docs/superpowers/specs/2026-08-23-batch-windows-root-acceptance-gap-design.md`

## Global Constraints

- Update only `/Users/illnino/Project/oscp/Credential-Hunting/credshunter.bat`.
- Keep the existing Batch fixed-drive discovery and `%SystemDrive%` fallback.
- Keep the existing structured probe list, including:
  - `System32\config\...`
  - `System32\SAM`
  - `System32\SYSTEM`
  - `System32\SECURITY`
  - `repair\...`
  - `RegBack\...`
  - `NTDS\ntds.dit`
- Change root acceptance so a discovered Windows root is kept when any valid Stage 1 structured artifact layout exists under it.
- Keep PowerShell and Bash unchanged in this patch.
- Do not broaden recursive search, labels, severity, or stage numbering.

---

### Task 1: Replace the Batch root-acceptance gate with a structured-layout check

**Files:**
- Modify: `/Users/illnino/Project/oscp/Credential-Hunting/credshunter.bat`

**Interfaces:**
- Consumes: Existing `:Stage1RecordWindowsRoot`, `:Stage1AppendUnique`, `:Stage1ProbeWindowsRoot`, and current Windows-root discovery flow.
- Produces: A widened root-acceptance check that admits backup roots containing any already-supported structured artifact layout, while leaving the downstream probe loop untouched.

- [ ] **Step 1: Inspect the current `:Stage1RecordWindowsRoot` implementation**

Run:

```bash
cd /Users/illnino/Project/oscp/Credential-Hunting
sed -n '688,702p' credshunter.bat
```

Expected: The label contains this single gate:

```bat
if not exist "%~1\System32\config\" goto :EOF
```

- [ ] **Step 2: Replace the single gate with a narrow multi-path acceptance block**

Edit `:Stage1RecordWindowsRoot` in `credshunter.bat` so it becomes:

```bat
:Stage1RecordWindowsRoot
set "candidateWindowsRoot=%~1"
set "candidateRootAccepted="
if exist "!candidateWindowsRoot!\System32\config\" set "candidateRootAccepted=1"
if not defined candidateRootAccepted if exist "!candidateWindowsRoot!\System32\SAM" set "candidateRootAccepted=1"
if not defined candidateRootAccepted if exist "!candidateWindowsRoot!\System32\SYSTEM" set "candidateRootAccepted=1"
if not defined candidateRootAccepted if exist "!candidateWindowsRoot!\System32\SECURITY" set "candidateRootAccepted=1"
if not defined candidateRootAccepted if exist "!candidateWindowsRoot!\NTDS\ntds.dit" set "candidateRootAccepted=1"
if not defined candidateRootAccepted goto :EOF
for %%A in ("!candidateWindowsRoot!") do set "candidateWindowsRoot=%%~fA"
call :Stage1AppendUnique "!candidateWindowsRoot!" "%~2"
set "candidateRootAccepted="
set "candidateWindowsRoot="
goto :EOF
```

Do not change:

```text
- :Stage1CollectFixedDrives
- :Stage1ProbeWindowsRoot
- :Stage1LooseBackupDrive
- readability checks
- labels or stage banner
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
    'System32\\config\\',
    'System32\\SAM',
    'System32\\SYSTEM',
    'System32\\SECURITY',
    'NTDS\\ntds.dit',
    ':Stage1RecordWindowsRoot',
    ':Stage1ProbeWindowsRoot'
]:
    assert needle in text, needle
labels = {m.group(1).lower() for m in re.finditer(r'^:([A-Za-z0-9_]+)$', text, re.M)}
for call in re.finditer(r'call\\s+:([A-Za-z0-9_]+)', text, re.I):
    assert call.group(1).lower() in labels, call.group(1)
print("bat-root-gap-check: OK")
PY
git diff --check -- credshunter.bat
```

Expected: `bat-root-gap-check: OK`, and `git diff --check` prints nothing.

- [ ] **Step 4: Commit the Batch fix**

```bash
cd /Users/illnino/Project/oscp/Credential-Hunting
git add credshunter.bat
git commit -m "fix: accept backup windows roots in batch"
```

### Task 2: Validate that the patch stayed narrow

**Files:**
- Modify: `/Users/illnino/Project/oscp/Credential-Hunting/credshunter.bat`

**Interfaces:**
- Consumes: The completed `:Stage1RecordWindowsRoot` acceptance change from Task 1.
- Produces: Validation evidence that only Batch changed, recursive search was not broadened, and the probe loop itself remained intact.

- [ ] **Step 1: Review the diff scope**

Run:

```bash
cd /Users/illnino/Project/oscp/Credential-Hunting
git diff --stat HEAD~1..HEAD
git diff --name-only HEAD~1..HEAD
```

Expected: Only `credshunter.bat` appears in the implementation commit for this patch.

- [ ] **Step 2: Confirm acceptance widened but probing stayed the same**

Run:

```bash
cd /Users/illnino/Project/oscp/Credential-Hunting
python3 - <<'PY'
from pathlib import Path
text = Path("credshunter.bat").read_text()
assert '!probeWindowsRoot!\\System32\\config\\SAM' in text
assert '!probeWindowsRoot!\\System32\\SAM' in text
assert '!probeWindowsRoot!\\NTDS\\ntds.dit' in text
assert ':Stage1LooseBackupDrive' in text
print("probe-scope-check: OK")
PY
```

Expected: `probe-scope-check: OK`

- [ ] **Step 3: Confirm no PowerShell or Bash changes were made by this patch**

Run:

```bash
cd /Users/illnino/Project/oscp/Credential-Hunting
git diff --name-only HEAD~1..HEAD -- credshunter.ps1 credshunter.sh
```

Expected: No output.

- [ ] **Step 4: Record the runtime note honestly**

Use this exact note unless native Windows `cmd.exe` validation is performed later:

```text
Native cmd.exe runtime validation is still unverified locally; this Batch-only gate fix is statically reviewed and should be re-tested on Windows with a real path such as C:\Windows.old\Windows\System32\SAM.
```

- [ ] **Step 5: Commit any cleanup only if validation forced a source edit**

```bash
cd /Users/illnino/Project/oscp/Credential-Hunting
git status --short
```

Expected: No uncommitted Batch changes remain if validation did not require a follow-up edit.

## Self-Review

- Spec coverage: Task 1 replaces the single `System32\config\` gate with the required multi-path acceptance check; Task 2 confirms the probe loop, recursion, and non-Batch files stayed unchanged.
- Placeholder scan: No incomplete placeholder markers or vague “handle appropriately” instructions remain; each task includes exact code blocks, commands, and expected outputs.
- Type consistency: The plan preserves the existing Batch label names and Stage 1 helper interfaces, and the new acceptance paths exactly match the structured probe targets already used later in the file.
