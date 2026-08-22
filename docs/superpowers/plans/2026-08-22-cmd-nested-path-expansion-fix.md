# CMD Nested Path Expansion Fix Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Remove native CMD nested `%~variable` path-expansion failures from Stage 1 in `/Users/illnino/Project/oscp/Credential-Hunting/credshunter.bat` without changing findings, scan scope, or non-Batch scanners.

**Architecture:** Keep the existing Stage 1 control flow and helpers, but materialize every affected outer `FOR` root into a delayed-expansion variable before appending suffixes or using it as a nested `FOR /R` or `FOR /D` root. Reuse the current helper subroutines and matcher logic so the patch only changes path construction, then statically validate that all equivalent Stage 1 sites were covered.

**Tech Stack:** Windows Batch (`cmd.exe` semantics), delayed expansion, `findstr`, existing `credshunter.bat` helper labels, `git diff --check`, Python 3 for static validation on macOS.

**Spec:** `/Users/illnino/Project/oscp/Credential-Hunting/docs/superpowers/specs/2026-08-22-cmd-nested-path-expansion-fix-design.md`

## Global Constraints

- Stage 1 must construct GPP, history, vault, WinSCP, browser, SSH, remote manager, application-server, and other nested paths without `%~variable` substitution errors.
- The audit must cover every equivalent outer-`FOR` composite path, not only the examples seen in the captured output.
- Existing finding categories, matchers, scan roots, and stage order must remain unchanged.
- The implementation must remain strictly CMD-only, without PowerShell, .NET, or additional helper executables.
- Completed paths passed to existing finding and scanning subroutines must preserve the current argument interface.
- Only `/Users/illnino/Project/oscp/Credential-Hunting/credshunter.bat` and supporting design/plan documentation are changed.

---

### Task 1: Patch all affected Stage 1 nested-path construction sites

**Files:**
- Modify: `/Users/illnino/Project/oscp/Credential-Hunting/credshunter.bat`

**Interfaces:**
- Consumes: Existing Stage 1 labels `:Stage1_GPP` through `:Stage1_DotNetSecrets`; existing helper labels `:AddChecked`, `:AddHigh`, `:AddInterest`, `:ScanFile`.
- Produces: Same Stage 1 helper calls and same finding identifiers, but with materialized delayed-expansion variables such as `gppRoot`, `gppFile`, `psUserRoot`, `vaultRoot`, `winscpRoot`, `browserUserRoot`, `cloudUserRoot`, `sshUserRoot`, `rdpRoot`, `stickyUserRoot`, `dbeaverRoot`, `jenkinsRoot`, `appServerRoot`, `tomcatRoot`, and `userSecretsRoot`.

- [ ] **Step 1: Capture the current Stage 1 unsafe composite-path sites**

Run:

```bash
cd /Users/illnino/Project/oscp/Credential-Hunting
python3 - <<'PY'
from pathlib import Path
for i, line in enumerate(Path("credshunter.bat").read_text().splitlines(), 1):
    if "%%~" in line and "\\" in line:
        print(f"{i}:{line}")
PY
```

Expected: Output includes the GPP, PowerShell history, vault, WinSCP, browser, cloud CLI, SSH, RDP, Sticky Notes, DBeaver, Jenkins, Tomcat, and .NET user-secrets Stage 1 lines that currently append suffixes to `%%~<outer-variable>`.

- [ ] **Step 2: Materialize outer-loop roots before appending suffixes or recursing**

Update `/Users/illnino/Project/oscp/Credential-Hunting/credshunter.bat` so each affected outer loop starts by assigning the modified `FOR` value alone to a delayed-expansion variable, then build child paths from that variable. Use patterns like:

```bat
for %%R in ("%SystemRoot%\SYSVOL" "%ProgramData%\Microsoft\Group Policy\History" "%SystemRoot%\System32\GroupPolicy") do (
    set "gppRoot=%%~R"
    if exist "!gppRoot!\" (
        call :AddChecked "gpp_root" "!gppRoot!"
        for %%X in (Groups Services ScheduledTasks DataSources Drives Printers) do (
            set "gppFile=!gppRoot!\%%X.xml"
            if exist "!gppFile!" (
                call :AddChecked "gpp_xml" "!gppFile!"
                findstr /I /M /C:"cpassword=" "!gppFile!" >nul 2>&1
                if !errorlevel!==0 call :AddHigh "gpp/cpassword" "!gppFile!" "0" "cpassword found"
            )
            for /r "!gppRoot!" %%F in (%%X.xml) do (
                call :AddChecked "gpp_xml" "%%~F"
                findstr /I /M /C:"cpassword=" "%%~F" >nul 2>&1
                if !errorlevel!==0 call :AddHigh "gpp/cpassword" "%%~F" "0" "cpassword found"
            )
        )
    )
)
```

Apply the same pattern everywhere the Stage 1 audit identified an outer modified `FOR` variable used in:

- `if exist "%%~X\..."`
- `call :Helper "... "%%~X\..."`
- `for /r "%%~X" ...`
- `for /d %%Y in ("%%~X\...")`

Required concrete rewrites:

- `Stage1_GPP`: `gppRoot`, `gppFile`
- `Stage1_PSHistory`: `psUserRoot`, `psHistoryFile`
- `Stage1_Cmdkey`: `vaultRoot`, `vaultEntry`
- `Stage1_WinSCP`: `winscpRoot`
- `Stage1_Browser`: `browserUserRoot`, `browserFile`, `firefoxProfiles`
- `Stage1_CloudCLI`: `cloudUserRoot`, `cloudFile`
- `Stage1_SSH`: `sshUserRoot`, `sshDir`
- `Stage1_RDP`: `rdpRoot`
- `Stage1_StickyNotes`: `stickyUserRoot`, `stickyFile`
- `Stage1_DBClients`: `dbeaverRoot`
- `Stage1_AppServers`: `jenkinsRoot`, `jenkinsFile`, `appServerRoot`, `tomcatRoot`, `tomcatUsers`
- `Stage1_DotNetSecrets`: `userSecretsRoot`, `userSecretsFile`

- [ ] **Step 3: Keep behavior unchanged while tightening only path construction**

While editing, preserve these invariants exactly:

```text
- same Stage 1 label order and dispatcher calls
- same helper labels and argument count
- same finding IDs such as gpp/cpassword, winscp_ini, cloud_credential_file, tomcat_users
- same scan roots and file globs such as (WinSCP.ini), (*.rdp *.rdg), and secrets.json
- no new PowerShell, pwsh, cscript, wscript, .NET, or helper executable calls
```

Expected: The diff is limited to delayed-expansion variable assignments plus replacement of unsafe composite `%%~X\...` expressions at equivalent Stage 1 sites.

- [ ] **Step 4: Review the patched diff before validation**

Run:

```bash
cd /Users/illnino/Project/oscp/Credential-Hunting
git diff -- credshunter.bat
```

Expected: Only `/Users/illnino/Project/oscp/Credential-Hunting/credshunter.bat` changes, and the edits are restricted to Stage 1 path handling.

- [ ] **Step 5: Commit the code patch**

```bash
cd /Users/illnino/Project/oscp/Credential-Hunting
git add credshunter.bat
git commit -m "fix: harden batch stage1 path expansion"
```

### Task 2: Statically validate the Batch fix and document remaining runtime limits

**Files:**
- Modify: `/Users/illnino/Project/oscp/Credential-Hunting/credshunter.bat`
- Test: static shell and Python checks only; no native Windows runtime is assumed locally

**Interfaces:**
- Consumes: Patched `credshunter.bat`; existing literal `CALL :label` structure.
- Produces: Validation evidence that no audited Stage 1 unsafe composite path remains, all literal `CALL :label` targets still exist, and no new non-CMD dependency was introduced.

- [ ] **Step 1: Re-scan for unsafe Stage 1 composite-path patterns**

Run:

```bash
cd /Users/illnino/Project/oscp/Credential-Hunting
python3 - <<'PY'
from pathlib import Path
text = Path("credshunter.bat").read_text().splitlines()
for i, line in enumerate(text, 1):
    if 470 <= i <= 980 and "%%~" in line and "\\" in line:
        print(f"{i}:{line}")
PY
```

Expected: Remaining hits are only safe innermost complete-path variables such as `%%~F`, `%%~K`, or unrelated non-audited lines; there are no remaining Stage 1 `%%~<outer-variable>\...` composites or nested recursion roots using modified outer variables directly.

- [ ] **Step 2: Verify literal label dispatch integrity**

Run:

```bash
cd /Users/illnino/Project/oscp/Credential-Hunting
python3 - <<'PY'
from pathlib import Path
import re
lines = Path("credshunter.bat").read_text().splitlines()
labels = {m.group(1).lower() for line in lines if (m := re.match(r'^:([A-Za-z0-9_]+)$', line.strip()))}
missing = []
for i, line in enumerate(lines, 1):
    for match in re.finditer(r'call\s+:([A-Za-z0-9_]+)', line, re.I):
        label = match.group(1).lower()
        if label not in labels:
            missing.append((i, label, line))
if missing:
    raise SystemExit("\\n".join(f"{i}:{label}:{line}" for i, label, line in missing))
print("OK")
PY
```

Expected: `OK`

- [ ] **Step 3: Check formatting and dependency boundaries**

Run:

```bash
cd /Users/illnino/Project/oscp/Credential-Hunting
git diff --check
python3 - <<'PY'
from pathlib import Path
text = Path("credshunter.bat").read_text()
for needle in ["powershell", "pwsh", "System.IO", "cscript", "wscript"]:
    if needle.lower() in text.lower():
        print(f"FOUND:{needle}")
PY
```

Expected: `git diff --check` prints nothing, and the dependency scan shows no new helper/runtime additions beyond pre-existing Batch content.

- [ ] **Step 4: Record the native-runtime validation gap honestly**

Use this exact reviewer note in the final handoff unless a native Windows `cmd.exe` run is performed later:

```text
Native cmd.exe runtime validation is still unverified locally; this patch is backed by static audit plus user-side Windows execution to confirm the Stage 1.2, Stage 1.5, and Stage 1.7 failures are gone.
```

- [ ] **Step 5: Commit any final validation-only cleanup if needed**

```bash
cd /Users/illnino/Project/oscp/Credential-Hunting
git status --short
```

Expected: No additional source changes beyond the intended Batch patch and plan/spec docs already tracked in git.

## Self-Review

- Spec coverage: Task 1 implements the required materialization pattern at every audited Stage 1 site; Task 2 covers static enumeration, label checks, dependency boundaries, and the native-runtime caveat required by the spec.
- Placeholder scan: No `TODO`, `TBD`, or vague “handle appropriately” language remains; every task includes exact commands, concrete variable names, and expected outcomes.
- Type and name consistency: All delayed-expansion variable names referenced in later steps are introduced in Task 1, and the helper-label interfaces remain the current string-based Batch arguments.
