# Stage 7 Process Environment Credential Discovery Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add default-on process-environment credential discovery to all three CredsHunter implementations with environment-only operation, secure snapshot handling, consistent findings, counting, and documentation.

**Architecture:** Each platform captures its inherited environment before scanner-owned state can contaminate it, then Stage 7 converts each variable into one logical `NAME=VALUE` assignment and feeds it through that platform's existing credential and private-key matchers. Environment locations use `ENV:<name>`, matching variable names are tracked separately for the subset summary count, and existing HIGH/KEY collections continue to control exit status.

**Tech Stack:** Bash 4+/GNU or BusyBox userland, Windows PowerShell 5.1-compatible PowerShell, CMD batch/findstr, Markdown, Docker-based Bash 5 and PowerShell 7 validation.

**Spec:** `docs/superpowers/specs/2026-08-17-stage7-process-environment-design.md`

## Global Constraints

- Stage 7 is enabled by default and independent of Stages 1-6.
- Inspect only the environment inherited by the scanner process.
- Bash uses `env -0` when available and line-delimited `env` only as fallback.
- PowerShell uses `Get-ChildItem Env:` and keeps its snapshot in memory.
- CMD uses `set` and remains strictly CMD-only: no PowerShell, .NET, or new helper dependency.
- `--no-stage7`/`--no-env` and `-NoStage7`/`-NoEnv` disable the stage.
- A scan path is optional while Stage 7 is enabled.
- Assignments over 16,384 characters are skipped with a value-free warning.
- Full accepted `NAME=VALUE` assignments are printed and logged; control characters are neutralized and embedded CR/LF/TAB bytes are represented visibly rather than executed.
- Count unique matched environment variable names; do not add this subset count to severity totals.
- Keep duplicate findings across file and environment sources because they are distinct exposures.
- Bump every displayed version from 2.4.0 to 2.5.0.
- Do not modify files outside `credshunter.sh`, `credshunter.ps1`, `credshunter.bat`, and `README.md` during runtime implementation.

---

### Task 1: Bash Stage 7

**Files:**
- Modify: `credshunter.sh:22-112`
- Modify: `credshunter.sh:248-292`
- Modify: `credshunter.sh:427-468`
- Modify: `credshunter.sh:966-1020`
- Modify: `credshunter.sh:1211-1370`
- Modify: `credshunter.sh:2110-2385`

**Interfaces:**
- Consumes: existing `CRED_PATTERNS`, `KEY_PATTERNS`, `classify_line`, `is_false_positive`, `record_finding`, stage lifecycle helpers, and finding files.
- Produces: `STARTUP_ENV`, `STARTUP_ENV_MODE`, `STAGE7_SKIP`, `ENV_FINDINGS_FILE`, `capture_startup_environment()`, `escape_environment_preview()`, and `scan_process_environment()`.

- [ ] **Step 1: Add an environment-only failing smoke check**

Run the unmodified script in a clean environment with all earlier stages disabled:

```bash
env -i PATH="$PATH" DB_PASSWORD='Stage7-Real-Secret!' \
  bash ./credshunter.sh --no-stage1 --no-stage2 --no-stage3 \
  --no-stage4 --no-stage5 --no-stage6 --no-color > /tmp/ch-bash-before.out 2>&1
status=$?
grep -F 'ENV:DB_PASSWORD' /tmp/ch-bash-before.out
test "$status" -eq 1
```

Expected before implementation: FAIL because no Stage 7 finding exists.

- [ ] **Step 2: Capture the inherited environment before `LC_ALL` mutation**

Add a startup array and capture function immediately after `set -uo pipefail`, then call it before assigning/exporting `LC_ALL`:

```bash
STARTUP_ENV=()
STARTUP_ENV_MODE='lines'
capture_startup_environment() {
    local item
    if env -0 </dev/null >/dev/null 2>&1; then
        STARTUP_ENV_MODE='nul'
        while IFS= read -r -d '' item; do STARTUP_ENV+=("$item"); done < <(env -0)
    else
        while IFS= read -r item || [ -n "$item" ]; do STARTUP_ENV+=("$item"); done < <(env)
    fi
}
capture_startup_environment
```

The fallback explicitly documents that embedded newlines cannot be reconstructed when `env -0` is unavailable.

- [ ] **Step 3: Add Stage 7 state and command-line controls**

Add `STAGE7_SKIP=0`, an owner-only `ENV_FINDINGS_FILE` in the existing `TMPDIR`, and argument cases:

```bash
--no-stage7|--no-env) STAGE7_SKIP=1; shift ;;
```

Update usage to make `-p` optional, list Stage 7 aliases, show an environment-only example, and warn that accepted values appear in plaintext output/logs.

- [ ] **Step 4: Reuse the existing matcher for logical assignments**

Implement `escape_environment_preview()` to remove terminal control bytes while rendering `\r`, `\n`, and `\t` visibly. Implement `scan_process_environment()` with this flow:

```bash
for assignment in "${STARTUP_ENV[@]}"; do
    [[ "$assignment" == *=* ]] || continue
    name=${assignment%%=*}
    [ -n "$name" ] || continue
    if [ "${#assignment}" -gt "$MAX_LINE_LEN" ]; then
        warn "Skipping oversized environment variable: ENV:$name (>16 KiB)"
        continue
    fi
    location="ENV:$name"
    matched=0
    for entry in "${KEY_PATTERNS[@]}"; do
        label="${entry%%|*}"
        regex="${entry#*|}"
        if [[ "$assignment" =~ $regex ]]; then
            record_finding KEY "process_env/${label}" "$location" 0 \
                "$(escape_environment_preview "$assignment")"
            matched=1
            break
        fi
    done
    classify_line "$assignment" "$location" 0 process_env && matched=1
    [ "$matched" -eq 1 ] && printf '%s\n' "$name" >>"$ENV_FINDINGS_FILE"
done
sort -u "$ENV_FINDINGS_FILE" -o "$ENV_FINDINGS_FILE"
```

Pass the escaped complete assignment as the preview. Adjust finding rendering so line `0` prints `ENV:NAME` without `:0`; file findings retain `path:line`.

- [ ] **Step 5: Integrate Stage 7 and its subset summary row**

After the Stage 2-6 path branch, always run or display the skipped Stage 7 block:

```bash
if [ "$STAGE7_SKIP" -eq 0 ]; then
    stage_begin 7
    scan_process_environment
    stage_end 7 "Process environment credential discovery"
else
    stage_skipped 7 "Process environment credential discovery"
fi
```

Add `Environment credential findings` to console and log summaries using the unique line count from `ENV_FINDINGS_FILE`. Do not include that count in the sensitive-exit calculation.

- [ ] **Step 6: Run Bash behavioral checks**

Run:

```bash
bash -n credshunter.sh
docker run --rm -v "$PWD:/repo:ro" -w /repo bash:5 \
  bash -n credshunter.sh

env -i PATH="$PATH" DB_PASSWORD='Stage7-Real-Secret!' BENIGN_NAME='hello' \
  bash ./credshunter.sh --no-stage1 --no-stage2 --no-stage3 \
  --no-stage4 --no-stage5 --no-stage6 --no-color > /tmp/ch-bash-hit.out 2>&1
test $? -eq 1
grep -F 'process_env/env_password' /tmp/ch-bash-hit.out
grep -F 'ENV:DB_PASSWORD' /tmp/ch-bash-hit.out
grep -F 'DB_PASSWORD=Stage7-Real-Secret!' /tmp/ch-bash-hit.out
grep -F 'Environment credential findings' /tmp/ch-bash-hit.out | grep -E '1[[:space:]]*$'
! grep -F 'ENV:BENIGN_NAME' /tmp/ch-bash-hit.out

env -i PATH="$PATH" DB_PASSWORD='Stage7-Real-Secret!' \
  bash ./credshunter.sh --no-env --no-stage1 --no-stage2 --no-stage3 \
  --no-stage4 --no-stage5 --no-stage6 --no-color > /tmp/ch-bash-skip.out 2>&1
test $? -eq 0
! grep -F 'ENV:DB_PASSWORD' /tmp/ch-bash-skip.out
grep -F 'Stage 7' /tmp/ch-bash-skip.out | grep -F '[SKIPPED]'
```

Repeat the skip assertion with `--no-stage7`. Test a 16,385-character assignment and confirm the warning contains the name but not the value. Test `-o` and confirm the full accepted assignment is logged with mode `600`.

- [ ] **Step 7: Commit the Bash implementation**

```bash
git add credshunter.sh
git commit -m "feat: scan process environment on Linux"
```

---

### Task 2: PowerShell Stage 7

**Files:**
- Modify: `credshunter.ps1:94-180`
- Modify: `credshunter.ps1:185-300`
- Modify: `credshunter.ps1:1225-1308`
- Modify: `credshunter.ps1:1415-1760`
- Modify: `credshunter.ps1:2871-3130`

**Interfaces:**
- Consumes: compiled `$script:CredPatterns`, `$script:KeyPatterns`, `Test-FalsePositive`, `Add-Finding`, `Format-Preview`, and stage lifecycle helpers.
- Produces: `[Alias('NoEnv')] $NoStage7`, `$script:StartupEnvironment`, `$script:Stage7Skip`, `$script:EnvironmentFindingNames`, `Test-CredentialAssignment`, and `Find-ProcessEnvironmentCredentials`.

- [ ] **Step 1: Add a failing environment-only container check**

```bash
docker run --rm -e DB_PASSWORD='Stage7-Real-Secret!' \
  -v "$PWD:/repo:ro" -w /repo mcr.microsoft.com/powershell:lts-alpine-3.20 \
  pwsh -NoProfile -File ./credshunter.ps1 -NoStage1 -NoStage2 -NoStage3 \
  -NoStage4 -NoStage5 -NoStage6 -NoColor
```

Expected before implementation: output lacks `ENV:DB_PASSWORD` and exits zero.

- [ ] **Step 2: Capture the inherited environment and add CLI controls**

Add:

```powershell
[Alias('NoEnv')]
[switch] $NoStage7
```

Change the early usage gate to `$Help` only so a no-argument invocation can run Stages 1 and 7. Immediately afterward, capture immutable name/value records:

```powershell
$script:StartupEnvironment = @(
    Get-ChildItem Env: | ForEach-Object {
        [PSCustomObject]@{ Name = [string]$_.Name; Value = [string]$_.Value }
    }
)
$script:Stage7Skip = $NoStage7.IsPresent
```

Add a case-insensitive `HashSet[string]` named `$script:EnvironmentFindingNames` and update help/examples/plaintext warning.

- [ ] **Step 3: Extract a reusable assignment classifier**

Move the per-line first-match classification logic from `Invoke-ScanFile` into:

```powershell
function Test-CredentialAssignment {
    param([string]$Text, [string]$SourceLabel, [string]$Location)
    # Return $true only when Add-Finding records a HIGH or KEY finding.
}
```

The function applies the existing key-marker checks, keyword prefilter, first-matching credential pattern, value extraction, hard-coded false positives, `Test-FalsePositive`, and `Add-Finding`. `Invoke-ScanFile` continues using the same logic for each file line so existing behavior does not drift. Use line number `0` for environment locations and update `Write-FindingsSection` to omit `:0`.

- [ ] **Step 4: Implement and integrate Stage 7**

Implement:

```powershell
function Find-ProcessEnvironmentCredentials {
    foreach ($entry in $script:StartupEnvironment) {
        $assignment = '{0}={1}' -f $entry.Name, $entry.Value
        if ($assignment.Length -gt $script:MaxLineLen) {
            Write-Warn ("Skipping oversized environment variable: ENV:{0} (>16 KiB)" -f $entry.Name)
            continue
        }
        if (Test-CredentialAssignment -Text $assignment -SourceLabel 'process_env' -Location ("ENV:" + $entry.Name)) {
            [void]$script:EnvironmentFindingNames.Add($entry.Name)
        }
    }
}
```

Run it as Stage 7 after the path-dependent Stage 2-6 branch. Add the unique-name count to console and log summaries without changing the sensitive-exit expression.

- [ ] **Step 5: Run PowerShell behavioral checks**

Use the PowerShell container to assert:

```powershell
$text = & ./credshunter.ps1 -NoStage1 -NoStage2 -NoStage3 -NoStage4 -NoStage5 -NoStage6 -NoColor 2>&1 | Out-String
if ($LASTEXITCODE -ne 1) { throw 'expected sensitive exit 1' }
if ($text -notmatch 'ENV:DB_PASSWORD') { throw 'missing environment location' }
if ($text -notmatch 'DB_PASSWORD=Stage7-Real-Secret!') { throw 'missing complete assignment' }
if ($text -notmatch 'Environment credential findings\s+\.+\s+1') { throw 'wrong environment count' }
```

Run equivalent checks for `-NoEnv`, `-NoStage7`, benign variables, duplicate patterns, output logging, a 16,385-character assignment, and no-argument operation. Parse-check with the PowerShell parser and confirm only PowerShell-5.1-compatible syntax is used.

- [ ] **Step 6: Commit the PowerShell implementation**

```bash
git add credshunter.ps1
git commit -m "feat: scan process environment on Windows"
```

---

### Task 3: CMD Stage 7

**Files:**
- Modify: `credshunter.bat:1-180`
- Modify: `credshunter.bat:330-430`
- Modify: `credshunter.bat:1548-1780`

**Interfaces:**
- Consumes: `%PATTERNS%`, `%KEYPATTERNS%`, `:AddHigh`, `:AddKey`, `%DEDUP%`, `%HIGH%`, `%KEY%`, `%EXITCODE%`, and `:WriteSummary`.
- Produces: `NOSTAGE7`, `ENV_SNAPSHOT`, `ENV_MATCHES`, `ENV_NAMES`, `nEnv`, `:DoStage7`, `:RecordEnvName`, and a single cleanup exit path.

- [ ] **Step 1: Capture `set` output before scanner defaults contaminate it**

Immediately after `setlocal DisableDelayedExpansion`, create the temporary workspace and snapshot:

```bat
set "TMPDIR=%TEMP%\credshunter_%RANDOM%_%RANDOM%"
mkdir "%TMPDIR%" 2>nul
set "ENV_SNAPSHOT=%TMPDIR%\environment.txt"
set > "%ENV_SNAPSHOT%"
```

The snapshot contains only inherited variables plus the two known bootstrap variables. `:DoStage7` explicitly ignores `TMPDIR` and `ENV_SNAPSHOT`. Move the later duplicate `TMPDIR` creation to this bootstrap and route help, normal exit, and fatal argument paths through cleanup so the snapshot is removed.

- [ ] **Step 2: Add Stage 7 arguments and path-optional behavior**

Parse both forms:

```bat
if /I "%arg%"=="-NoStage7" set "NOSTAGE7=1" & shift & goto ParseArgs
if /I "%arg%"=="/NoStage7" set "NOSTAGE7=1" & shift & goto ParseArgs
if /I "%arg%"=="-NoEnv"    set "NOSTAGE7=1" & shift & goto ParseArgs
if /I "%arg%"=="/NoEnv"    set "NOSTAGE7=1" & shift & goto ParseArgs
```

At `:ArgsDone`, require `-Path` only when Stage 7 is disabled. Update help, examples, stage range, and plaintext warning.

- [ ] **Step 3: Implement CMD-native matching without executing values**

Create `%ENV_MATCHES%` and `%ENV_NAMES%`. `:DoStage7` uses `findstr /I /G` against the snapshot for credential patterns and key patterns. It never uses `call`, delayed expansion, or `echo <expanded assignment>` for a value. Full matched assignments are emitted directly from snapshot files with `type`/`findstr`, preventing metacharacters in values from becoming commands.

For each normal variable name parsed before the first `=`, validate the name against the CMD-safe name character set before using it in a command. Use dynamic substring probing of the original variable (`:~16384,1`) to classify values over the cap without expanding the full value; oversized variables receive a name-only warning and are excluded from match output. Bootstrap names are ignored.

For accepted matches:

```text
[HIGH] process_env/credential_match  ENV:DB_PASSWORD
       DB_PASSWORD=Stage7-Real-Secret!
```

Add the finding through existing HIGH/KEY counters and exit semantics, but add the variable name to `%ENV_NAMES%` only once. Modify `:AddHigh`/`:AddKey` so line `0` does not render `:0`, while existing file findings are unchanged.

- [ ] **Step 4: Integrate independent execution, summary, and cleanup**

Run `:DoStage7` after the Stage 2-6 branch regardless of whether `%PATHS%` is defined. Add `[SKIPPED]` output for `NOSTAGE7`, initialize `nEnv=0`, and add `Environment credential findings` to console and log counts. Use one `:CleanupAndExit` label that removes `%TMPDIR%` with delayed expansion disabled and returns `%EXITCODE%`.

- [ ] **Step 5: Perform Batch static validation**

Check:

```bash
python3 - <<'PY'
from pathlib import Path
p = Path('credshunter.bat').read_text(errors='strict')
required = ['-NoStage7', '-NoEnv', ':DoStage7', 'ENV_SNAPSHOT',
            'Environment credential findings', '2.5.0-bat']
missing = [x for x in required if x not in p]
assert not missing, missing
assert 'powershell' not in p.lower()
PY
```

Manually trace no-argument, `-NoEnv` without `-Path`, help, normal completion, and Stage 7 sensitive-hit paths. Verify every path deletes the snapshot. Record native `cmd.exe` execution as outstanding rather than claiming behavioral success.

- [ ] **Step 6: Commit the Batch implementation**

```bash
git add credshunter.bat
git commit -m "feat: scan process environment in CMD"
```

---

### Task 4: Documentation and version consistency

**Files:**
- Modify: `README.md:1-170`
- Modify: `credshunter.sh:34`
- Modify: `credshunter.ps1:131`
- Modify: `credshunter.bat:4,22`

**Interfaces:**
- Consumes: completed CLI behavior from Tasks 1-3.
- Produces: consistent 2.5.0 version strings and operator documentation for Stages 6-7.

- [ ] **Step 1: Update all versions**

Set Bash and PowerShell to `2.5.0`, Batch to `2.5.0-bat`, and the README badge to `version-2.5.0`.

- [ ] **Step 2: Update README behavior and usage**

Change the five-stage description/table to seven stages, adding:

```markdown
| **6** | Git repository discovery | `.git` directories and valid `.git` indirection files |
| **7** | Process environment | Live inherited `NAME=VALUE` assignments matched by existing credential rules |
```

Document pathless environment-only Bash, PowerShell, and CMD examples; all Stage 7 skip aliases; the 16 KiB limit; the unique-variable summary count; and a prominent warning that accepted assignments are shown and logged in plaintext.

- [ ] **Step 3: Verify documentation consistency**

```bash
rg -n '2\.4\.0|five-stage|NoStage1\.\.6|no-stage2.*no-stage5' README.md credshunter.sh credshunter.ps1 credshunter.bat
rg -n '2\.5\.0|Stage 7|no-env|NoEnv|Environment credential findings' README.md credshunter.sh credshunter.ps1 credshunter.bat
git diff --check
```

Expected: no stale 2.4.0 or five-stage claims; every implementation and README contains the new controls and summary label.

- [ ] **Step 4: Commit documentation and versions**

```bash
git add README.md credshunter.sh credshunter.ps1 credshunter.bat
git commit -m "docs: document process environment scanning"
```

---

### Task 5: Cross-platform regression review

**Files:**
- Verify only: `credshunter.sh`
- Verify only: `credshunter.ps1`
- Verify only: `credshunter.bat`
- Verify only: `README.md`

**Interfaces:**
- Consumes: all completed implementation tasks.
- Produces: final validation evidence and an explicit CMD-runtime limitation statement.

- [ ] **Step 1: Run syntax and whitespace checks**

```bash
bash -n credshunter.sh
git diff --check HEAD~4..HEAD
git status --short
```

Parse `credshunter.ps1` inside the PowerShell container with `[System.Management.Automation.Language.Parser]::ParseFile()` and require zero parse errors.

- [ ] **Step 2: Run the Bash validation matrix**

Test: hit, benign variable, both skip aliases, no path, unique-name count, file-and-environment duplicate exposure, 16 KiB boundary, output log, cleanup, and exit codes 0/1/2. Use `env -i` so host credentials cannot leak into fixtures.

- [ ] **Step 3: Run the PowerShell validation matrix**

Repeat the same cases inside `mcr.microsoft.com/powershell:lts-alpine-3.20`, injecting only fixture variables with Docker `-e`. Verify no host environment secrets are forwarded unintentionally.

- [ ] **Step 4: Review Batch control flow and limitations**

Confirm strict CMD-only implementation, no value expansion through `call` or delayed expansion, unique cleanup routing, summary/exit integration, and matching option aliases. State clearly in the final report: `credshunter.bat` was statically reviewed but not executed because native `cmd.exe` was unavailable.

- [ ] **Step 5: Inspect the final patch and history**

```bash
git status --short --branch
git log --oneline --decorate -8
git diff origin/main...HEAD -- README.md credshunter.sh credshunter.ps1 credshunter.bat \
  docs/superpowers/specs/2026-08-17-stage7-process-environment-design.md \
  docs/superpowers/plans/2026-08-18-stage7-process-environment.md
```

Verify no unrelated paths changed and do not push without a separate explicit request.
