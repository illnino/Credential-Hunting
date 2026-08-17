# Stage 7 Process Environment Credential Discovery Design

**Date:** 2026-08-17
**Status:** Approved for specification
**Target version:** 2.5.0

## Objective

Add a seventh, independently selectable scan stage that checks the current
CredsHunter process environment for reusable credentials. The implementation
must behave consistently across Bash, PowerShell, and CMD while preserving the
project's read-only, network-silent design.

## Scope

Modify:

- `credshunter.sh`
- `credshunter.ps1`
- `credshunter.bat`
- `README.md`

Stage 7 inspects only environment variables inherited by the scanner process.
It does not inspect other processes, the Windows registry, persistent user or
machine environment stores, shell startup files, or `.env` files. Existing
filesystem stages continue to cover files.

The CMD implementation must remain strictly CMD-native. It must not invoke
PowerShell, .NET, or newly introduced helper executables.

## Considered approaches

### 1. Scan only credential-like variable names

This is fast and low-noise but misses credentials stored under application-
specific names. Rejected because it provides less coverage than the existing
file-content matcher.

### 2. Scan every `NAME=VALUE` assignment with the existing content matcher

This provides consistent classification and filtering across file and process
environment sources. Selected because it reuses the scanner's established
credential rules without creating a second detection policy.

### 3. Add a new environment-specific matcher set

This could be tuned independently but would duplicate detection rules and
create cross-platform drift. Rejected for the initial implementation.

## Command-line behavior

Stage 7 is enabled by default and runs independently of Stages 1-6.

Skip controls:

| Platform | Stage-specific option | Friendly alias |
|---|---|---|
| Bash | `--no-stage7` | `--no-env` |
| PowerShell | `-NoStage7` | `-NoEnv` |
| CMD | `-NoStage7` | `-NoEnv` |

An environment-only invocation is valid without `-p` or `-Path` while Stage 7
is enabled. If Stage 7 is disabled and no filesystem path or other runnable
stage input remains, the script retains its existing usage-error behavior.

Help text must explain that matched environment values are printed and, when
output logging is enabled, written to the log in plaintext.

## Snapshot and data flow

The inherited environment is captured near startup, before scanner-owned
environment variables can contaminate the results.

- Bash prefers `env -0` and parses NUL-delimited assignments so embedded
  newlines are preserved. It falls back to ordinary line-delimited `env` when
  NUL output is unavailable.
- PowerShell captures `Get-ChildItem Env:` into an in-memory collection of
  name/value records.
- CMD captures the output of `set` using CMD-native commands only.

Bash and CMD may store their snapshots in the scanner's access-restricted
temporary workspace. Snapshot files must be deleted by the existing cleanup
path on normal completion, errors, and handled interruptions. PowerShell keeps
its snapshot in memory. Snapshot data must never be transmitted.

Stage 7 constructs one logical `NAME=VALUE` assignment per environment
variable and sends it through the existing credential matcher,
classification, false-positive filtering, sanitization, deduplication, logging,
and sensitive-exit-status behavior. Existing private-key detection remains
applicable. Reusing the existing classifier also preserves its current
first-applicable-classification behavior.

An assignment larger than 16 KiB is not scanned or printed. The scanner emits
a warning naming the skipped environment variable without including its value.
Empty values may be processed normally; they produce no finding unless an
existing rule explicitly matches them.

## Findings and counting

Findings use `process_env` as the source and `ENV:<variable-name>` as the
location. Example:

```text
[HIGH] process_env/env_password -> ENV:DB_PASSWORD
       DB_PASSWORD=SuperSecret123
```

The complete matched `NAME=VALUE` assignment is displayed and logged without
redaction, as explicitly selected for this feature. Embedded newlines are
preserved using the platform's existing safe output handling.

The final summary adds:

```text
Environment credential findings ........ N
```

`N` counts unique environment variable names for which Stage 7 emitted at
least one credential finding. This count is informational and is a subset of
the existing severity totals; it must not be added to those totals again.

The same credential found in a file and an environment variable is reported
once for each source because those are distinct exposures. Existing
deduplication rules continue to suppress duplicate emissions for the same
source and location.

## Error and exit behavior

- Failure to capture the environment produces a warning and allows other
  enabled stages to continue.
- Oversized variables produce warnings but do not count as findings.
- Temporary snapshots are covered by cleanup on completion and handled
  interruption.
- Existing exit semantics remain unchanged: emitted `HIGH`, `KEY`, or other
  currently sensitive tiers cause the established sensitive-findings exit
  status; informational warnings alone do not.
- Skipping Stage 7 produces no environment finding count beyond a zero summary
  row if the existing summary format shows all categories.

## Documentation and versioning

Update all three script versions and the README badge from 2.4.0 to 2.5.0.
The README must describe Stage 6 Git repository discovery and Stage 7 process
environment discovery, document environment-only usage and skip flags, and
warn that matching environment values are exposed in console and log output.

## Validation

Behavioral validation must cover:

1. Detection of a representative password assignment.
2. No finding for a benign assignment.
3. Both Stage 7 skip aliases.
4. Environment-only invocation without a scan path.
5. Unique-variable counting and no double-counting in severity totals.
6. The 16 KiB limit and value-free warning.
7. Sensitive-findings exit status.
8. Snapshot cleanup.
9. No regressions in existing stage selection and filesystem scanning.
10. Version and README consistency.

Bash is behaviorally tested with Bash 5. PowerShell is behaviorally tested
with PowerShell 7 while retaining PowerShell 5.1-compatible syntax. Because a
native Windows CMD runtime is unavailable in the current macOS environment,
the Batch implementation receives static parsing/control-flow review here and
must be validated later with native `cmd.exe`; that limitation must be reported
explicitly.
