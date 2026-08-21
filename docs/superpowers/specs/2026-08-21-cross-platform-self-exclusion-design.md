# Cross-Platform Scanner Self-Exclusion Design

## Problem

When a scan root contains the running scanner, the scanner can inspect its own
source and report embedded credential patterns and private-key markers. A
full-root scan therefore produces false positives from `credshunter.sh`,
`credshunter.ps1`, or `credshunter.bat` itself.

The existing implementations are inconsistent:

- Bash compares path strings, which fails when `readlink -f --` is unsupported
  or the enumerated path uses a different spelling.
- PowerShell compares path strings during content scanning and excludes every
  file sharing the scanner basename during the filename stage.
- Batch has no comprehensive executing-script exclusion.

## Required Behaviour

Each implementation must exclude only the script that is currently executing.
A separate copy with the same basename must remain eligible for all applicable
findings. Self-exclusion must cover both metadata-only stages and content
scanning, including full-root scans.

The Batch implementation must remain strictly CMD-only, with no PowerShell,
.NET, or helper executable dependency.

## Design

### Bash

Add an `is_self_file` helper that uses Bash `test -ef` to compare filesystem
identity. This handles relative paths, absolute paths, symbolic-link aliases,
and hard links. Remove the GNU-specific `--` operand separator from the
best-effort `readlink -f` initialization.

Apply the helper before Stage 2, Stage 3, and Stage 4 record findings, while
building the Stage 5 candidate stream, and at the beginning of `scan_file` as a
defensive guard. Filtering the candidate stream ensures the displayed candidate
count does not include the scanner.

### PowerShell

Normalize `$PSCommandPath` with `[System.IO.Path]::GetFullPath()` and introduce
`Test-IsSelfPath`, using an ordinal case-insensitive comparison of normalized
paths.

Filter the executing script from `Get-WalkedFiles` before its descriptor enters
the shared Stage 2-5 inventory. Retain a defensive check in `Invoke-ScanFile` for
Stage 1 and direct calls. Replace the Stage 4 basename comparison so that other
copies named `credshunter.ps1` are not suppressed.

This intentionally avoids native file-ID interop. A distinct Windows hard-link
path is treated as a separate path and may be scanned.

### Batch

Capture `%~f0` as `SELF_PATH`. Normalize enumerated and directly supplied file
paths with `%%~f` expansion and omit an ordinal case-insensitive exact match
from `FILELIST`. Add the same normalized comparison at the start of `:ScanFile`
as a defensive guard.

Because Stages 2-5 share `FILELIST`, inventory filtering prevents metadata and
content findings while keeping candidate counts accurate. Pure CMD cannot
reliably identify junction aliases or hard links without an external helper;
that limitation is accepted and documented.

## Error Handling

Self-path normalization is best effort and must not terminate a scan. Bash and
PowerShell helpers return “not self” when the candidate cannot be resolved.
Batch falls back to its existing path handling if expansion does not identify a
matching absolute path.

## Validation

For every implementation:

1. Place the scanner inside the selected scan root.
2. Run a full-root scan (`/` or `C:\`).
3. Invoke it by relative and absolute paths.
4. Place another copy with the same basename inside the root and verify it
   remains eligible for findings.
5. Confirm the running source never appears as `CRITICAL`, `HIGH`, `KEY`,
   `INTEREST`, or `NAME` and is absent from Stage 5 candidate counts.
6. Exercise paths containing spaces.

Additionally, test Bash through symbolic-link and hard-link invocation. Validate
PowerShell syntax under the supported Windows PowerShell version and perform a
static CMD review; native `cmd.exe` runtime validation is required when a
Windows host is available.

## Scope

This change only addresses executing-script self-exclusion. It does not alter
credential matchers, general path exclusions, severity counts, or Git and
environment discovery.
