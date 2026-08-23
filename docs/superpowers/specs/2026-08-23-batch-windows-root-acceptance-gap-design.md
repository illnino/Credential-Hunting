# Batch Windows Root Acceptance Gap Design

## Problem

`credshunter.bat` now probes direct backup-hive paths such as:

- `System32\SAM`
- `System32\SYSTEM`
- `System32\SECURITY`

but its root-acceptance gate still rejects a discovered Windows root unless
this directory exists:

- `System32\config\`

That means a backup root like:

- `C:\Windows.old\Windows`

is dropped before probing when it contains:

- `C:\Windows.old\Windows\System32\SAM`

but not `C:\Windows.old\Windows\System32\config\`.

## Required Behaviour

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
- Change root acceptance so a discovered Windows root is kept when any valid
  Stage 1 structured artifact layout exists under it.
- Keep PowerShell and Bash unchanged in this patch.
- Do not broaden recursive search, labels, severity, or stage numbering.

## Design

### 1. Replace the single `System32\config\` gate

Today `:Stage1RecordWindowsRoot` does:

```bat
if not exist "%~1\System32\config\" goto :EOF
```

Replace that with a narrow multi-path acceptance test. A candidate Windows root
is accepted if at least one of these exists:

- `%~1\System32\config\`
- `%~1\System32\SAM`
- `%~1\System32\SYSTEM`
- `%~1\System32\SECURITY`
- `%~1\NTDS\ntds.dit`

This preserves the original canonical layout while also accepting the backup
layout that the user proved exists on the target.

### 2. Keep probing unchanged after acceptance

Once a root is accepted, keep the rest of the Batch logic unchanged:

- dedupe with `:Stage1AppendUnique`
- probe through `:Stage1ProbeWindowsRoot`
- keep the loose-backup pass unchanged
- keep readability gating unchanged

### 3. Keep the fix narrow

This patch does **not** redesign discovery. It only corrects the condition that
decides whether an already discovered Windows root should be probed.

## Validation

1. Confirm `credshunter.bat` no longer requires only `System32\config\` to
   accept a root.
2. Confirm the acceptance check now allows roots with:
   - `System32\SAM`
   - `System32\SYSTEM`
   - `System32\SECURITY`
   - `NTDS\ntds.dit`
3. Confirm `:Stage1ProbeWindowsRoot` itself is unchanged apart from using roots
   that now pass the widened gate.
4. Confirm no PowerShell or Bash changes were made.

## Scope

This is a narrow Batch-only follow-up fix for a verified missed backup-root
layout. It does not change the PowerShell implementation or the general backup
discovery strategy.
