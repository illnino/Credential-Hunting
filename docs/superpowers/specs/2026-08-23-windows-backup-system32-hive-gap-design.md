# Windows Backup System32 Hive Gap Design

## Problem

The new Windows backup-hive coverage still assumes discovered Windows roots
primarily store `SAM`, `SYSTEM`, and `SECURITY` under the canonical:

- `System32\config\...`

The user's real test case shows a backup copy at:

- `C:\Windows.old\Windows\System32\SAM`

That path is under a valid discovered Windows backup root, but it is not under
`System32\config\`, so the structured probe misses it. The loose-backup pass is
not sufficient to rely on for this exact layout.

## Required Behaviour

- Update only the Windows scanners:
  - `/Users/illnino/Project/oscp/Credential-Hunting/credshunter.ps1`
  - `/Users/illnino/Project/oscp/Credential-Hunting/credshunter.bat`
- Keep the current direct live-root probes and backup-root discovery.
- Add explicit structured probes for backup-copy hive layouts under discovered
  Windows roots:
  - `System32\SAM`
  - `System32\SYSTEM`
  - `System32\SECURITY`
- Keep the existing `System32\config\...`, `repair\...`, `RegBack\...`, and
  `NTDS\ntds.dit` checks.
- Keep Bash unchanged.
- Do not broaden the recursive loose-backup search in this patch.
- Do not change labels, severities, or stage numbering in this patch.

## Design

### 1. Extend structured Windows-root suffixes only

For each discovered Windows root, extend the structured hive suffix list from:

- `System32\config\SAM`
- `System32\config\SYSTEM`
- `System32\config\SECURITY`

to also include:

- `System32\SAM`
- `System32\SYSTEM`
- `System32\SECURITY`

This directly covers:

- `C:\Windows.old\Windows\System32\SAM`
- `C:\Windows.old\Windows\System32\SYSTEM`
- `C:\backup\Windows\System32\SECURITY`

without introducing a broader filename hunt.

### 2. Leave recursive logic unchanged

Do not widen the loose-backup pass in this patch. The recursive search stays as
implemented; this fix is specifically about making discovered Windows-root
probing tolerant of backup layouts that place the hive files directly under
`System32`.

### 3. Preserve existing reporting behavior

If any newly added `System32\SAM|SYSTEM|SECURITY` path exists:

- report it with the existing `sam_hive` checked label
- emit `readable_hive` and `readable_sam_hive` only after the existing real
  readability/open check passes

No new labels are introduced.

## Validation

1. Confirm both Windows scanners still probe:
   - `System32\config\...`
   - `repair\...`
   - `RegBack\...`
   - `NTDS\ntds.dit`
2. Confirm both Windows scanners now also probe:
   - `System32\SAM`
   - `System32\SYSTEM`
   - `System32\SECURITY`
3. Confirm no Bash changes were made.
4. Confirm no new recursive broadening was introduced in this patch.

## Scope

This is a narrow follow-up fix for a verified missed path shape under discovered
Windows backup roots. It does not redesign backup discovery, recursive search
rules, or finding semantics.
