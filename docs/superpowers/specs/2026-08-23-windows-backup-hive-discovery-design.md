# Windows Backup Hive Discovery Design

## Problem

The Windows scanners currently probe only the active Windows root through
`%SystemRoot%` / `$env:SystemRoot`, plus `repair` and `RegBack` below that
root. As a result, they miss credential-bearing artifacts copied into backup or
migration folders such as:

- `C:\Windows.old\Windows\System32\config\SAM`
- `C:\Windows.old\Windows\System32\config\SYSTEM`
- `D:\backup\SAM`

The user wants broader coverage for `SAM`, `SYSTEM`, and `ntds`-family
artifacts, but only with tight controls that avoid turning Stage 1 into a noisy
whole-disk filename hunt.

## Required Behaviour

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
- Respect existing default exclusions for the new recursive pass, except for
  explicit Windows-root probes that are intentionally targeted.
- Report `readable_*` findings only after a real readability/open check.
- Keep Bash unchanged.

## Design

### 1. Expand Stage 1 scope explicitly

Rename the Windows stage text from “SAM/SYSTEM/SECURITY hive files” to wording
that explicitly mentions NTDS, for example:

- PowerShell: `Stage 1.10 - SAM/SYSTEM/SECURITY/NTDS backup files`
- Batch: `Stage 1.10 - SAM/SYSTEM/SECURITY/NTDS backup files`

This keeps the new behavior visible in operator output.

### 2. Keep the current direct probes

Preserve the current checks under the active Windows root:

- `System32\config\SAM`
- `System32\config\SYSTEM`
- `System32\config\SECURITY`
- `repair\...`
- `System32\config\RegBack\...`

These remain the fastest and most important probes.

### 3. Add Windows-root discovery across fixed local drives

Discover likely Windows roots on fixed local disks and probe the standard hive
paths under each discovered root.

The discovery logic should include:

- the current live Windows root
- roots named like `X:\Windows`
- migrated roots like `X:\Windows.old\Windows`
- copied roots where the path still ends in `\Windows` and an ancestor
  directory contains a backup-like token such as:
  - `backup`
  - `bak`
  - `old`
  - `image`
  - `snapshot`
  - `copy`
  - `export`
  - `dump`

Candidate Windows roots must be deduplicated before probing.

For each discovered Windows root, probe:

- `System32\config\SAM`
- `System32\config\SYSTEM`
- `System32\config\SECURITY`
- `repair\SAM`
- `repair\SYSTEM`
- `repair\SECURITY`
- `System32\config\RegBack\SAM`
- `System32\config\RegBack\SYSTEM`
- `System32\config\RegBack\SECURITY`

For NTDS, probe only tighter AD-style locations, such as `NTDS\ntds.dit`,
anchored beneath the discovered Windows/backup context rather than through a
generic wide search.

### 4. Add a tight loose-backup pass

Add a bounded recursive search from each fixed local drive root, but only keep
exact filename matches for:

- `SAM`
- `SYSTEM`
- `SECURITY`
- `ntds.dit`

This recursive pass must be gated by path rules:

- for `SAM`, `SYSTEM`, and `SECURITY`, the parent path must contain at least one
  backup-like token:
  - `backup`
  - `bak`
  - `old`
  - `image`
  - `snapshot`
  - `copy`
  - `export`
  - `dump`
- for `ntds.dit`, require the same backup-like token plus at least one AD-style
  token somewhere in the path:
  - `ntds`
  - `active directory`
  - `windows`

This allows:

- `C:\backup\SAM`
- `D:\old\SYSTEM`
- `E:\image\SECURITY`
- `F:\backup\ntds\ntds.dit`

and rejects looser paths such as:

- `C:\temp\SAM`
- `D:\random\system`
- `E:\misc\ntds.dit`

### 5. Respect exclusions in the recursive pass

The new recursive search should reuse the scanner’s existing default exclusion
logic so it does not crawl noisy trees unnecessarily. Only the direct Windows
root probes may intentionally bypass that broader exclusion logic, because they
are targeted point checks rather than free-form recursion.

### 6. Use readability-first reporting

Existence alone may still count as a checked artifact, but operator-facing
readable findings must require a real open/read test.

For `SAM`, `SYSTEM`, and `SECURITY`:

- checked label remains `sam_hive`
- readable interest remains `readable_hive`
- readable KEY finding remains `readable_sam_hive`

For `ntds.dit`, add distinct labels:

- checked label: `ntds_file`
- readable interest: `readable_ntds`
- readable KEY finding: `readable_ntds_dit`

Batch must be hardened so it no longer treats simple existence as proof of
readability; it should attempt a real read/open operation before emitting the
readable interest and KEY finding.

## Validation

1. Confirm the new stage text explicitly mentions NTDS in both Windows scanners.
2. Confirm the current live-root probes still exist unchanged.
3. Confirm fixed-drive enumeration is used, not removable or network drives.
4. Confirm the recursive backup pass is exact-filename-only for:
   - `SAM`
   - `SYSTEM`
   - `SECURITY`
   - `ntds.dit`
5. Confirm backup-like path gating exists for the hive files and stricter
   backup-plus-AD-style gating exists for `ntds.dit`.
6. Confirm the recursive pass still honors the existing exclusion logic.
7. Confirm Batch now performs a real readability check before emitting
   `readable_hive` / `readable_sam_hive`.
8. Review the diff to ensure Bash was not modified.

## Scope

This change is limited to Windows Stage 1 artifact discovery and reporting in
the PowerShell and Batch scanners. It does not change Bash behavior, generic
Stage 5 content scanning, or severity policy outside the new NTDS-specific
labels.
