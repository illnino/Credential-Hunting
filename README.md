<div align="center">

<img src="assets/credshunter-icon.svg" alt="CredsHunter" width="148" />

# CredsHunter

**Find credentials that can actually be reused for lateral movement or privilege escalation.**

<br>

![read-only](https://img.shields.io/badge/read--only-yes-3fb950?style=flat-square)
![no network](https://img.shields.io/badge/network-none-3fb950?style=flat-square)
![version](https://img.shields.io/badge/version-2.5.0-2dd4bf?style=flat-square)
![bash](https://img.shields.io/badge/bash-4%2B-2b3137?style=flat-square&logo=gnubash&logoColor=white)
![PowerShell](https://img.shields.io/badge/PowerShell-5.1%2B-2b3137?style=flat-square&logo=powershell&logoColor=white)
![authorized use only](https://img.shields.io/badge/use-authorized%20only-f85149?style=flat-square)

</div>

---

## Overview

This repository provides two complementary **read-only credential discovery workflows** for authorized internal penetration testing and post-exploitation:

- **CredsHunter** performs a staged, low-noise scan of known credential locations, selected file types, filenames, content, Git repositories, and the scanner environment.
- **HomeHunter** searches user home/profile directories for easily missed clues. It enumerates every encountered file and applies CredsHunter-style credential rules to every readable file that can be treated as text, regardless of its name or extension.

It searches Linux and Windows hosts for credential material that is realistically useful during an engagement: plaintext passwords, database connection strings, private keys, credential containers, reusable hashes, shell-history credentials, GPP `cpassword` values, unattended-install credentials, and other high-value local artifacts.

The project deliberately **does not target cloud / SaaS access tokens** such as JWTs, AWS access keys, GitHub tokens, Slack tokens, or generic API keys. Those artifacts frequently create noise during internal assessments and are usually less useful for host-to-host lateral movement.


### Design goals

- **Reuse-focused** — prioritize credentials that can support privilege escalation or lateral movement.
- **Read-only** — never modify the target system.
- **Network-silent** — never transmit discovered data.
- **Low-noise** — tuned filters suppress common false positives.
- **Cross-platform** — matching Linux and Windows workflows.
- **Operator-friendly** — live findings, grouped severity tiers, plain-text logging, stage controls, and clean interruption handling.

---

## How it works

CredsHunter uses a seven-stage workflow covering known credential locations, recursive file inspection, Git repositories, and the scanner process environment.

| Stage | Focus | Examples |
|:--:|---|---|
| **1** | OS & application credential stores | Registry, GPP, histories, vaults, keys, saved sessions, known credential locations |
| **2** | Confirmed credential containers | `.kdbx`, `.ppk`, `.pfx`, `.p12`, `.keytab`, keystores and similar containers |
| **3** | High-value file types | Private keys, `.env`, backups, databases, captures, archives, configuration files |
| **4** | Suspicious filenames | `*password*`, `*secret*`, `*credential*`, `*login*`, `*account*` |
| **5** | Content scan | 70+ tuned credential regexes with false-positive filtering |
| **6** | Git repository discovery | `.git` directories and valid `.git` indirection files |
| **7** | Process environment | Inherited `NAME=VALUE` assignments matched by the existing credential rules |

Stages **1**, **5**, and **7** perform credential-content inspection. Stages **2–4** are intentionally fast filename and extension passes, while Stage **6** identifies repository roots without scanning Git internals.

Each finding is filtered before it reaches the final results, and findings are surfaced as the scan progresses rather than being hidden until the end.

---

## Quick start

### Linux

```bash
git clone https://github.com/NeCr00/Credential-Hunting.git
cd Credential-Hunting
chmod +x credshunter.sh

sudo ./credshunter.sh -p / -o loot.txt
```

### Windows

```powershell
git clone https://github.com/NeCr00/Credential-Hunting.git
cd Credential-Hunting

.\credshunter.ps1 -Path C:\ -OutputFile loot.txt
```

> Elevated execution is recommended when you want access to protected credential locations such as SAM / SYSTEM hives, vault directories, or other privileged stores.

---

## HomeHunter

HomeHunter is the focused companion scanner for user home/profile directories. It is intended for cases where a clue may be stored under an unexpected or hidden name such as `.~`, rather than a recognized Stage 5 extension.

No arguments are required. By default, each implementation discovers all user homes/profiles it can identify, scans those it can read, and continues past inaccessible locations while reporting `[DENIED]` entries.

### Linux

```bash
chmod +x homehunter.sh
./homehunter.sh

# Recommended when you are authorized to inspect every user's home
sudo ./homehunter.sh

# Optional: raise the text-scan limit and save a log
sudo ./homehunter.sh --max-size 20 --output home-loot.txt
```

### Windows PowerShell

```powershell
.\homehunter.ps1

# Optional: raise the text-scan limit and save a log
.\homehunter.ps1 -MaxFileSizeMB 20 -OutputFile home-loot.txt
```

### Windows CMD

```bat
homehunter.cmd
homehunter.cmd -MaxFileSizeMB 20 -OutputFile home-loot.txt
```

Use an elevated shell for the widest coverage. Without elevation, HomeHunter does not abort when another user's profile is inaccessible; it records the denied path and continues.

| Goal | Linux | PowerShell / CMD |
|---|---|---|
| Add an explicit home | `--home PATH` | `-Home PATH` |
| Scan only explicitly supplied homes | `--only-specified-homes` | `-OnlySpecifiedHomes` |
| Change text-scan size cap | `--max-size N` | `-MaxFileSizeMB N` |
| Write findings to a file | `--output FILE` | `-OutputFile FILE` |
| Reduce progress output | `--quiet` | `-Quiet` |
| Disable ANSI colors | `--no-color` | `-NoColor` |

The default text-scan limit is **5 MiB**. Larger files are still inventoried as `[SKIP:size>5MB]`; binary files are reported as `[SKIP:binary]`. Symlinks and Windows reparse points are not followed.

> **Plaintext warning:** HomeHunter output can contain matched passwords, keys, connection strings, and other secrets. Treat console captures and output logs as credential material.

---

## Usage

### Linux

Full host sweep with findings written to a file:

```bash
sudo ./credshunter.sh -p / -o loot.txt
```

Scan selected locations only:

```bash
./credshunter.sh -p /home -p /var/www -p /opt
```

Targeted scan without the slower recursive content stage:

```bash
./credshunter.sh -p /var/www -p /home --no-stage5
```

Exclude a directory tree:

```bash
./credshunter.sh -p / -x /var/lib/customer-app
```

Scan only the inherited process environment:

```bash
./credshunter.sh --no-stage1 --no-stage2 --no-stage3 --no-stage4 --no-stage5 --no-stage6
```

### Windows

Full `C:\` sweep:

```powershell
.\credshunter.ps1 -Path C:\ -OutputFile loot.txt
```

Scan multiple locations:

```powershell
.\credshunter.ps1 -Path C:\Users,C:\inetpub
```

Web / database host with SQL and CSV-style data scanning enabled:

```powershell
.\credshunter.ps1 -Path D:\ -IncludeData
```

Disable built-in system / vendor exclusions:

```powershell
.\credshunter.ps1 -Path C:\ -NoDefaultExclude
```

Scan only the inherited process environment:

```powershell
.\credshunter.ps1 -NoStage1 -NoStage2 -NoStage3 -NoStage4 -NoStage5 -NoStage6
```

The CMD-only port supports the same pathless Stage 7 workflow:

```bat
credshunter.bat -NoStage1 -NoStage2 -NoStage3 -NoStage4 -NoStage5 -NoStage6
```

> **Plaintext warning:** Stage 7 displays the complete matched `NAME=VALUE` assignment. If output logging is enabled, it writes that assignment to the log as well. Protect console captures and log files as credential material. Assignments larger than 16 KiB are skipped with a name-only warning.

CredsHunter is pipe-friendly. Use `--no-color` on Linux or `-NoColor` on Windows when redirecting or filtering output.

---

## Finding tiers

Results are grouped by usefulness and confidence, with the most important findings shown first.

| Tag | Meaning |
|---|---|
| `[CRITICAL]` | Confirmed credential container |
| `[HIGH]` | Reusable password, hash, GPP `cpassword`, or equivalent credential material |
| `[KEY]` | Private key or other key material, including readable SAM / SYSTEM hive findings |
| `[INTEREST]` | High-value file or location worth manual review |
| `[NAME]` | Suspicious filename — useful as a review hint |

A sensitive result in **CRITICAL**, **HIGH**, or **KEY** causes a non-zero sensitive-findings exit status. `INTEREST` and `NAME` findings alone do not.

HomeHunter also uses these inventory and classification tags:

| Tag | Meaning |
|---|---|
| `[HIDDEN]` | Hidden item, including a Unix basename beginning with `.` or a Windows Hidden/System item |
| `[OFFICE]` | Microsoft Office file worth manual review |
| `[SQL]` | SQL script, dump, or database-related file |
| `[ARCHIVE]` | Archive or compressed file worth manual review |
| `[SKIP:size>NMB]` | File was inventoried but its content exceeded the configured text-scan limit |
| `[SKIP:binary]` | File was inventoried but not content-scanned because it appeared binary |
| `[DENIED]` | A path could not be read with the current user's permissions |

`[HIGH]` and `[KEY]` retain their credential meanings in HomeHunter. Classification tags such as `[HIDDEN]`, `[OFFICE]`, and `[SQL]` identify files for review and do not by themselves claim that a credential was found.

For example:

```bash
./credshunter.sh -p /etc && echo "No high-confidence credential findings"
```

---

## Scan controls

| Goal | Linux | Windows |
|---|---|---|
| Add scan paths | `-p PATH` / `--path PATH` | `-Path PATH` |
| Exclude paths | `-x PATH` / `--exclude PATH` | `-ExcludePath PATH` |
| Scan every readable text file in Stage 5 | `-a` / `--all` | `-All` |
| Change file-size cap | `-m N` / `--max-size N` | `-MaxFileSizeMB N` |
| Disable size cap | `--no-size-limit` | `-NoSizeLimit` |
| Write findings to file | `-o FILE` / `--output FILE` | `-OutputFile FILE` |
| Skip OS-level checks | `-s` / `--skip-system` / `--no-stage1` | `-SkipSystem` / `-NoStage1` |
| Skip a stage | `--no-stage2` ... `--no-stage7` | `-NoStage2` ... `-NoStage7` |
| Skip Git discovery | `--no-stage6` / `--no-git` | `-NoStage6` / `-NoGit` |
| Skip process environment discovery | `--no-stage7` / `--no-env` | `-NoStage7` / `-NoEnv` |
| Reduce status output | `-q` / `--quiet` | `-Quiet` |
| Disable ANSI colors | `--no-color` | `-NoColor` |
| Include SQL / CSV-style data files | — | `-IncludeData` |
| Disable default vendor/system exclusions | — | `-NoDefaultExclude` |

The default maximum file size is **5 MB**. Increase it when credentials may live in larger logs, dumps, or configuration exports, or disable the cap when appropriate.

The summary row `Environment credential findings` counts unique matched environment variable names. It is a subset of the existing `HIGH`/`KEY` totals and is not added to them again.

---

## Customization

The pattern libraries and file-type lists are intentionally kept in clearly labeled configuration arrays inside each script.

You can extend or trim:

- Stage 2 credential-container extensions
- Stage 3 high-value file types and exact filenames
- Stage 4 suspicious filename tokens
- Stage 5 content-scan extensions
- Credential detection patterns
- False-positive filters

Edit the relevant list in one place; the scanning workflow does not need to be rewritten.

---

## Requirements

| Platform | Requirements |
|---|---|
| **Linux** | Bash 4+, `find`, `grep`, `awk`, `sed`, `stat`, `od` |
| **Linux — optional** | `realpath`, `file`, `iconv` (UTF-16 decoding) |
| **Windows** | PowerShell 5.1+ |
| **Windows CMD** | Native `cmd.exe` tools including `dir`, `findstr`, `reg`, and `icacls` |
| **Privileges** | Elevated execution is optional, but increases visibility into protected credential locations |

The Linux implementation is designed for common distributions including Debian/Ubuntu, RHEL-family systems, Arch, and Alpine.

---

## FAQ

<details>
<summary><strong>Does CredsHunter change anything on the host?</strong></summary>
<br>

No. The scanner is read-only. It writes only to the output file you explicitly choose, does not transmit findings over the network, and cleans up its temporary working data on exit.

</details>

<details>
<summary><strong>Why did CredsHunter miss a hidden or extensionless home-directory file?</strong></summary>
<br>

CredsHunter Stage 5 uses a targeted file-type allow-list by default to reduce noise and scan time. Use `--all` on Linux or `-All` on Windows for a broader CredsHunter content scan, or run HomeHunter when the objective is to inspect user homes comprehensively. HomeHunter reports hidden items such as `.~` and scans every readable file that can be treated as text, regardless of its name or extension.

</details>

<details>
<summary><strong>Why are AWS, GitHub, Slack, JWT, and generic API tokens ignored?</strong></summary>
<br>

By design. CredsHunter is optimized for credentials that are useful for local privilege escalation and in-network lateral movement. Cloud and SaaS tokens are a major source of false-positive noise during this type of assessment.

Local cloud-CLI credential **files and locations may still be surfaced for review**; the tool simply avoids treating generic cloud/SaaS token patterns as primary reusable-credential findings.

</details>

<details>
<summary><strong>Stage 5 is slow. How can I speed it up?</strong></summary>
<br>

Narrow the scope with `-p` / `-Path`, exclude noisy trees, keep the default file-size limit, or skip the recursive content scan with `--no-stage5` / `-NoStage5`.

</details>

<details>
<summary><strong>A credential was missed. What should I check?</strong></summary>
<br>

Confirm that the target file:

1. Is inside the selected scan path.
2. Is not inside an excluded path.
3. Is below the configured size limit.
4. Uses an extension included in Stage 5.

For a broader check, use `-a` / `--all` on Linux or `-All` on Windows.

</details>

---

## Wiki

For deeper project documentation, usage notes, and additional information, visit the **[Credential-Hunting Wiki](https://github.com/NeCr00/Credential-Hunting/wiki)**.

---

## Contributing

Contributions are welcome.

If you have a useful credential pattern, a false-positive reduction, a platform-specific credential location, or an improvement to scan performance and output quality, feel free to open an issue or pull request.

---

## Responsible use

CredsHunter is intended for **authorized security testing, internal penetration testing, red-team engagements, labs, and CTF environments**.

Only run it on systems you own or have explicit permission to assess.

<div align="center">
  <sub>Read-only. Network-silent. Built for signal over noise.</sub>
</div>
