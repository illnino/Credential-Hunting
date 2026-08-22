# CMD Nested Path Expansion Fix Design

## Problem

`credshunter.bat` constructs paths by appending suffixes directly to modified
outer `FOR` variables inside nested blocks, for example:

```bat
call :AddChecked "gpp_xml" "%%~R\%%X.xml"
for /r "%%~D" %%F in (WinSCP.ini) do (...)
```

`CALL` performs another expansion pass, and nested `FOR` parsing can preserve an
outer modifier expression in a generated path. CMD then interprets fragments
such as `%~R\Groups.xml` or `%~D\WinSCP.ini` as invalid batch-parameter
substitution. These errors can disrupt later Stage 1 subroutine dispatch,
including the observed `Stage1_Cmdkey` label failure.

## Required Behaviour

- Stage 1 must construct GPP, history, vault, WinSCP, browser, SSH, remote
  manager, application-server, and other nested paths without `%~variable`
  substitution errors.
- The audit must cover every equivalent outer-`FOR` composite path, not only the
  examples seen in the captured output.
- Existing finding categories, matchers, scan roots, and stage order must remain
  unchanged.
- The implementation must remain strictly CMD-only, without PowerShell, .NET,
  or additional helper executables.
- Completed paths passed to existing finding and scanning subroutines must
  preserve the current argument interface.

## Design

### Materialize outer loop values

At the beginning of each affected outer `FOR` iteration, assign the modified
value by itself to a descriptive delayed-expansion variable:

```bat
for %%R in (...) do (
    set "gppRoot=%%~R"
    ...
)
```

Using `%%~R` alone allows the active `FOR` variable to expand before any suffix
is attached.

### Materialize composite paths

Build child paths through delayed expansion before testing, enumerating, or
passing them to `CALL`:

```bat
set "gppFile=!gppRoot!\%%X.xml"
if exist "!gppFile!" call :AddChecked "gpp_xml" "!gppFile!"
```

Nested recursive enumeration must use the materialized root:

```bat
for /r "!winscpRoot!" %%F in (WinSCP.ini) do (...)
```

An innermost variable such as `%%~F` may remain when it already represents a
complete path and has no appended suffix. The repair must not add extra percent
escaping as a substitute for path materialization.

### Audit boundary

Review every Stage 1 occurrence matching these shapes:

- `%%~<outer-variable>\<suffix>`
- nested `FOR`, `FOR /D`, or `FOR /R` roots containing a modified outer variable
- composite modified-`FOR` paths passed to `CALL`

Apply the materialization pattern to GPP, PowerShell history, credential vault,
WinSCP, browser profiles, cloud CLI, SSH, RDP and remote managers, Sticky Notes,
Jenkins, Tomcat, .NET user secrets, and any additional equivalent occurrence
found by the audit.

### Cmdkey label

Keep the existing `Stage1_Cmdkey` call and label initially because static
inspection confirms the target exists. Remove the preceding parser errors and
verify label dispatch again. Change the label only if native `cmd.exe`
validation reproduces the label failure independently after the expansion
repair.

## Validation

1. Statically enumerate all composite modified-`FOR` expressions and confirm no
   unsafe Stage 1 occurrence remains.
2. Parse all literal `CALL :label` targets and confirm each target label exists.
3. Check balanced parentheses and ensure no PowerShell or helper dependency was
   introduced.
4. Run `git diff --check` and review the diff for matcher, severity, Stage 6,
   and Stage 7 changes.
5. Run the Batch script under native `cmd.exe` through at least Stage 1.7 and
   confirm:
   - no path-operator substitution errors;
   - Stage 1.5 cmdkey executes;
   - GPP and WinSCP enumeration continue normally.

Native CMD validation must be reported as unverified if no Windows runtime is
available locally; user-provided target output can complete that validation.

## Scope

Only `credshunter.bat` and supporting design/plan documentation are changed.
The Bash and PowerShell scanners are unaffected.
