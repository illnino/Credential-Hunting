# PowerShell and Batch SQL Credential Detection Design

## Purpose

Extend the approved generic SQL credential detection to `credshunter.ps1` and
`credshunter.bat` without adding product-specific Openfire rules.

## Scope

### Included

- Full SQL-aware parsing in PowerShell for files already admitted to Stage 5.
- Native CMD best-effort SQL detection in Batch.
- The existing SQL candidate extensions and SQL signatures.
- Generic DDL, property tuple, and `INSERT ... VALUES` credential detection.
- Focused fixtures and platform-appropriate regression tests.
- README documentation describing the different capability levels.

### Excluded

- Executing SQL or invoking a database client.
- Product-specific table, property, or path rules.
- Adding a PowerShell dependency to the Batch implementation.
- Parsing binary database formats.
- Broadening the current Stage 5 discovery policy or changing `-IncludeData`.

## PowerShell Design

`credshunter.ps1` receives the same bounded parser model as the Bash
implementation:

- identify known SQL text extensions, or SQL signatures in generic text-like
  files such as `.script`, `.txt`, `.bak`, `.old`, and `.log`;
- assemble statements while tracking single-quoted literals and doubled quote
  escapes;
- stop a statement at an unquoted semicolon or at the next SQL verb for dumps
  that use one statement per line;
- limit each statement to 64 KiB or 200 lines;
- retain per-file `CREATE TABLE` column order for later positional inserts;
- recognize generic credential column/property names such as `password`,
  `passwd`, `pwd`, `secret`, `credential`, `digest`, `storedkey`, `serverkey`,
  and their bounded suffix forms;
- detect `CREATE`/`ALTER USER|LOGIN|ROLE`, `IDENTIFIED BY`, `PASSWORD DIGEST`,
  `WITH PASSWORD`, and `SET PASSWORD` clauses;
- detect adjacent credential property/value literals and explicit-column or
  schema-mapped positional inserts.

Extracted values pass through the existing false-positive policy. Findings use
the existing high-severity store with `sql_ddl_password`,
`sql_property_credential`, or `sql_insert_credential` labels. SQL parsing is a
supplement to the existing line rules; it does not replace them.

## Batch Design

`credshunter.bat` remains native CMD and does not invoke `powershell.exe`.
Because `findstr` cannot safely implement quote-aware multi-line SQL parsing,
Batch provides explicitly best-effort, line-oriented detection:

- gate on known SQL extensions or an SQL verb signature in generic text-like
  files;
- report DDL lines containing generic password clauses;
- report same-line credential property/value tuples;
- report same-line explicit-column `INSERT ... VALUES` statements containing a
  credential column;
- use SQL-specific finding labels and a fixed preview that does not echo the
  credential-bearing line.

Batch does not infer positional values from `CREATE TABLE`, join multi-line
statements, or extract a literal. Those limitations preserve CMD-only
operation and avoid delayed-expansion corruption of values containing `!`, `%`,
or quotes.

## Discovery and Safety

Both implementations run SQL logic only after the existing path, readability,
binary, and size checks. Existing `-IncludeData` behavior remains unchanged:
large/data-oriented SQL extensions are scanned only when they are otherwise
selected, while a selected `.script` file can be recognized by content.

Malformed or unsupported statements are ignored rather than guessed. Neither
implementation writes to the scanned file or executes its contents.

## Output and Deduplication

SQL content findings remain `[HIGH]` findings because they represent reusable
credentials or authentication material; `[SQL]` continues to identify SQL or
database files during path discovery. SQL-specific labels make the source of a
finding explicit on every platform.

PowerShell deduplicates by path, start line, SQL label, field, and value before
using the normal finding store. Batch deduplicates through its existing
`AddHigh` key and emits at most one finding per SQL label and line.

## Validation

PowerShell uses the shared SQL fixture to verify:

- DDL password forms;
- property tuples;
- explicit and positional inserts;
- multi-line statements and escaped quotes;
- placeholder, comment, unknown-schema, and non-credential negatives;
- unchanged non-SQL behavior.

Batch validation uses a line-oriented fixture subset to verify supported DDL,
property, and explicit-insert positives plus obvious negatives. Native Windows
execution is required for final Batch validation; static inspection on another
OS is not treated as proof of CMD behavior.

## Documentation

The README will describe full SQL-aware extraction for Bash and PowerShell and
native best-effort extraction for Batch, including the unchanged size and
`-IncludeData` controls.
