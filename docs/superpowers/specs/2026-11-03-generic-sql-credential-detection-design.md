# Generic SQL Credential Detection Design

## Purpose

Improve `credshunter.sh` so SQL dumps and database script files yield reusable credential findings even when credentials are stored in SQL syntax rather than conventional `password=value` assignments.

The implementation must remain generic. It must not contain Openfire product names, Openfire table names, or paths that only work for one lab.

## Current Behavior

CredsHunter already:

- reports common SQL/database extensions with `[SQL]` during Stage 3;
- selects `.sql`, `.ddl`, `.dump`, `.psql`, `.pgsql`, `.plsql`, `.tsql`, `.cql`, `.sqlproj`, and `.script` text files for Stage 5;
- detects conventional assignments, connection strings, JDBC URLs, and supported standard hash formats.

It misses credentials represented as SQL structure, including:

- property tuples such as `VALUES('mail.smtp.password','secret')`;
- `CREATE USER ... IDENTIFIED BY 'secret'`;
- `CREATE USER ... PASSWORD DIGEST 'hash'`;
- `INSERT INTO users(username,password) VALUES(...)`;
- positional inserts whose column order is defined by a preceding `CREATE TABLE` statement.

The existing 5 MiB content limit remains in effect. Operators can raise it with `--max-size` or disable it with `--no-size-limit`.

## Scope

### Included

- Bash implementation in `credshunter.sh`.
- SQL-aware processing for text files already admitted to Stage 5.
- Bounded multi-line SQL statement assembly.
- Generic DDL password clauses.
- Generic property-key/value tuples.
- Column-aware `INSERT ... VALUES` parsing.
- Per-file `CREATE TABLE` column maps for positional inserts.
- Focused fixtures and regression tests against existing credential rules.

### Excluded

- A complete SQL grammar or database engine.
- Decryption or cracking of captured hashes.
- Parsing binary `.mdf`, `.ndf`, `.ldf`, SQLite, or proprietary database formats.
- Product-specific Openfire rules.
- Changes to `credshunter.ps1`, `credshunter.bat`, or HomeHunter in this change.

Cross-platform parity can follow after the Bash behavior is validated.

## Design

### 1. SQL Candidate Gate

Run the SQL-aware pass only for files that are likely SQL:

- known SQL text extensions; or
- `.script`/`.txt`/`.dump`-style candidates whose content contains bounded SQL signatures such as `CREATE TABLE`, `CREATE USER`, `ALTER USER`, `CREATE LOGIN`, `INSERT INTO`, `COPY`, or `SET DATABASE`.

The normal Stage 5 candidate selection, readability check, binary check, and file-size limit run first. The SQL pass does not broaden filesystem traversal and does not bypass safety limits.

### 2. Bounded Statement Assembly

Read SQL-like files line by line and assemble statements until an unquoted semicolon. Track single-quoted SQL strings, including doubled quote escapes (`''`), so semicolons and commas inside literals do not terminate or split a statement.

Safety limits:

- maximum assembled statement size: 64 KiB;
- maximum statement span: 200 input lines;
- over-limit statements are skipped without aborting the file;
- line numbers retain the first input line of the statement.

Single-line statements remain the fast path.

### 3. DDL Credential Clauses

Recognize case-insensitively:

- `CREATE` or `ALTER USER`;
- `CREATE` or `ALTER LOGIN`;
- `CREATE` or `ALTER ROLE`;
- `IDENTIFIED BY`;
- `PASSWORD`, `WITH PASSWORD`, and `PASSWORD DIGEST`;
- `SET PASSWORD [FOR ...]`.

Extract only the password/digest literal, pass it through the existing false-positive filter where appropriate, and report it as:

```text
[HIGH] content/sql_ddl_password ...
```

An explicitly declared password digest is reportable even if it is an otherwise ambiguous unprefixed hexadecimal value, because the SQL clause supplies the credential context.

### 4. Property Tuple Detection

Recognize adjacent SQL string literals where the first literal is a credential-bearing property name and the second is its value, for example:

```sql
VALUES('mail.smtp.password','secret',0,NULL)
VALUES('service.credentials','value')
VALUES('passwordKey','value')
```

Credential property names must contain a bounded credential token such as `password`, `passwd`, `passphrase`, `pwd`, `secret`, `credential`, `storedkey`, `serverkey`, or `passwordkey`. A generic property containing only `key` must not match.

Report the extracted property name and value as `content/sql_property_credential`. Apply the existing placeholder/reference filters to plaintext values.

### 5. INSERT Column Mapping

For statements with explicit columns:

```sql
INSERT INTO users(username,password,email)
VALUES('alice','secret','alice@example.test');
```

Tokenize the column list and value list with quote-aware comma splitting. Match credential-bearing column names to the value at the same ordinal position.

Credential columns include exact or suffix-normalized forms of:

- password, passwd, passphrase, pwd;
- password_hash, passwd_hash, pwhash, digest;
- encryptedpassword, plainpassword;
- storedkey, serverkey, passwordkey;
- secret and credential when used as a complete column token or suffix.

Do not report `salt` by itself. When a row contains both a credential value and a salt, the salt may be included as supporting context in the same finding.

### 6. Positional INSERT Mapping

Maintain a per-file map from bounded `CREATE TABLE` statements:

```sql
CREATE TABLE users(username ..., storedkey ..., serverkey ..., salt ...);
INSERT INTO users VALUES('alice','stored','server','salt');
```

Use the stored column order to interpret later positional inserts. Table and column identifiers are normalized case-insensitively and may be bare, quoted, bracketed, or schema-qualified.

If no trustworthy column map exists, do not guess positional meanings. Property tuple detection can still recognize key/value rows without knowing the schema.

### 7. Finding Output and Deduplication

Use the existing finding store and sensitive exit status. SQL findings are `[HIGH]` because they contain plaintext credentials, password digests, or authentication material.

Previews should contain the credential field/property and extracted value rather than an entire potentially large SQL statement. Existing sanitization and output-file protections remain unchanged.

Deduplicate by file, starting line, SQL label, field/property name, and extracted value.

### 8. Interaction with Existing Rules

The existing line-oriented credential pass runs unchanged. The SQL pass supplements it.

If both passes identify the same file, line, and value, the SQL pass must avoid emitting a duplicate. Existing non-SQL fixtures must continue to produce the same labels and counts.

## Error Handling

- Malformed SQL is skipped at statement or row level; it must not abort Stage 5.
- Unterminated strings or statements are discarded at EOF unless they form a safely parseable single statement.
- Mismatched column/value counts are ignored rather than guessed.
- Over-limit statements are recorded internally as skipped SQL statements without printing credential content.
- SQL parsing must not execute SQL, invoke a database client, or modify the target file.

## Validation

### Positive fixtures

- Direct `password =` assignment remains detected.
- SQL Server `CREATE LOGIN ... WITH PASSWORD =`.
- Oracle/MySQL-style `IDENTIFIED BY`.
- HSQLDB-style `PASSWORD DIGEST`.
- PostgreSQL-style role password.
- Property name/value tuple.
- Single-line explicit-column insert.
- Multi-line explicit-column insert.
- Positional insert after `CREATE TABLE`.
- Quoted values containing commas, semicolons, and doubled quotes.
- Credential hash with adjacent salt context.

### Negative fixtures

- Schema declarations containing `PASSWORD VARCHAR(...)` but no value.
- Placeholder values such as `changeme`, `example`, and variable references.
- Generic `key`, `monkey`, `password_policy`, and documentation text.
- Positional insert without a column map.
- Mismatched column/value counts.
- SQL comments containing example credentials.
- Oversized or unterminated statements.

### Regression checks

- Bash syntax check under Bash 4+ and Bash 5.
- Existing non-SQL credential fixture counts remain unchanged.
- Stage 3 continues to report SQL paths independently of Stage 5 findings.
- A synthetic Openfire-shaped HSQLDB fixture produces generic SQL labels without any product-specific rule.
- The supplied `openfire.script` produces SQL findings while test output redacts secret values.
- `git diff --check` passes.

## Success Criteria

The feature is complete when:

1. common SQL DDL and DML credential forms are detected;
2. schema-aware positional inserts work within one file;
3. the supplied HSQLDB script yields findings through generic rules;
4. malformed or unrelated SQL does not generate broad false positives;
5. current non-SQL behavior and safety limits remain intact.
