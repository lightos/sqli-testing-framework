# SQL Injection Knowledge Base Test Coverage

This document tracks which KB entries are covered by tests in this framework.

## PostgreSQL Coverage

| KB Entry                    | Test File                        | Status  | Notes                                                    |
| --------------------------- | -------------------------------- | ------- | -------------------------------------------------------- |
| `intro.md`                  | -                                | N/A     | Introductory content, no testable techniques             |
| `testing-injection.md`      | `testing-injection.test.ts`      | Covered | Boolean, error, UNION, comment-based detection           |
| `testing-version.md`        | `version-detection.test.ts`      | Covered | version(), current_setting, SHOW, parsing, injection     |
| `timing.md`                 | `timing.test.ts`                 | Covered | pg_sleep, conditional timing, heavy queries              |
| `stacked-queries.md`        | `stacked-queries.test.ts`        | Covered | Multi-statement, schema manipulation                     |
| `comment-out-query.md`      | `comment-out-query.test.ts`      | Covered | `--`, `/* */`, nested comments, injection patterns       |
| `string-concatenation.md`   | `string-concatenation.test.ts`   | Covered | `\|\|`, CONCAT, STRING_AGG, FORMAT, CHR(), SUBSTRING     |
| `conditional-statements.md` | `conditional-statements.test.ts` | Covered | CASE, COALESCE, NULLIF, GREATEST/LEAST, boolean          |
| `tables-and-columns.md`     | `tables-columns.test.ts`         | Covered | information_schema, pg_catalog, column enumeration       |
| `database-names.md`         | `database-names.test.ts`         | Covered | current_database(), pg_database, schemas                 |
| `database-credentials.md`   | `database-credentials.test.ts`   | Covered | pg_user, pg_roles, pg_shadow, current_user               |
| `server-hostname.md`        | `server-hostname.test.ts`        | Covered | inet_server_addr/port, inet_client_addr/port             |
| `privileges.md`             | `privileges.test.ts`             | Covered | Superuser, role attributes, has\_\*\_privilege()         |
| `default-databases.md`      | `default-databases.test.ts`      | Covered | postgres/template DBs, schemas, system tables            |
| `avoiding-quotations.md`    | `avoiding-quotations.test.ts`    | Covered | CHR(), dollar-quoting, hex encoding, ASCII               |
| `reading-files.md`          | `reading-files.test.ts`          | Covered | pg_read_file(), COPY FROM, lo_import, pg_ls_dir          |
| `writing-files.md`          | `writing-files.test.ts`          | Covered | COPY TO, lo_export, pg_file_write, web shells            |
| `command-execution.md`      | `command-execution.test.ts`      | Covered | COPY PROGRAM, privilege checks, extension enumeration    |
| `password-hashing.md`       | `password-hashing.test.ts`       | Covered | MD5/SCRAM formats, password_encryption, hash generation  |
| `password-cracking.md`      | -                                | N/A     | Reference content about external cracking tools          |
| `config-exploitation.md`    | `config-exploitation.test.ts`    | Covered | pg_settings, ALTER SYSTEM, configuration enumeration     |
| `privilege-escalation.md`   | `privilege-escalation.test.ts`   | Covered | Role membership, default privileges, security definer    |
| `fuzzing-obfuscation.md`    | `fuzzing-obfuscation.test.ts`    | Covered | Case variations, encoding, comment injection, whitespace |
| `out-of-band-channeling.md` | `out-of-band.test.ts`            | Covered | dblink, COPY TO PROGRAM, dns exfiltration detection      |

## Coverage Summary

- **Fully Covered**: 22 entries
- **Partially Covered**: 0 entries
- **Not Covered**: 0 entries
- **N/A (Reference only)**: 2 entries (intro - non-testable, password-cracking - requires external tools)

## Test Files Overview

| Test File                        | KB Entries Covered      | Test Count |
| -------------------------------- | ----------------------- | ---------- |
| `avoiding-quotations.test.ts`    | avoiding-quotations     | 19         |
| `command-execution.test.ts`      | command-execution       | 21         |
| `comment-out-query.test.ts`      | comment-out-query       | 19         |
| `conditional-statements.test.ts` | conditional-statements  | 20         |
| `config-exploitation.test.ts`    | config-exploitation     | 34         |
| `constants.test.ts`              | (general SQL constants) | 31         |
| `database-credentials.test.ts`   | database-credentials    | 17         |
| `database-names.test.ts`         | database-names          | 18         |
| `default-databases.test.ts`      | default-databases       | 26         |
| `fuzzing-obfuscation.test.ts`    | fuzzing-obfuscation     | 38         |
| `operators.test.ts`              | (general SQL operators) | 43         |
| `out-of-band.test.ts`            | out-of-band-channeling  | 16         |
| `password-hashing.test.ts`       | password-hashing        | 25         |
| `postgresql-specific.test.ts`    | (PostgreSQL-specific)   | 34         |
| `privilege-escalation.test.ts`   | privilege-escalation    | 36         |
| `privileges.test.ts`             | privileges              | 17         |
| `reading-files.test.ts`          | reading-files           | 18         |
| `server-hostname.test.ts`        | server-hostname         | 13         |
| `server-info.test.ts`            | (server information)    | 19         |
| `stacked-queries.test.ts`        | stacked-queries         | 12         |
| `string-concatenation.test.ts`   | string-concatenation    | 40         |
| `tables-columns.test.ts`         | tables-and-columns      | 22         |
| `testing-injection.test.ts`      | testing-injection       | 38         |
| `timing.test.ts`                 | timing                  | 9          |
| `version-detection.test.ts`      | testing-version         | 13         |
| `writing-files.test.ts`          | writing-files           | 17         |

Total: 26 test files, 615 tests

## JSDoc Annotations

All test files use JSDoc annotations to link tests to KB entries:

```typescript
/**
 * @kb-coverage postgresql/timing - Full coverage
 */
describe("PostgreSQL Timing Attacks", () => {
  /**
   * @kb-entry postgresql/timing
   * @kb-section pg_sleep() Timing Attack
   */
  test("pg_sleep() delays execution", async () => {
    // test implementation
  });
});
```

### Annotation Types

- `@kb-coverage` - File-level annotation indicating which KB entry the file covers
- `@kb-entry` - Test/describe-level annotation linking to specific KB entry
- `@kb-section` - Links to a specific section within the KB entry

## Permission-Aware Tests

Several test files handle PostgreSQL permission requirements gracefully:

- **reading-files.test.ts**: Tests for `pg_read_file()`, `COPY FROM`, `lo_import()` check for `pg_read_server_files` role
- **writing-files.test.ts**: Tests for `COPY TO`, `lo_export()`, `COPY TO PROGRAM` check for superuser/write permissions
- **database-credentials.test.ts**: Tests for `pg_shadow` handle permission denied errors
- **privileges.test.ts**: Tests enumerate available privileges without requiring superuser

## Running Tests

```bash
# Run all tests
npm test

# Run specific test file
npm test -- tests/postgresql/timing.test.ts

# Run with verbose output
npm test -- --reporter=verbose
```
