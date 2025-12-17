# Driver Multi-Statement Tests

Tests for validating multi-statement (stacked query) support across different PostgreSQL drivers.

## Purpose

These tests verify the claims in the SQL Injection Knowledge Base documentation about which drivers support multi-statement queries and under what conditions.

## Running the Tests

### Prerequisites

Make sure the PostgreSQL containers are running:

```bash
cd docker
docker compose up -d postgres-16
```

### Run All Driver Tests

```bash
cd docker
docker compose --profile driver-tests up --build
```

### Run Individual Driver Tests

**PHP (pg_query / pg_query_params):**

```bash
docker compose run --rm test-php
```

**Python psycopg2:**

```bash
docker compose run --rm test-python-psycopg2
```

**Python psycopg3:**

```bash
docker compose run --rm test-python-psycopg3
```

## Test Coverage

### PHP (`pg_query` / `pg_query_params`)

| Function            | Multi-Statement Support | Notes                                                        |
| ------------------- | ----------------------- | ------------------------------------------------------------ |
| `pg_query()`        | Yes                     | Fully supports multiple statements                           |
| `pg_query_params()` | No                      | Limited to single statement (PostgreSQL protocol limitation) |

### Python (psycopg2)

psycopg2 uses **client-side parameter substitution** by default, which means parameters are interpolated into the query string before being sent to the server.

| Method                    | Multi-Statement Support | Notes                                            |
| ------------------------- | ----------------------- | ------------------------------------------------ |
| `execute()` (no params)   | Yes                     | Returns **last** result set                      |
| `execute()` (with params) | Yes                     | Client-side substitution allows multi-statements |

### Python (psycopg3)

psycopg3 uses **server-side parameter binding** by default (extended query protocol via `PQexecParams`), which is more secure but has protocol limitations.

| Method                       | Multi-Statement Support | Notes                                                            |
| ---------------------------- | ----------------------- | ---------------------------------------------------------------- |
| `execute()` (no params)      | Yes                     | Returns **first** result set (uses simple query protocol)        |
| `execute()` (with params)    | No                      | "cannot insert multiple commands into a prepared statement"      |
| `ClientCursor` (with params) | Yes                     | Uses client-side binding like psycopg2, returns **first** result |

**Key Difference:** psycopg2 returns the **last** result set, while psycopg3 returns the **first** result set.

## Expected Results

All tests should pass, confirming:

1. Non-parameterized queries support multi-statements in all drivers
2. Server-side parameterized queries (pg_query_params, psycopg3 execute with params) do NOT support multi-statements due to PostgreSQL extended query protocol limitation
3. Client-side parameterized queries (psycopg2, psycopg3 ClientCursor) DO support multi-statements because parameters are interpolated before sending to server
4. Stacked INSERT/UPDATE/DELETE operations work with non-parameterized queries

## Security Implications

| Driver/Method                      | Stacked Query Injection Risk                          |
| ---------------------------------- | ----------------------------------------------------- |
| PHP `pg_query()`                   | **High** - allows stacked queries                     |
| PHP `pg_query_params()`            | **Low** - protocol blocks stacked queries             |
| psycopg2 `execute()` (any)         | **High** - client-side binding allows stacked queries |
| psycopg3 `execute()` (no params)   | **High** - simple protocol allows stacked queries     |
| psycopg3 `execute()` (with params) | **Low** - extended protocol blocks stacked queries    |
| psycopg3 `ClientCursor`            | **High** - client-side binding like psycopg2          |
