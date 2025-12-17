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

**PHP:**

```bash
docker compose run --rm test-php
```

**Python:**

```bash
docker compose run --rm test-python
```

## Test Coverage

### PHP (`pg_query` / `pg_query_params`)

| Function            | Multi-Statement Support | Notes                                                        |
| ------------------- | ----------------------- | ------------------------------------------------------------ |
| `pg_query()`        | Yes                     | Fully supports multiple statements                           |
| `pg_query_params()` | No                      | Limited to single statement (PostgreSQL protocol limitation) |

### Python (psycopg2)

| Method                    | Multi-Statement Support | Notes                                                       |
| ------------------------- | ----------------------- | ----------------------------------------------------------- |
| `execute()` (no params)   | Yes                     | Returns last result set                                     |
| `execute()` (with params) | No                      | "cannot insert multiple commands into a prepared statement" |

## Expected Results

All tests should pass, confirming:

1. Non-parameterized queries support multi-statements
2. Parameterized queries do NOT support multi-statements (PostgreSQL protocol limitation)
3. Stacked INSERT/UPDATE/DELETE operations work with non-parameterized queries
