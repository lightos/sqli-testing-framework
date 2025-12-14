# SQL Injection Testing Framework

A comprehensive framework for validating and discovering SQL injection techniques across multiple database platforms.

## Overview

This framework provides:

- **Direct SQL Testing** - Execute SQL directly against databases to validate syntax and behavior
- **HTTP Testing** - Test injection payloads via a vulnerable web application
- **Multi-Version Support** - Test against multiple database versions simultaneously
- **Timing Analysis** - Automated timing-based blind injection testing

Currently supports PostgreSQL, with MySQL, MSSQL, and Oracle planned.

## Prerequisites

- Node.js 18+
- Docker and Docker Compose
- npm or pnpm

## Installation

```bash
# Clone the repository
git clone <repository-url>
cd sqli-testing-framework

# Install dependencies
npm install

# Copy environment template
cp .env.example .env
```

## Quick Start

```bash
# Start PostgreSQL containers
npm run docker:up

# Wait for databases to be ready (about 10 seconds)
sleep 10

# Run all tests
npm test

# Stop containers when done
npm run docker:down
```

## Project Structure

```
sqli-testing-framework/
├── docker/
│   ├── docker-compose.yml      # Database containers
│   └── postgresql/
│       └── init.sql            # Schema and test data
├── src/
│   ├── app/
│   │   └── server.ts           # Vulnerable Express app
│   ├── db/
│   │   ├── connection.ts       # Connection manager
│   │   └── postgresql.ts       # PostgreSQL adapter
│   ├── runner/
│   │   ├── direct.ts           # Direct SQL execution
│   │   └── http.ts             # HTTP-based testing
│   └── utils/
│       ├── logger.ts           # Structured logging
│       └── timing.ts           # Timing utilities
├── tests/
│   └── postgresql/
│       ├── timing.test.ts              # Time-based injection
│       ├── stacked-queries.test.ts     # Multi-statement injection
│       └── testing-injection.test.ts   # Detection techniques
└── package.json
```

## Available Scripts

| Script                | Description               |
| --------------------- | ------------------------- |
| `npm run docker:up`   | Start database containers |
| `npm run docker:down` | Stop database containers  |
| `npm run docker:logs` | View container logs       |
| `npm test`            | Run all tests             |
| `npm run test:watch`  | Run tests in watch mode   |
| `npm run app:start`   | Start the vulnerable app  |
| `npm run lint`        | Check code style          |
| `npm run lint:fix`    | Fix code style issues     |
| `npm run typecheck`   | TypeScript type checking  |

## Database Versions

The Docker setup includes multiple PostgreSQL versions for compatibility testing:

| Container | Port | Version       |
| --------- | ---- | ------------- |
| sqli-pg12 | 5432 | PostgreSQL 12 |
| sqli-pg16 | 5433 | PostgreSQL 16 |

Set `PG_PORT` environment variable to switch between versions:

```bash
# Test against PostgreSQL 12
PG_PORT=5432 npm test

# Test against PostgreSQL 16 (default)
PG_PORT=5433 npm test
```

## Test Categories

### Timing Tests (`timing.test.ts`)

Validates time-based blind SQL injection techniques:

- `pg_sleep()` basic functionality
- Conditional timing with `CASE WHEN`
- Data extraction via timing differences
- Heavy query timing (without `pg_sleep`)

### Stacked Queries (`stacked-queries.test.ts`)

Tests multi-statement SQL injection:

- Basic stacked query execution
- Schema manipulation (CREATE, ALTER, DROP)
- Privilege escalation patterns
- Information gathering

### Detection Tests (`testing-injection.test.ts`)

Validates injection detection techniques:

- Boolean-based detection
- Error-based detection
- UNION-based detection
- Comment techniques
- PostgreSQL-specific features

## Vulnerable Application

The framework includes a minimal Express app with intentional vulnerabilities:

```bash
# Start the vulnerable app
npm run app:start
```

### Endpoints

| Endpoint           | Method | Vulnerability                 |
| ------------------ | ------ | ----------------------------- |
| `/users?id=X`      | GET    | SQL injection in WHERE clause |
| `/search`          | POST   | SQL injection in LIKE clause  |
| `/products?sort=X` | GET    | SQL injection in ORDER BY     |
| `/login`           | POST   | Authentication bypass         |

### Example Payloads

```bash
# Boolean-based
curl "http://localhost:3000/users?id=1' OR '1'='1"

# Time-based
curl "http://localhost:3000/users?id=1' AND pg_sleep(5)--"

# Authentication bypass
curl -X POST http://localhost:3000/login \
  -H "Content-Type: application/json" \
  -d '{"username":"admin'\''--","password":"x"}'
```

## Configuration

Environment variables (see `.env.example`):

| Variable      | Default   | Description         |
| ------------- | --------- | ------------------- |
| `PG_HOST`     | localhost | Database host       |
| `PG_PORT`     | 5433      | Database port       |
| `PG_USER`     | postgres  | Database user       |
| `PG_PASSWORD` | testpass  | Database password   |
| `PG_DATABASE` | vulndb    | Database name       |
| `APP_PORT`    | 3000      | Vulnerable app port |

## Writing Tests

Tests use [Vitest](https://vitest.dev/) and the framework's test runners:

```typescript
import { describe, test, expect, beforeAll, afterAll } from "vitest";
import { initDirectRunner, cleanupDirectRunner, directSQL } from "../../src/runner/direct.js";

describe("My SQL Injection Tests", () => {
  beforeAll(async () => {
    await initDirectRunner();
  });

  afterAll(async () => {
    await cleanupDirectRunner();
  });

  test("injection payload works", async () => {
    const { success, result, timing } = await directSQL("SELECT * FROM users WHERE id = 1 OR 1=1");

    expect(success).toBe(true);
    expect(result?.rows.length).toBeGreaterThan(1);
  });
});
```

## Future Roadmap

- [ ] MySQL adapter and tests
- [ ] MSSQL adapter and tests
- [ ] Oracle adapter and tests
- [ ] Fuzzing module for payload discovery
- [ ] HTML report generation
- [ ] CI/CD integration

## Security Notice

This framework contains **intentionally vulnerable code** for educational and testing purposes.

**DO NOT:**

- Deploy the vulnerable app to production
- Expose the vulnerable app to untrusted networks
- Use these techniques against systems without authorization

## License

MIT
