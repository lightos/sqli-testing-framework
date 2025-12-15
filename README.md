# SQL Injection Testing Framework

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Node.js](https://img.shields.io/badge/Node.js-18%2B-green.svg)](https://nodejs.org/)
[![TypeScript](https://img.shields.io/badge/TypeScript-5.x-blue.svg)](https://www.typescriptlang.org/)
[![Vitest](https://img.shields.io/badge/Vitest-Testing-6E9F18.svg)](https://vitest.dev/)
[![PostgreSQL](https://img.shields.io/badge/PostgreSQL-12%20%7C%2016-336791.svg)](https://www.postgresql.org/)

A comprehensive framework for validating and testing SQL injection techniques against real database instances in isolated Docker environments.

## Overview

This framework validates SQL injection payloads documented in the [SQL Injection Knowledge Base](https://github.com/WebsecLabs/sql-injection-knowledge-base). The test suites cover techniques and payloads from the knowledge base, ensuring they work as documented against real database instances.

### Features

- **Direct SQL Testing** - Execute SQL directly against databases to validate syntax and behavior
- **HTTP Testing** - Test injection payloads via a vulnerable web application
- **Multi-Version Support** - Test against multiple database versions simultaneously
- **Timing Analysis** - Automated timing-based blind injection testing
- **615+ Tests** - Comprehensive test coverage across 26 test files

### Current Database Support

| Database   | Status    | Versions |
| ---------- | --------- | -------- |
| PostgreSQL | Supported | 12, 16   |
| MySQL      | Planned   | -        |
| MSSQL      | Planned   | -        |
| Oracle     | Planned   | -        |

## Prerequisites

- Node.js 18+
- Docker and Docker Compose
- npm or pnpm

## Quick Start

```bash
# Clone the repository
git clone https://github.com/lightos/sqli-testing-framework.git
cd sqli-testing-framework

# Install dependencies
npm install

# Copy environment template
cp .env.example .env

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
│   └── postgresql/             # 26 test files, 615+ tests
├── COVERAGE.md                 # KB coverage documentation
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

```bash
# Test against PostgreSQL 12
PG_PORT=5432 npm test

# Test against PostgreSQL 16 (default)
PG_PORT=5433 npm test
```

## Test Categories

Tests are organized to match the [SQL Injection Knowledge Base](https://github.com/WebsecLabs/sql-injection-knowledge-base) structure:

| Category              | Test File                      | Tests |
| --------------------- | ------------------------------ | ----- |
| Timing Attacks        | `timing.test.ts`               | 9     |
| Stacked Queries       | `stacked-queries.test.ts`      | 12    |
| Detection Techniques  | `testing-injection.test.ts`    | 38    |
| String Concatenation  | `string-concatenation.test.ts` | 40    |
| Fuzzing & Obfuscation | `fuzzing-obfuscation.test.ts`  | 38    |
| Privilege Escalation  | `privilege-escalation.test.ts` | 36    |
| Config Exploitation   | `config-exploitation.test.ts`  | 34    |
| File Operations       | `reading-files.test.ts`        | 18    |
| Command Execution     | `command-execution.test.ts`    | 21    |
| ...and more           | See `COVERAGE.md`              | 615+  |

## Vulnerable Application

The framework includes a minimal Express app with intentional vulnerabilities:

```bash
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

Tests use [Vitest](https://vitest.dev/) and link to KB entries via JSDoc annotations:

```typescript
import { describe, test, expect, beforeAll, afterAll } from "vitest";
import { initDirectRunner, cleanupDirectRunner, directSQL } from "../../src/runner/direct.js";

/**
 * @kb-coverage postgresql/timing - Full coverage
 */
describe("PostgreSQL Timing Attacks", () => {
  beforeAll(async () => {
    await initDirectRunner();
  });

  afterAll(async () => {
    await cleanupDirectRunner();
  });

  /**
   * @kb-entry postgresql/timing
   * @kb-section pg_sleep() Timing Attack
   */
  test("pg_sleep() delays execution", async () => {
    const { success, result, timing } = await directSQL("SELECT pg_sleep(0.1)");

    expect(success).toBe(true);
    expect(timing).toBeGreaterThan(100);
  });
});
```

## Roadmap

- [ ] MySQL adapter and tests
- [ ] MSSQL adapter and tests
- [ ] Oracle adapter and tests
- [ ] Fuzzing module for payload discovery
- [ ] HTML report generation
- [ ] CI/CD integration

## Disclaimer

> **WARNING: This framework is for authorized security testing and educational purposes only.**

This repository contains:

- Intentionally vulnerable code
- SQL injection payloads and techniques
- Tools that can be used to compromise database systems

**You MUST:**

- Only use this framework against systems you own or have explicit written authorization to test
- Ensure all testing is performed in isolated environments
- Comply with all applicable laws and regulations

**You MUST NOT:**

- Deploy the vulnerable application to production or public networks
- Use these techniques against systems without authorization
- Use this framework for malicious purposes

The authors are not responsible for any misuse or damage caused by this framework. By using this software, you agree to use it responsibly and ethically.

## Related Projects

- [SQL Injection Knowledge Base](https://github.com/WebsecLabs/sql-injection-knowledge-base) - Comprehensive documentation of SQL injection techniques that this framework validates

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.
