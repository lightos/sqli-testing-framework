/**
 * PostgreSQL SQL Injection Detection Tests
 *
 * These tests validate basic SQL injection detection techniques
 * documented in the SQL Injection Knowledge Base.
 */

import { describe, test, expect, beforeAll, afterAll } from "vitest";
import {
  initDirectRunner,
  cleanupDirectRunner,
  directSQL,
  directSQLExpectSuccess,
  directSQLExpectError,
} from "../../src/runner/direct.js";
import { logger } from "../../src/utils/logger.js";

describe("PostgreSQL Injection Detection", () => {
  beforeAll(async () => {
    logger.setLevel("warn");
    await initDirectRunner();
  }, 30000);

  afterAll(async () => {
    await cleanupDirectRunner();
  }, 10000);

  describe("Boolean-based detection", () => {
    test("OR 1=1 always returns true", async () => {
      const { rows } = await directSQLExpectSuccess("SELECT * FROM users WHERE id = 999 OR 1=1");

      // Should return all users since OR 1=1 is always true
      expect(rows.length).toBeGreaterThan(0);
    });

    test("AND 1=1 preserves original results", async () => {
      const { rows: original } = await directSQLExpectSuccess("SELECT * FROM users WHERE id = 1");

      const { rows: withAnd } = await directSQLExpectSuccess(
        "SELECT * FROM users WHERE id = 1 AND 1=1"
      );

      // Should return the same results
      expect(withAnd.length).toBe(original.length);
    });

    test("AND 1=2 returns no results", async () => {
      const { rows } = await directSQLExpectSuccess("SELECT * FROM users WHERE id = 1 AND 1=2");

      // Should return no results since AND 1=2 is always false
      expect(rows).toHaveLength(0);
    });

    test("Comparing true vs false condition results", async () => {
      const { rows: trueRows } = await directSQLExpectSuccess(
        "SELECT COUNT(*) as cnt FROM users WHERE 1=1"
      );

      const { rows: falseRows } = await directSQLExpectSuccess(
        "SELECT COUNT(*) as cnt FROM users WHERE 1=2"
      );

      const trueCount = parseInt((trueRows[0] as { cnt: string }).cnt, 10);
      const falseCount = parseInt((falseRows[0] as { cnt: string }).cnt, 10);

      expect(trueCount).toBeGreaterThan(0);
      expect(falseCount).toBe(0);
    });
  });

  describe("Error-based detection", () => {
    test("CAST error reveals injection point", async () => {
      const error = await directSQLExpectError("SELECT CAST('test' AS int)");

      expect(error.message).toMatch(/invalid input syntax for (type )?integer/i);
    });

    test("Division by zero error", async () => {
      const error = await directSQLExpectError("SELECT 1/0");

      expect(error.message).toMatch(/division by zero/i);
    });

    test("Syntax error from unclosed quote", async () => {
      const error = await directSQLExpectError("SELECT * FROM users WHERE username = '");

      expect(error.message).toMatch(/syntax|unterminated/i);
    });

    test("Invalid column name error", async () => {
      const error = await directSQLExpectError("SELECT nonexistent_column FROM users");

      expect(error.message).toMatch(/column.*does not exist/i);
    });
  });

  describe("UNION-based detection", () => {
    test("UNION SELECT with matching columns", async () => {
      // Users table has id, username, password, email, role, created_at
      // We need to match the column count
      const { rows } = await directSQLExpectSuccess(`
        SELECT id, username FROM users WHERE id = 1
        UNION
        SELECT 999, 'injected'
      `);

      const usernames = rows.map(
        (r: Record<string, unknown>) => (r as { username: string }).username
      );
      expect(usernames).toContain("injected");
    });

    test("UNION SELECT NULL technique to find column count", async () => {
      // Try different NULL counts until one works
      let columnCount = 0;

      for (let i = 1; i <= 10; i++) {
        const nulls = Array<string>(i).fill("NULL").join(", ");
        const sql = `SELECT * FROM users WHERE id = 1 UNION SELECT ${nulls}`;

        const { success } = await directSQL(sql);

        if (success) {
          columnCount = i;
          break;
        }
      }

      expect(columnCount).toBeGreaterThan(0);
    });

    test("ORDER BY column enumeration", async () => {
      // Find how many columns by incrementing ORDER BY
      let maxColumn = 0;

      for (let i = 1; i <= 10; i++) {
        const { success } = await directSQL(`SELECT * FROM users ORDER BY ${i}`);

        if (success) {
          maxColumn = i;
        } else {
          break;
        }
      }

      expect(maxColumn).toBeGreaterThan(0);
    });
  });

  describe("Comment-based techniques", () => {
    test("Double dash comment (--) terminates query", async () => {
      const { success, result } = await directSQL(
        "SELECT * FROM users WHERE id = 1 -- AND password = 'wrong'"
      );

      // Comment removes the password check
      expect(success).toBe(true);
      expect(result?.rows.length).toBeGreaterThan(0);
    });

    test("C-style comment (/* */) removes portion", async () => {
      const { success, result } = await directSQL(
        "SELECT * FROM users WHERE id = 1 /* AND password = 'wrong' */"
      );

      expect(success).toBe(true);
      expect(result?.rows.length).toBeGreaterThan(0);
    });

    test("Inline comment for obfuscation", async () => {
      const { success, result } = await directSQL("SELECT/*comment*/* FROM/**/users WHERE id = 1");

      expect(success).toBe(true);
      expect(result?.rows.length).toBeGreaterThan(0);
    });
  });

  describe("PostgreSQL-specific detection", () => {
    test("version() function available", async () => {
      const { rows } = await directSQLExpectSuccess("SELECT version()");

      const version = (rows[0] as { version: string }).version;
      expect(version).toMatch(/PostgreSQL/i);
    });

    test("current_database() reveals database name", async () => {
      const { rows } = await directSQLExpectSuccess("SELECT current_database()");

      const dbName = (rows[0] as { current_database: string }).current_database;
      expect(dbName).toBe("vulndb");
    });

    test("current_user reveals connected user", async () => {
      const { rows } = await directSQLExpectSuccess("SELECT current_user");

      const user = (rows[0] as { current_user: string }).current_user;
      expect(user).toBe("postgres");
    });

    test("pg_catalog accessible for metadata", async () => {
      const { rows } = await directSQLExpectSuccess(
        "SELECT tablename FROM pg_catalog.pg_tables WHERE schemaname = 'public' LIMIT 5"
      );

      expect(rows.length).toBeGreaterThan(0);
    });
  });

  describe("String manipulation for bypass", () => {
    test("Concatenation with || operator", async () => {
      const { rows } = await directSQLExpectSuccess("SELECT 'ad' || 'min' as combined");

      expect((rows[0] as { combined: string }).combined).toBe("admin");
    });

    test("CHR() function for character encoding", async () => {
      // 'a' = CHR(97), 'd' = CHR(100), etc.
      const { rows } = await directSQLExpectSuccess(
        "SELECT CHR(97) || CHR(100) || CHR(109) || CHR(105) || CHR(110) as word"
      );

      expect((rows[0] as { word: string }).word).toBe("admin");
    });

    test("ASCII() function for character extraction", async () => {
      const { rows } = await directSQLExpectSuccess("SELECT ASCII('a')");

      expect((rows[0] as { ascii: number }).ascii).toBe(97);
    });

    test("SUBSTRING for character-by-character extraction", async () => {
      const { rows } = await directSQLExpectSuccess(
        "SELECT SUBSTRING('admin', 1, 1) as first_char"
      );

      expect((rows[0] as { first_char: string }).first_char).toBe("a");
    });
  });
});
