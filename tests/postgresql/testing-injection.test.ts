/**
 * PostgreSQL SQL Injection Detection Tests
 *
 * These tests validate basic SQL injection detection techniques
 * documented in the SQL Injection Knowledge Base.
 *
 * @kb-coverage postgresql/testing-injection - Full coverage
 * @kb-coverage postgresql/testing-version - Partial (version() function)
 * @kb-coverage postgresql/comment-out-query - Full coverage
 * @kb-coverage postgresql/string-concatenation - Partial (||, CHR, ASCII, SUBSTRING)
 * @kb-coverage postgresql/avoiding-quotations - Partial (CHR encoding)
 * @kb-coverage postgresql/database-names - Partial (current_database)
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

  /**
   * @kb-entry postgresql/testing-injection
   * @kb-section Boolean-Based SQLi
   */
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

  /**
   * @kb-entry postgresql/testing-injection
   * @kb-section Error-Based SQLi
   */
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

  /**
   * @kb-entry postgresql/testing-injection
   * @kb-section UNION-Based SQLi
   */
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

  /**
   * @kb-entry postgresql/comment-out-query
   * @kb-section Comment Syntax
   */
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

  /**
   * @kb-entry postgresql/testing-version
   * @kb-section Version Detection
   * @kb-entry postgresql/database-names
   * @kb-section Database Enumeration
   */
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

  /**
   * @kb-entry postgresql/string-concatenation
   * @kb-section String Functions
   * @kb-entry postgresql/avoiding-quotations
   * @kb-section CHR() Encoding
   */
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

  /**
   * @kb-entry postgresql/testing-injection
   * @kb-section PostgreSQL Cast Syntax
   */
  describe("PostgreSQL-specific cast syntax (::type)", () => {
    test("::int cast shorthand works", async () => {
      const { rows } = await directSQLExpectSuccess("SELECT 1::int as num");
      expect((rows[0] as { num: number }).num).toBe(1);
    });

    test("::text cast shorthand works", async () => {
      const { rows } = await directSQLExpectSuccess("SELECT 123::text as str");
      expect((rows[0] as { str: string }).str).toBe("123");
    });

    test("::boolean cast shorthand works", async () => {
      const { rows } = await directSQLExpectSuccess("SELECT 1::boolean as bool");
      expect((rows[0] as { bool: boolean }).bool).toBe(true);
    });

    test("1::int=1 as PostgreSQL detection", async () => {
      const { rows } = await directSQLExpectSuccess(
        "SELECT CASE WHEN 1::int=1 THEN 'postgresql' ELSE 'other' END as db"
      );
      expect((rows[0] as { db: string }).db).toBe("postgresql");
    });
  });

  /**
   * @kb-entry postgresql/testing-injection
   * @kb-section Error-Based Data Extraction
   */
  describe("Error-based data extraction via CAST", () => {
    test("CAST version() to int reveals version in error", async () => {
      const error = await directSQLExpectError("SELECT CAST(version() AS int)");
      expect(error.message).toMatch(/PostgreSQL/i);
    });

    test("::int cast reveals data in error", async () => {
      const error = await directSQLExpectError("SELECT (SELECT current_database())::int");
      expect(error.message).toMatch(/vulndb/i);
    });

    test("CAST current_user to int reveals username", async () => {
      const error = await directSQLExpectError("SELECT CAST(current_user AS int)");
      expect(error.message).toMatch(/postgres/i);
    });

    test("String markers in CAST error for easy extraction", async () => {
      const error = await directSQLExpectError(
        "SELECT CAST('~'||(SELECT current_database())||'~' AS int)"
      );
      expect(error.message).toMatch(/~vulndb~/i);
    });
  });

  /**
   * @kb-entry postgresql/string-concatenation
   * @kb-section String Length and Position Functions
   */
  describe("String length and extraction functions", () => {
    test("LENGTH() returns string length", async () => {
      const { rows } = await directSQLExpectSuccess("SELECT LENGTH('admin') as len");
      expect((rows[0] as { len: number }).len).toBe(5);
    });

    test("CHAR_LENGTH() is alias for LENGTH()", async () => {
      const { rows } = await directSQLExpectSuccess("SELECT CHAR_LENGTH('admin') as len");
      expect((rows[0] as { len: number }).len).toBe(5);
    });

    test("OCTET_LENGTH() returns byte length", async () => {
      const { rows } = await directSQLExpectSuccess("SELECT OCTET_LENGTH('admin') as len");
      expect((rows[0] as { len: number }).len).toBe(5);
    });

    test("SUBSTR() extracts substring", async () => {
      const { rows } = await directSQLExpectSuccess("SELECT SUBSTR('admin', 1, 3) as sub");
      expect((rows[0] as { sub: string }).sub).toBe("adm");
    });

    test("LEFT() returns leftmost characters", async () => {
      const { rows } = await directSQLExpectSuccess("SELECT LEFT('admin', 3) as left");
      expect((rows[0] as { left: string }).left).toBe("adm");
    });

    test("RIGHT() returns rightmost characters", async () => {
      const { rows } = await directSQLExpectSuccess("SELECT RIGHT('admin', 3) as right");
      expect((rows[0] as { right: string }).right).toBe("min");
    });

    test("POSITION() finds substring location", async () => {
      const { rows } = await directSQLExpectSuccess("SELECT POSITION('min' IN 'admin') as pos");
      expect((rows[0] as { pos: number }).pos).toBe(3);
    });

    test("STRPOS() PostgreSQL-specific position function", async () => {
      const { rows } = await directSQLExpectSuccess("SELECT STRPOS('admin', 'min') as pos");
      expect((rows[0] as { pos: number }).pos).toBe(3);
    });
  });
});
