/**
 * PostgreSQL String Concatenation Tests
 *
 * Tests for string concatenation methods and functions.
 *
 * @kb-coverage postgresql/string-concatenation - Full coverage
 */

import { describe, test, expect, beforeAll, afterAll } from "vitest";
import {
  initDirectRunner,
  cleanupDirectRunner,
  directSQLExpectSuccess,
} from "../../src/runner/direct.js";
import { logger } from "../../src/utils/logger.js";

describe("PostgreSQL String Concatenation", () => {
  beforeAll(async () => {
    logger.setLevel("warn");
    await initDirectRunner();
  }, 30000);

  afterAll(async () => {
    await cleanupDirectRunner();
  }, 10000);

  /**
   * @kb-entry postgresql/string-concatenation
   * @kb-section || Operator
   */
  describe("|| operator", () => {
    test("Basic string concatenation", async () => {
      const { rows } = await directSQLExpectSuccess("SELECT 'A' || 'B' as result");
      expect((rows[0] as { result: string }).result).toBe("AB");
    });

    test("Multiple string concatenation", async () => {
      const { rows } = await directSQLExpectSuccess("SELECT 'Hello' || ' ' || 'World' as result");
      expect((rows[0] as { result: string }).result).toBe("Hello World");
    });

    test("|| with NULL returns NULL", async () => {
      const { rows } = await directSQLExpectSuccess("SELECT 'a' || NULL || 'c' as result");
      expect((rows[0] as { result: string | null }).result).toBeNull();
    });

    test("Concatenate column values", async () => {
      const { rows } = await directSQLExpectSuccess(
        "SELECT username || ':' || id::text as result FROM users WHERE id = 1"
      );
      expect((rows[0] as { result: string }).result).toContain(":");
    });
  });

  /**
   * @kb-entry postgresql/string-concatenation
   * @kb-section CONCAT() Function
   */
  describe("CONCAT() function", () => {
    test("Basic CONCAT", async () => {
      const { rows } = await directSQLExpectSuccess("SELECT CONCAT('a', 'b', 'c') as result");
      expect((rows[0] as { result: string }).result).toBe("abc");
    });

    test("CONCAT handles NULL gracefully", async () => {
      const { rows } = await directSQLExpectSuccess("SELECT CONCAT('a', NULL, 'c') as result");
      expect((rows[0] as { result: string }).result).toBe("ac");
    });

    test("CONCAT with numbers", async () => {
      const { rows } = await directSQLExpectSuccess("SELECT CONCAT('ID:', 123) as result");
      expect((rows[0] as { result: string }).result).toBe("ID:123");
    });
  });

  /**
   * @kb-entry postgresql/string-concatenation
   * @kb-section CONCAT_WS() Function
   */
  describe("CONCAT_WS() function", () => {
    test("Concatenate with separator", async () => {
      const { rows } = await directSQLExpectSuccess(
        "SELECT CONCAT_WS(',', 'a', 'b', 'c') as result"
      );
      expect((rows[0] as { result: string }).result).toBe("a,b,c");
    });

    test("CONCAT_WS with colon separator", async () => {
      const { rows } = await directSQLExpectSuccess(
        "SELECT CONCAT_WS(':', 'user', 'password') as result"
      );
      expect((rows[0] as { result: string }).result).toBe("user:password");
    });

    test("CONCAT_WS skips NULL values", async () => {
      const { rows } = await directSQLExpectSuccess(
        "SELECT CONCAT_WS(',', 'a', NULL, 'c') as result"
      );
      expect((rows[0] as { result: string }).result).toBe("a,c");
    });
  });

  /**
   * @kb-entry postgresql/string-concatenation
   * @kb-section STRING_AGG() Function
   */
  describe("STRING_AGG() function", () => {
    test("Aggregate usernames", async () => {
      const { rows } = await directSQLExpectSuccess(
        "SELECT STRING_AGG(username, ',') as result FROM users"
      );
      expect((rows[0] as { result: string }).result).toContain(",");
    });

    test("STRING_AGG with ordering", async () => {
      const { rows } = await directSQLExpectSuccess(
        "SELECT STRING_AGG(username, ',' ORDER BY username) as result FROM users"
      );
      expect((rows[0] as { result: string }).result).toBeTruthy();
    });

    test("STRING_AGG with DISTINCT", async () => {
      const { rows } = await directSQLExpectSuccess(
        "SELECT STRING_AGG(DISTINCT username, ',') as result FROM users"
      );
      expect((rows[0] as { result: string }).result).toBeTruthy();
    });
  });

  /**
   * @kb-entry postgresql/string-concatenation
   * @kb-section ARRAY_TO_STRING() Function
   */
  describe("ARRAY_TO_STRING() function", () => {
    test("Convert array to string", async () => {
      const { rows } = await directSQLExpectSuccess(
        "SELECT ARRAY_TO_STRING(ARRAY['a', 'b', 'c'], ',') as result"
      );
      expect((rows[0] as { result: string }).result).toBe("a,b,c");
    });

    test("Array from subquery to string", async () => {
      const { rows } = await directSQLExpectSuccess(
        "SELECT ARRAY_TO_STRING(ARRAY(SELECT username FROM users LIMIT 3), ',') as result"
      );
      expect((rows[0] as { result: string }).result).toBeTruthy();
    });
  });

  /**
   * @kb-entry postgresql/string-concatenation
   * @kb-section FORMAT() Function
   */
  describe("FORMAT() function", () => {
    test("Basic FORMAT with %s", async () => {
      const { rows } = await directSQLExpectSuccess(
        "SELECT FORMAT('%s:%s', 'username', 'password') as result"
      );
      expect((rows[0] as { result: string }).result).toBe("username:password");
    });

    test("FORMAT with column values", async () => {
      const { rows } = await directSQLExpectSuccess(
        "SELECT FORMAT('User: %s (ID: %s)', username, id) as result FROM users WHERE id = 1"
      );
      expect((rows[0] as { result: string }).result).toContain("User:");
    });

    test("FORMAT with %I for identifiers", async () => {
      const { rows } = await directSQLExpectSuccess(
        "SELECT FORMAT('SELECT * FROM %I', 'users') as result"
      );
      expect((rows[0] as { result: string }).result).toBe("SELECT * FROM users");
    });
  });

  /**
   * @kb-entry postgresql/string-concatenation
   * @kb-section CHR() for Building Strings
   */
  describe("Building strings with CHR()", () => {
    test("Build 'admin' with CHR()", async () => {
      const { rows } = await directSQLExpectSuccess(
        "SELECT CHR(97)||CHR(100)||CHR(109)||CHR(105)||CHR(110) as result"
      );
      expect((rows[0] as { result: string }).result).toBe("admin");
    });

    test("Build string without quotes", async () => {
      const { rows } = await directSQLExpectSuccess(
        "SELECT CHR(116)||CHR(101)||CHR(115)||CHR(116) as result"
      );
      expect((rows[0] as { result: string }).result).toBe("test");
    });
  });

  /**
   * @kb-entry postgresql/string-concatenation
   * @kb-section Type Casting in Concatenation
   */
  describe("Type casting in concatenation", () => {
    test("Cast integer to text with ::", async () => {
      const { rows } = await directSQLExpectSuccess("SELECT 'ID: ' || 123::text as result");
      expect((rows[0] as { result: string }).result).toBe("ID: 123");
    });

    test("Cast with CAST function", async () => {
      const { rows } = await directSQLExpectSuccess("SELECT 'ID: ' || CAST(123 AS text) as result");
      expect((rows[0] as { result: string }).result).toBe("ID: 123");
    });

    test("Concatenate column with type cast", async () => {
      const { rows } = await directSQLExpectSuccess(
        "SELECT 'ID: ' || id::text as result FROM users WHERE id = 1"
      );
      expect((rows[0] as { result: string }).result).toBe("ID: 1");
    });
  });

  /**
   * @kb-entry postgresql/string-concatenation
   * @kb-section String Length Functions
   */
  describe("String length functions", () => {
    test("LENGTH() returns character count", async () => {
      const { rows } = await directSQLExpectSuccess("SELECT LENGTH('admin') as len");
      expect((rows[0] as { len: number }).len).toBe(5);
    });

    test("CHAR_LENGTH() alias", async () => {
      const { rows } = await directSQLExpectSuccess("SELECT CHAR_LENGTH('admin') as len");
      expect((rows[0] as { len: number }).len).toBe(5);
    });

    test("OCTET_LENGTH() returns byte count", async () => {
      const { rows } = await directSQLExpectSuccess("SELECT OCTET_LENGTH('admin') as len");
      expect((rows[0] as { len: number }).len).toBe(5);
    });

    test("LENGTH of column value", async () => {
      const { rows } = await directSQLExpectSuccess(
        "SELECT LENGTH(username) as len FROM users WHERE id = 1"
      );
      expect((rows[0] as { len: number }).len).toBeGreaterThan(0);
    });
  });

  /**
   * @kb-entry postgresql/string-concatenation
   * @kb-section Position Functions
   */
  describe("Position functions", () => {
    test("POSITION() finds substring", async () => {
      const { rows } = await directSQLExpectSuccess("SELECT POSITION('min' IN 'admin') as pos");
      expect((rows[0] as { pos: number }).pos).toBe(3);
    });

    test("STRPOS() PostgreSQL-specific", async () => {
      const { rows } = await directSQLExpectSuccess("SELECT STRPOS('admin', 'min') as pos");
      expect((rows[0] as { pos: number }).pos).toBe(3);
    });

    test("Position returns 0 if not found", async () => {
      const { rows } = await directSQLExpectSuccess("SELECT POSITION('xyz' IN 'admin') as pos");
      expect((rows[0] as { pos: number }).pos).toBe(0);
    });
  });

  /**
   * @kb-entry postgresql/string-concatenation
   * @kb-section Substring Functions
   */
  describe("Substring extraction functions", () => {
    test("SUBSTRING with position and length", async () => {
      const { rows } = await directSQLExpectSuccess("SELECT SUBSTRING('admin', 1, 1) as sub");
      expect((rows[0] as { sub: string }).sub).toBe("a");
    });

    test("SUBSTRING with FROM/FOR syntax", async () => {
      const { rows } = await directSQLExpectSuccess(
        "SELECT SUBSTRING('admin' FROM 1 FOR 1) as sub"
      );
      expect((rows[0] as { sub: string }).sub).toBe("a");
    });

    test("SUBSTR() alias", async () => {
      const { rows } = await directSQLExpectSuccess("SELECT SUBSTR('admin', 1, 1) as sub");
      expect((rows[0] as { sub: string }).sub).toBe("a");
    });

    test("LEFT() function", async () => {
      const { rows } = await directSQLExpectSuccess("SELECT LEFT('admin', 3) as sub");
      expect((rows[0] as { sub: string }).sub).toBe("adm");
    });

    test("RIGHT() function", async () => {
      const { rows } = await directSQLExpectSuccess("SELECT RIGHT('admin', 3) as sub");
      expect((rows[0] as { sub: string }).sub).toBe("min");
    });
  });

  /**
   * @kb-entry postgresql/string-concatenation
   * @kb-section NULL Handling with COALESCE
   */
  describe("NULL handling with COALESCE", () => {
    test("COALESCE prevents NULL concatenation issue", async () => {
      const { rows } = await directSQLExpectSuccess(
        "SELECT COALESCE(NULL, '') || 'text' as result"
      );
      expect((rows[0] as { result: string }).result).toBe("text");
    });

    test("COALESCE with column that might be NULL", async () => {
      const { rows } = await directSQLExpectSuccess(
        "SELECT COALESCE(username, 'unknown') || ':' || id::text as result FROM users WHERE id = 1"
      );
      expect((rows[0] as { result: string }).result).toContain(":");
    });
  });

  /**
   * @kb-entry postgresql/string-concatenation
   * @kb-section Injection Examples
   */
  describe("Concatenation in injection context", () => {
    test("Extract username:password pairs", async () => {
      const { rows } = await directSQLExpectSuccess(
        "SELECT id, username || ':' || id::text as creds FROM users WHERE id = 1"
      );
      expect((rows[0] as { creds: string }).creds).toContain(":");
    });

    test("Aggregate multiple rows into single result", async () => {
      const { rows } = await directSQLExpectSuccess(
        "SELECT STRING_AGG(username || ':' || id::text, ';') as all_creds FROM users"
      );
      expect((rows[0] as { all_creds: string }).all_creds).toContain(";");
    });

    test("Build file path without quotes", async () => {
      const { rows } = await directSQLExpectSuccess("SELECT '/etc/' || 'passwd' as path");
      expect((rows[0] as { path: string }).path).toBe("/etc/passwd");
    });
  });
});
