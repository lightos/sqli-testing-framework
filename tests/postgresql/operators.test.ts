/**
 * PostgreSQL Operators Tests
 *
 * @kb-coverage postgresql/operators - Full coverage
 */

import { describe, test, expect, beforeAll, afterAll } from "vitest";
import {
  initDirectRunner,
  cleanupDirectRunner,
  directSQLExpectSuccess,
} from "../../src/runner/direct.js";
import { logger } from "../../src/utils/logger.js";

describe("PostgreSQL Operators", () => {
  beforeAll(async () => {
    logger.setLevel("warn");
    await initDirectRunner();
  }, 30000);

  afterAll(async () => {
    await cleanupDirectRunner();
  }, 10000);

  /**
   * @kb-entry postgresql/operators
   * @kb-section Comparison Operators
   */
  describe("Comparison operators", () => {
    test("Equal operator (=)", async () => {
      const { rows } = await directSQLExpectSuccess("SELECT * FROM users WHERE id = 1");
      expect(rows.length).toBe(1);
    });

    test("Not equal operator (<>)", async () => {
      const { rows } = await directSQLExpectSuccess("SELECT * FROM users WHERE id <> 1");
      expect(rows.length).toBeGreaterThan(0);
    });

    test("Not equal operator (!=)", async () => {
      const { rows } = await directSQLExpectSuccess("SELECT * FROM users WHERE id != 1");
      expect(rows.length).toBeGreaterThan(0);
    });

    test("Greater than operator (>)", async () => {
      const { rows } = await directSQLExpectSuccess("SELECT * FROM users WHERE id > 1");
      expect(rows.length).toBeGreaterThan(0);
    });

    test("BETWEEN operator", async () => {
      const { rows } = await directSQLExpectSuccess("SELECT * FROM users WHERE id BETWEEN 1 AND 3");
      expect(rows.length).toBeGreaterThan(0);
    });

    test("IS NULL operator", async () => {
      const { rows } = await directSQLExpectSuccess("SELECT (NULL IS NULL) as result");
      expect((rows[0] as { result: boolean }).result).toBe(true);
    });

    test("IS DISTINCT FROM operator (NULL-safe)", async () => {
      const { rows } = await directSQLExpectSuccess("SELECT (NULL IS DISTINCT FROM 1) as result");
      expect((rows[0] as { result: boolean }).result).toBe(true);
    });

    test("LIKE operator", async () => {
      const { rows } = await directSQLExpectSuccess("SELECT * FROM users WHERE username LIKE 'a%'");
      expect(rows.length).toBeGreaterThan(0);
    });

    test("ILIKE operator (case-insensitive)", async () => {
      const { rows } = await directSQLExpectSuccess(
        "SELECT * FROM users WHERE username ILIKE 'ADMIN'"
      );
      expect(rows.length).toBeGreaterThan(0);
    });

    test("IN operator", async () => {
      const { rows } = await directSQLExpectSuccess("SELECT * FROM users WHERE id IN (1, 2, 3)");
      expect(rows.length).toBeGreaterThan(0);
    });
  });

  /**
   * @kb-entry postgresql/operators
   * @kb-section Logical Operators
   */
  describe("Logical operators", () => {
    test("AND operator", async () => {
      const { rows } = await directSQLExpectSuccess(
        "SELECT * FROM users WHERE id = 1 AND username = 'admin'"
      );
      expect(rows.length).toBe(1);
    });

    test("OR operator", async () => {
      const { rows } = await directSQLExpectSuccess("SELECT * FROM users WHERE id = 1 OR id = 2");
      expect(rows.length).toBeGreaterThan(1);
    });

    test("NOT operator", async () => {
      const { rows } = await directSQLExpectSuccess("SELECT * FROM users WHERE NOT id = 1");
      expect(rows.length).toBeGreaterThan(0);
    });

    test("Operator precedence (AND before OR)", async () => {
      const { rows } = await directSQLExpectSuccess("SELECT (false OR true AND true) as result");
      expect((rows[0] as { result: boolean }).result).toBe(true);
    });
  });

  /**
   * @kb-entry postgresql/operators
   * @kb-section String Operators
   */
  describe("String operators", () => {
    test("Concatenation operator (||)", async () => {
      const { rows } = await directSQLExpectSuccess("SELECT 'hello' || ' ' || 'world' as str");
      expect((rows[0] as { str: string }).str).toBe("hello world");
    });

    test("CONCAT function", async () => {
      const { rows } = await directSQLExpectSuccess("SELECT CONCAT('hello', ' ', 'world') as str");
      expect((rows[0] as { str: string }).str).toBe("hello world");
    });

    test("CONCAT_WS function", async () => {
      const { rows } = await directSQLExpectSuccess("SELECT CONCAT_WS('-', 'a', 'b', 'c') as str");
      expect((rows[0] as { str: string }).str).toBe("a-b-c");
    });
  });

  /**
   * @kb-entry postgresql/operators
   * @kb-section Mathematical Operators
   */
  describe("Mathematical operators", () => {
    test("Addition (+)", async () => {
      const { rows } = await directSQLExpectSuccess("SELECT 2 + 3 as result");
      expect((rows[0] as { result: number }).result).toBe(5);
    });

    test("Subtraction (-)", async () => {
      const { rows } = await directSQLExpectSuccess("SELECT 5 - 3 as result");
      expect((rows[0] as { result: number }).result).toBe(2);
    });

    test("Multiplication (*)", async () => {
      const { rows } = await directSQLExpectSuccess("SELECT 2 * 3 as result");
      expect((rows[0] as { result: number }).result).toBe(6);
    });

    test("Division (/)", async () => {
      const { rows } = await directSQLExpectSuccess("SELECT 6 / 2 as result");
      expect((rows[0] as { result: number }).result).toBe(3);
    });

    test("Modulo (%)", async () => {
      const { rows } = await directSQLExpectSuccess("SELECT 7 % 3 as result");
      expect((rows[0] as { result: number }).result).toBe(1);
    });

    test("Exponentiation (^)", async () => {
      const { rows } = await directSQLExpectSuccess("SELECT 2 ^ 3 as result");
      expect(parseFloat((rows[0] as { result: string }).result)).toBe(8);
    });
  });

  /**
   * @kb-entry postgresql/operators
   * @kb-section Bitwise Operators
   */
  describe("Bitwise operators", () => {
    test("Bitwise AND (&)", async () => {
      const { rows } = await directSQLExpectSuccess("SELECT 5 & 1 as result");
      expect((rows[0] as { result: number }).result).toBe(1);
    });

    test("Bitwise OR (|)", async () => {
      const { rows } = await directSQLExpectSuccess("SELECT 5 | 1 as result");
      expect((rows[0] as { result: number }).result).toBe(5);
    });

    test("Bitwise XOR (#)", async () => {
      const { rows } = await directSQLExpectSuccess("SELECT 5 # 1 as result");
      expect((rows[0] as { result: number }).result).toBe(4);
    });

    test("Left shift (<<)", async () => {
      const { rows } = await directSQLExpectSuccess("SELECT 1 << 2 as result");
      expect((rows[0] as { result: number }).result).toBe(4);
    });

    test("Right shift (>>)", async () => {
      const { rows } = await directSQLExpectSuccess("SELECT 4 >> 2 as result");
      expect((rows[0] as { result: number }).result).toBe(1);
    });
  });

  /**
   * @kb-entry postgresql/operators
   * @kb-section Type Cast Operator
   */
  describe("Type cast operator (::)", () => {
    test("Cast string to int", async () => {
      const { rows } = await directSQLExpectSuccess("SELECT '123'::int as num");
      expect((rows[0] as { num: number }).num).toBe(123);
    });

    test("Cast int to text", async () => {
      const { rows } = await directSQLExpectSuccess("SELECT 123::text as str");
      expect((rows[0] as { str: string }).str).toBe("123");
    });

    test("Cast to boolean", async () => {
      const { rows } = await directSQLExpectSuccess("SELECT 1::boolean as bool");
      expect((rows[0] as { bool: boolean }).bool).toBe(true);
    });

    test("Cast string to date", async () => {
      const { rows } = await directSQLExpectSuccess("SELECT '2025-01-01'::date as dt");
      expect((rows[0] as { dt: Date }).dt).toBeTruthy();
    });
  });

  /**
   * @kb-entry postgresql/operators
   * @kb-section Regex Operators
   */
  describe("Regex operators", () => {
    test("POSIX regex match (~)", async () => {
      const { rows } = await directSQLExpectSuccess("SELECT 'admin' ~ '^a' as result");
      expect((rows[0] as { result: boolean }).result).toBe(true);
    });

    test("Case-insensitive regex match (~*)", async () => {
      const { rows } = await directSQLExpectSuccess("SELECT 'admin' ~* '^A' as result");
      expect((rows[0] as { result: boolean }).result).toBe(true);
    });

    test("Regex not match (!~)", async () => {
      const { rows } = await directSQLExpectSuccess("SELECT 'admin' !~ '^b' as result");
      expect((rows[0] as { result: boolean }).result).toBe(true);
    });

    test("SIMILAR TO operator", async () => {
      const { rows } = await directSQLExpectSuccess("SELECT 'admin' SIMILAR TO 'a%' as result");
      expect((rows[0] as { result: boolean }).result).toBe(true);
    });
  });

  /**
   * @kb-entry postgresql/operators
   * @kb-section Array Operators
   */
  describe("Array operators", () => {
    test("Array contains (@>)", async () => {
      const { rows } = await directSQLExpectSuccess("SELECT ARRAY[1,2,3] @> ARRAY[1,2] as result");
      expect((rows[0] as { result: boolean }).result).toBe(true);
    });

    test("Array is contained by (<@)", async () => {
      const { rows } = await directSQLExpectSuccess("SELECT ARRAY[1,2] <@ ARRAY[1,2,3] as result");
      expect((rows[0] as { result: boolean }).result).toBe(true);
    });

    test("Array subscript", async () => {
      const { rows } = await directSQLExpectSuccess("SELECT (ARRAY['a','b','c'])[1] as elem");
      expect((rows[0] as { elem: string }).elem).toBe("a");
    });

    test("ANY with array", async () => {
      const { rows } = await directSQLExpectSuccess(
        "SELECT * FROM users WHERE id = ANY(ARRAY[1,2,3])"
      );
      expect(rows.length).toBeGreaterThan(0);
    });
  });

  /**
   * @kb-entry postgresql/operators
   * @kb-section Injection Context Examples
   */
  describe("Injection context examples", () => {
    test("String concatenation for data extraction", async () => {
      const { rows } = await directSQLExpectSuccess(
        "SELECT id, username || ':' || password as creds FROM users WHERE id = 1"
      );
      expect((rows[0] as { creds: string }).creds).toContain(":");
    });

    test("Regex-based blind injection", async () => {
      const { rows } = await directSQLExpectSuccess(
        "SELECT CASE WHEN (SELECT username FROM users LIMIT 1) ~ '^a' THEN true ELSE false END as result"
      );
      expect(typeof (rows[0] as { result: boolean }).result).toBe("boolean");
    });

    test("Type cast for database detection", async () => {
      const { rows } = await directSQLExpectSuccess(
        "SELECT CASE WHEN 1::int=1 THEN 'postgresql' ELSE 'other' END as db"
      );
      expect((rows[0] as { db: string }).db).toBe("postgresql");
    });
  });
});
