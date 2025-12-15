/**
 * PostgreSQL Conditional Statements Tests
 *
 * @kb-coverage postgresql/conditional-statements - Full coverage
 */

import { describe, test, expect, beforeAll, afterAll } from "vitest";
import {
  initDirectRunner,
  cleanupDirectRunner,
  directSQLExpectSuccess,
  directSQLExpectError,
} from "../../src/runner/direct.js";
import { logger } from "../../src/utils/logger.js";

describe("PostgreSQL Conditional Statements", () => {
  beforeAll(async () => {
    logger.setLevel("warn");
    await initDirectRunner();
  }, 30000);

  afterAll(async () => {
    await cleanupDirectRunner();
  }, 10000);

  /**
   * @kb-entry postgresql/conditional-statements
   * @kb-section CASE Expression
   */
  describe("CASE expression", () => {
    test("Basic CASE WHEN true returns first branch", async () => {
      const { rows } = await directSQLExpectSuccess(
        "SELECT CASE WHEN (1=1) THEN 'A' ELSE 'B' END as result"
      );
      expect((rows[0] as { result: string }).result).toBe("A");
    });

    test("Basic CASE WHEN false returns ELSE branch", async () => {
      const { rows } = await directSQLExpectSuccess(
        "SELECT CASE WHEN (1=2) THEN 'A' ELSE 'B' END as result"
      );
      expect((rows[0] as { result: string }).result).toBe("B");
    });

    test("Multi-branch CASE with subquery", async () => {
      const { rows } = await directSQLExpectSuccess(`
        SELECT CASE
          WHEN (SELECT COUNT(*) FROM users) > 100 THEN 'large'
          WHEN (SELECT COUNT(*) FROM users) > 1 THEN 'medium'
          ELSE 'small'
        END as size
      `);
      const size = (rows[0] as { size: string }).size;
      expect(["large", "medium", "small"]).toContain(size);
    });
  });

  /**
   * @kb-entry postgresql/conditional-statements
   * @kb-section Boolean Type
   */
  describe("Boolean type", () => {
    test("Literal true/false values", async () => {
      const { rows } = await directSQLExpectSuccess("SELECT true as t, false as f");
      const row = rows[0] as { t: boolean; f: boolean };
      expect(row.t).toBe(true);
      expect(row.f).toBe(false);
    });

    test("String to boolean casting 'yes'", async () => {
      const { rows } = await directSQLExpectSuccess("SELECT 'yes'::boolean as result");
      expect((rows[0] as { result: boolean }).result).toBe(true);
    });

    test("String to boolean casting 'no'", async () => {
      const { rows } = await directSQLExpectSuccess("SELECT 'no'::boolean as result");
      expect((rows[0] as { result: boolean }).result).toBe(false);
    });

    test("Integer to boolean casting 1", async () => {
      const { rows } = await directSQLExpectSuccess("SELECT 1::boolean as result");
      expect((rows[0] as { result: boolean }).result).toBe(true);
    });

    test("Integer to boolean casting 0", async () => {
      const { rows } = await directSQLExpectSuccess("SELECT 0::boolean as result");
      expect((rows[0] as { result: boolean }).result).toBe(false);
    });
  });

  /**
   * @kb-entry postgresql/conditional-statements
   * @kb-section COALESCE Function
   */
  describe("COALESCE function", () => {
    test("COALESCE returns first non-null value", async () => {
      const { rows } = await directSQLExpectSuccess(
        "SELECT COALESCE(NULL, NULL, 'default') as result"
      );
      expect((rows[0] as { result: string }).result).toBe("default");
    });

    test("COALESCE with column value", async () => {
      const { rows } = await directSQLExpectSuccess(
        "SELECT COALESCE(username, 'anonymous') as name FROM users LIMIT 1"
      );
      expect((rows[0] as { name: string }).name).toBeTruthy();
    });
  });

  /**
   * @kb-entry postgresql/conditional-statements
   * @kb-section NULLIF Function
   */
  describe("NULLIF function", () => {
    test("NULLIF returns NULL when values equal", async () => {
      const { rows } = await directSQLExpectSuccess("SELECT NULLIF(1, 1) as result");
      expect((rows[0] as { result: number | null }).result).toBeNull();
    });

    test("NULLIF returns first value when not equal", async () => {
      const { rows } = await directSQLExpectSuccess("SELECT NULLIF(1, 2) as result");
      expect((rows[0] as { result: number }).result).toBe(1);
    });
  });

  /**
   * @kb-entry postgresql/conditional-statements
   * @kb-section GREATEST and LEAST Functions
   */
  describe("GREATEST and LEAST functions", () => {
    test("GREATEST returns maximum value", async () => {
      const { rows } = await directSQLExpectSuccess("SELECT GREATEST(1, 2, 3) as result");
      expect((rows[0] as { result: number }).result).toBe(3);
    });

    test("LEAST returns minimum value", async () => {
      const { rows } = await directSQLExpectSuccess("SELECT LEAST(1, 2, 3) as result");
      expect((rows[0] as { result: number }).result).toBe(1);
    });
  });

  /**
   * @kb-entry postgresql/conditional-statements
   * @kb-section Boolean-Based Blind Injection
   */
  describe("Boolean-based blind injection patterns", () => {
    test("CASE WHEN for character extraction", async () => {
      const { rows } = await directSQLExpectSuccess(`
        SELECT CASE
          WHEN SUBSTRING(current_database(),1,1)='v'
          THEN true
          ELSE false
        END as result
      `);
      expect((rows[0] as { result: boolean }).result).toBe(true);
    });

    test("CASE WHEN for existence check", async () => {
      const { rows } = await directSQLExpectSuccess(`
        SELECT CASE
          WHEN (SELECT COUNT(*) FROM users WHERE username='admin') > 0
          THEN true
          ELSE false
        END as result
      `);
      expect(typeof (rows[0] as { result: boolean }).result).toBe("boolean");
    });
  });

  /**
   * @kb-entry postgresql/conditional-statements
   * @kb-section Conditional Error-Based
   */
  describe("Conditional error-based injection", () => {
    test("CASE WHEN true triggers division by zero", async () => {
      const error = await directSQLExpectError("SELECT CASE WHEN (1=1) THEN 1/0 ELSE 1 END");
      expect(error.message).toMatch(/division by zero/i);
    });

    test("CASE WHEN false avoids error", async () => {
      // Use consistent types (integer) to avoid type coercion issues
      const { rows } = await directSQLExpectSuccess(
        "SELECT CASE WHEN (1=2) THEN 1/0 ELSE 999 END as result"
      );
      expect((rows[0] as { result: number }).result).toBe(999);
    });
  });

  /**
   * @kb-entry postgresql/conditional-statements
   * @kb-section Case-Sensitive Comparisons
   */
  describe("Case-sensitive comparisons", () => {
    test("Direct comparison is case-sensitive", async () => {
      const { rows } = await directSQLExpectSuccess(
        "SELECT CASE WHEN 'Admin' = 'admin' THEN 'match' ELSE 'no match' END as result"
      );
      expect((rows[0] as { result: string }).result).toBe("no match");
    });

    test("LOWER() enables case-insensitive comparison", async () => {
      const { rows } = await directSQLExpectSuccess(
        "SELECT CASE WHEN LOWER('Admin') = 'admin' THEN 'match' ELSE 'no match' END as result"
      );
      expect((rows[0] as { result: string }).result).toBe("match");
    });
  });
});
