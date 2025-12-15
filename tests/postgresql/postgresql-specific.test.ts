/**
 * PostgreSQL-specific Code Tests
 *
 * @kb-coverage postgresql/postgresql-specific-code - Full coverage
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

describe("PostgreSQL-specific Code", () => {
  beforeAll(async () => {
    logger.setLevel("warn");
    await initDirectRunner();
  }, 30000);

  afterAll(async () => {
    await cleanupDirectRunner();
  }, 10000);

  /**
   * @kb-entry postgresql/postgresql-specific-code
   * @kb-section Dollar-Quoted Strings
   */
  describe("Dollar-quoted strings", () => {
    test("Standard dollar quotes", async () => {
      const { rows } = await directSQLExpectSuccess("SELECT $$admin$$ as str");
      expect((rows[0] as { str: string }).str).toBe("admin");
    });

    test("Tagged dollar quotes", async () => {
      const { rows } = await directSQLExpectSuccess("SELECT $tag$admin$tag$ as str");
      expect((rows[0] as { str: string }).str).toBe("admin");
    });

    test("Nested dollar quotes", async () => {
      const { rows } = await directSQLExpectSuccess(
        "SELECT $outer$Contains $$inner$$ quotes$outer$ as str"
      );
      expect((rows[0] as { str: string }).str).toBe("Contains $$inner$$ quotes");
    });

    test("Dollar quotes in WHERE clause", async () => {
      const { rows } = await directSQLExpectSuccess(
        "SELECT * FROM users WHERE username = $$admin$$"
      );
      expect(rows.length).toBeGreaterThan(0);
    });
  });

  /**
   * @kb-entry postgresql/postgresql-specific-code
   * @kb-section Type Cast Shorthand
   */
  describe("Type cast shorthand (::)", () => {
    test("String to int cast", async () => {
      const { rows } = await directSQLExpectSuccess("SELECT '42'::int as num");
      expect((rows[0] as { num: number }).num).toBe(42);
    });

    test("Int to boolean cast", async () => {
      const { rows } = await directSQLExpectSuccess("SELECT 1::boolean as bool");
      expect((rows[0] as { bool: boolean }).bool).toBe(true);
    });

    test("String to inet cast", async () => {
      const { rows } = await directSQLExpectSuccess("SELECT '192.168.1.1'::inet as ip");
      expect((rows[0] as { ip: string }).ip).toBe("192.168.1.1");
    });

    test("Array cast", async () => {
      const { rows } = await directSQLExpectSuccess("SELECT '{1,2,3}'::int[] as arr");
      expect((rows[0] as { arr: number[] }).arr).toEqual([1, 2, 3]);
    });
  });

  /**
   * @kb-entry postgresql/postgresql-specific-code
   * @kb-section RETURNING Clause
   */
  describe("RETURNING clause", () => {
    test("INSERT with RETURNING", async () => {
      const { rows } = await directSQLExpectSuccess(
        "INSERT INTO products (name, price) VALUES ('test_product', 9.99) RETURNING id, name"
      );
      expect((rows[0] as { name: string }).name).toBe("test_product");
      // Clean up
      await directSQL(`DELETE FROM products WHERE name = 'test_product'`);
    });

    test("UPDATE with RETURNING", async () => {
      // Create test row
      await directSQL("INSERT INTO products (name, price) VALUES ('return_test', 1.00)");
      const { rows } = await directSQLExpectSuccess(
        "UPDATE products SET price = 2.00 WHERE name = 'return_test' RETURNING name, price"
      );
      expect(parseFloat((rows[0] as { price: string }).price)).toBe(2);
      // Clean up
      await directSQL("DELETE FROM products WHERE name = 'return_test'");
    });

    test("DELETE with RETURNING", async () => {
      // Create test row
      await directSQL("INSERT INTO products (name, price) VALUES ('delete_test', 1.00)");
      const { rows } = await directSQLExpectSuccess(
        "DELETE FROM products WHERE name = 'delete_test' RETURNING name"
      );
      expect((rows[0] as { name: string }).name).toBe("delete_test");
    });
  });

  /**
   * @kb-entry postgresql/postgresql-specific-code
   * @kb-section Array Syntax
   */
  describe("Array syntax", () => {
    test("ARRAY literal", async () => {
      const { rows } = await directSQLExpectSuccess("SELECT ARRAY[1, 2, 3] as arr");
      expect((rows[0] as { arr: number[] }).arr).toEqual([1, 2, 3]);
    });

    test("Array access (1-indexed)", async () => {
      const { rows } = await directSQLExpectSuccess("SELECT (ARRAY['a','b','c'])[1] as elem");
      expect((rows[0] as { elem: string }).elem).toBe("a");
    });

    test("array_agg function", async () => {
      const { rows } = await directSQLExpectSuccess(
        "SELECT array_agg(username) as users FROM (SELECT username FROM users LIMIT 5) sub"
      );
      expect(Array.isArray((rows[0] as { users: string[] }).users)).toBe(true);
    });

    test("unnest function", async () => {
      const { rows } = await directSQLExpectSuccess("SELECT unnest(ARRAY[1,2,3]) as num");
      expect(rows.length).toBe(3);
    });

    test("array_to_string for aggregation", async () => {
      const { rows } = await directSQLExpectSuccess(
        "SELECT array_to_string(array_agg(username), ':') as users FROM users WHERE id <= 2"
      );
      expect((rows[0] as { users: string }).users).toContain(":");
    });
  });

  /**
   * @kb-entry postgresql/postgresql-specific-code
   * @kb-section PostgreSQL-specific Functions
   */
  describe("PostgreSQL-specific functions", () => {
    test("string_agg function", async () => {
      const { rows } = await directSQLExpectSuccess(
        "SELECT string_agg(username, ',') as users FROM users WHERE id <= 3"
      );
      expect((rows[0] as { users: string }).users).toContain(",");
    });

    test("generate_series function", async () => {
      const { rows } = await directSQLExpectSuccess("SELECT generate_series(1, 5) as num");
      expect(rows.length).toBe(5);
    });

    test("regexp_matches function", async () => {
      const { rows } = await directSQLExpectSuccess(
        "SELECT regexp_matches('admin123', '([a-z]+)([0-9]+)') as matches"
      );
      expect((rows[0] as { matches: string[] }).matches).toContain("admin");
    });

    test("regexp_replace function", async () => {
      const { rows } = await directSQLExpectSuccess(
        "SELECT regexp_replace('admin123', '[0-9]', 'X', 'g') as result"
      );
      expect((rows[0] as { result: string }).result).toBe("adminXXX");
    });
  });

  /**
   * @kb-entry postgresql/postgresql-specific-code
   * @kb-section Error-Based Data Extraction
   */
  describe("Error-based data extraction", () => {
    test("CAST reveals data in error", async () => {
      const error = await directSQLExpectError("SELECT CAST(version() AS int)");
      expect(error.message).toMatch(/PostgreSQL/i);
    });

    test(":: shorthand reveals data in error", async () => {
      const error = await directSQLExpectError(
        "SELECT (SELECT password FROM users WHERE username='admin' LIMIT 1)::int"
      );
      expect(error.message).toMatch(/invalid input syntax/i);
    });

    test("Error markers for extraction", async () => {
      const error = await directSQLExpectError("SELECT ('~' || current_database() || '~')::int");
      expect(error.message).toMatch(/~vulndb~/i);
    });
  });

  /**
   * @kb-entry postgresql/postgresql-specific-code
   * @kb-section Conditional Expressions
   */
  describe("Conditional expressions", () => {
    test("CASE WHEN expression", async () => {
      const { rows } = await directSQLExpectSuccess(
        "SELECT CASE WHEN 1=1 THEN 'true' ELSE 'false' END as result"
      );
      expect((rows[0] as { result: string }).result).toBe("true");
    });

    test("COALESCE function", async () => {
      const { rows } = await directSQLExpectSuccess("SELECT COALESCE(NULL, 'default') as result");
      expect((rows[0] as { result: string }).result).toBe("default");
    });

    test("NULLIF function", async () => {
      const { rows } = await directSQLExpectSuccess("SELECT NULLIF(1, 1) as result");
      expect((rows[0] as { result: null }).result).toBeNull();
    });
  });

  /**
   * @kb-entry postgresql/postgresql-specific-code
   * @kb-section Regular Expression Operators
   */
  describe("Regular expression operators", () => {
    test("POSIX regex match (~)", async () => {
      const { rows } = await directSQLExpectSuccess("SELECT 'admin' ~ '^a' as result");
      expect((rows[0] as { result: boolean }).result).toBe(true);
    });

    test("Case-insensitive regex (~*)", async () => {
      const { rows } = await directSQLExpectSuccess("SELECT 'admin' ~* '^A' as result");
      expect((rows[0] as { result: boolean }).result).toBe(true);
    });

    test("Regex not match (!~)", async () => {
      const { rows } = await directSQLExpectSuccess("SELECT 'admin' !~ '^b' as result");
      expect((rows[0] as { result: boolean }).result).toBe(true);
    });
  });

  /**
   * @kb-entry postgresql/postgresql-specific-code
   * @kb-section Session Variables
   */
  describe("Session variables", () => {
    test("current_setting function", async () => {
      const { rows } = await directSQLExpectSuccess(
        "SELECT current_setting('server_version') as ver"
      );
      expect((rows[0] as { ver: string }).ver).toBeTruthy();
    });

    test("SHOW command", async () => {
      const { rows } = await directSQLExpectSuccess("SHOW server_version");
      expect((rows[0] as { server_version: string }).server_version).toBeTruthy();
    });
  });

  /**
   * @kb-entry postgresql/postgresql-specific-code
   * @kb-section PostgreSQL Information Tables
   */
  describe("PostgreSQL information tables", () => {
    test("pg_tables catalog", async () => {
      const { rows } = await directSQLExpectSuccess(
        "SELECT tablename FROM pg_tables WHERE schemaname = 'public' LIMIT 5"
      );
      expect(rows.length).toBeGreaterThan(0);
    });

    test("pg_database catalog", async () => {
      const { rows } = await directSQLExpectSuccess("SELECT datname FROM pg_database LIMIT 5");
      expect(rows.length).toBeGreaterThan(0);
    });

    test("pg_roles catalog", async () => {
      const { rows } = await directSQLExpectSuccess("SELECT rolname FROM pg_roles LIMIT 5");
      expect(rows.length).toBeGreaterThan(0);
    });
  });
});
