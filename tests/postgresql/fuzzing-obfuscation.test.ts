/**
 * PostgreSQL Fuzzing and Obfuscation Tests
 *
 * @kb-coverage postgresql/fuzzing-obfuscation - Full coverage
 */

import { describe, test, expect, beforeAll, afterAll } from "vitest";
import {
  initDirectRunner,
  cleanupDirectRunner,
  directSQLExpectSuccess,
  directSQL,
} from "../../src/runner/direct.js";
import { logger } from "../../src/utils/logger.js";

describe("PostgreSQL Fuzzing and Obfuscation", () => {
  beforeAll(async () => {
    logger.setLevel("warn");
    await initDirectRunner();
  }, 30000);

  afterAll(async () => {
    await cleanupDirectRunner();
  }, 10000);

  /**
   * @kb-entry postgresql/fuzzing-obfuscation
   * @kb-section Comment Variations
   */
  describe("Comment variations", () => {
    test("Line comment (--)", async () => {
      const { rows } = await directSQLExpectSuccess(
        "SELECT * FROM users WHERE id = 1 -- this is a comment"
      );
      expect(rows.length).toBeGreaterThan(0);
    });

    test("Block comment (/* */)", async () => {
      const { rows } = await directSQLExpectSuccess(
        "SELECT * FROM users /* comment */ WHERE id = 1"
      );
      expect(rows.length).toBeGreaterThan(0);
    });

    test("Inline comments for obfuscation", async () => {
      const { rows } = await directSQLExpectSuccess(
        "SELECT/*comment*/username/**/FROM/**/users WHERE id = 1"
      );
      expect(rows.length).toBeGreaterThan(0);
    });

    test("Nested comments", async () => {
      const { rows } = await directSQLExpectSuccess(
        "SELECT /* outer /* nested */ comment */ username FROM users WHERE id = 1"
      );
      expect(rows.length).toBeGreaterThan(0);
    });
  });

  /**
   * @kb-entry postgresql/fuzzing-obfuscation
   * @kb-section Dollar Quote Obfuscation
   */
  describe("Dollar quote obfuscation", () => {
    test("Standard dollar quotes bypass single quote filters", async () => {
      const { rows } = await directSQLExpectSuccess(
        "SELECT * FROM users WHERE username = $$admin$$"
      );
      expect(rows.length).toBeGreaterThan(0);
    });

    test("Tagged dollar quotes", async () => {
      const { rows } = await directSQLExpectSuccess(
        "SELECT * FROM users WHERE username = $x$admin$x$"
      );
      expect(rows.length).toBeGreaterThan(0);
    });

    test("Dollar quotes in UNION injection", async () => {
      const { rows } = await directSQLExpectSuccess(
        "SELECT id, username FROM users WHERE id = 1 UNION SELECT 999, $$injected$$"
      );
      const usernames = rows.map((r) => (r as { username: string }).username);
      expect(usernames).toContain("injected");
    });
  });

  /**
   * @kb-entry postgresql/fuzzing-obfuscation
   * @kb-section Case Variation
   */
  describe("Case variation", () => {
    test("Lowercase keywords", async () => {
      const { rows } = await directSQLExpectSuccess("select username from users where id = 1");
      expect(rows.length).toBeGreaterThan(0);
    });

    test("Uppercase keywords", async () => {
      const { rows } = await directSQLExpectSuccess("SELECT USERNAME FROM USERS WHERE ID = 1");
      expect(rows.length).toBeGreaterThan(0);
    });

    test("Mixed case keywords", async () => {
      const { rows } = await directSQLExpectSuccess("SeLeCt UsErNaMe FrOm UsErS wHeRe Id = 1");
      expect(rows.length).toBeGreaterThan(0);
    });
  });

  /**
   * @kb-entry postgresql/fuzzing-obfuscation
   * @kb-section String Representation Alternatives
   */
  describe("String representation alternatives", () => {
    test("CHR() function avoids quotes", async () => {
      const { rows } = await directSQLExpectSuccess(
        "SELECT * FROM users WHERE username = CHR(97)||CHR(100)||CHR(109)||CHR(105)||CHR(110)"
      );
      expect(rows.length).toBeGreaterThan(0);
    });

    test("convert_from with bytea hex", async () => {
      const { rows } = await directSQLExpectSuccess(
        "SELECT * FROM users WHERE username = convert_from('\\x61646d696e'::bytea, 'UTF8')"
      );
      expect(rows.length).toBeGreaterThan(0);
    });

    test("Escape string syntax", async () => {
      const { rows } = await directSQLExpectSuccess("SELECT E'\\x61\\x64\\x6d\\x69\\x6e' as str");
      expect((rows[0] as { str: string }).str).toBe("admin");
    });
  });

  /**
   * @kb-entry postgresql/fuzzing-obfuscation
   * @kb-section Numeric Representation
   */
  describe("Numeric representation", () => {
    test("Mathematical expression for number", async () => {
      const { rows } = await directSQLExpectSuccess("SELECT * FROM users WHERE id = 2-1");
      expect(rows.length).toBeGreaterThan(0);
    });

    test("Cast from string", async () => {
      const { rows } = await directSQLExpectSuccess("SELECT * FROM users WHERE id = '1'::int");
      expect(rows.length).toBeGreaterThan(0);
    });

    test("Boolean to int conversion", async () => {
      const { rows } = await directSQLExpectSuccess("SELECT * FROM users WHERE id = true::int");
      expect(rows.length).toBeGreaterThan(0);
    });
  });

  /**
   * @kb-entry postgresql/fuzzing-obfuscation
   * @kb-section Function Call Variations
   */
  describe("Function call variations", () => {
    test("SUBSTRING standard syntax", async () => {
      const { rows } = await directSQLExpectSuccess("SELECT SUBSTRING('admin', 1, 3) as sub");
      expect((rows[0] as { sub: string }).sub).toBe("adm");
    });

    test("SUBSTRING FROM/FOR syntax", async () => {
      const { rows } = await directSQLExpectSuccess(
        "SELECT SUBSTRING('admin' FROM 1 FOR 3) as sub"
      );
      expect((rows[0] as { sub: string }).sub).toBe("adm");
    });

    test("SUBSTR alternative", async () => {
      const { rows } = await directSQLExpectSuccess("SELECT SUBSTR('admin', 1, 3) as sub");
      expect((rows[0] as { sub: string }).sub).toBe("adm");
    });

    test("LEFT function alternative", async () => {
      const { rows } = await directSQLExpectSuccess("SELECT LEFT('admin', 3) as sub");
      expect((rows[0] as { sub: string }).sub).toBe("adm");
    });
  });

  /**
   * @kb-entry postgresql/fuzzing-obfuscation
   * @kb-section UNION Query Obfuscation
   */
  describe("UNION query obfuscation", () => {
    test("UNION ALL avoids DISTINCT", async () => {
      const { rows } = await directSQLExpectSuccess(
        "SELECT id, username FROM users WHERE id = 1 UNION ALL SELECT 1, 'test'"
      );
      expect(rows.length).toBeGreaterThan(1);
    });

    test("UNION with redundant conditions", async () => {
      const { rows } = await directSQLExpectSuccess(
        "SELECT id, username FROM users WHERE 1=1 AND id = 1 UNION SELECT 999, 'test' WHERE 1=1"
      );
      expect(rows.length).toBeGreaterThan(1);
    });

    test("Nested UNION query", async () => {
      const { rows } = await directSQLExpectSuccess(
        "SELECT * FROM (SELECT id, username FROM users WHERE id = 1 UNION SELECT 999, 'test') AS t"
      );
      expect(rows.length).toBeGreaterThan(1);
    });
  });

  /**
   * @kb-entry postgresql/fuzzing-obfuscation
   * @kb-section Keyword Splitting Limitations
   *
   * Note: Unlike MySQL, PostgreSQL does NOT support splitting keywords with comments.
   * SEL[comment]ECT does NOT work in PostgreSQL - keywords must be intact.
   */
  describe("Keyword splitting limitations (PostgreSQL vs MySQL)", () => {
    test("PostgreSQL requires intact keywords (no splitting)", async () => {
      // Unlike MySQL, PostgreSQL doesn't allow SEL/**/ECT
      // This test verifies that keywords work when intact
      const { rows } = await directSQLExpectSuccess(
        "SELECT/**/ username /**/FROM/**/ users WHERE id = 1"
      );
      expect(rows.length).toBeGreaterThan(0);
    });

    test("Comments between keywords work (not within)", async () => {
      // Comments BETWEEN keywords work, but not WITHIN keywords
      const { rows } = await directSQLExpectSuccess(
        "SELECT /**/ id, /**/ username /**/ FROM /**/ users /**/ WHERE id = 1"
      );
      expect(rows.length).toBeGreaterThan(0);
    });
  });

  /**
   * @kb-entry postgresql/fuzzing-obfuscation
   * @kb-section Alternative SQL Constructs
   */
  describe("Alternative SQL constructs", () => {
    test("OR true instead of OR 1=1", async () => {
      const { rows } = await directSQLExpectSuccess("SELECT * FROM users WHERE id = 999 OR true");
      expect(rows.length).toBeGreaterThan(0);
    });

    test("OR NOT false", async () => {
      const { rows } = await directSQLExpectSuccess(
        "SELECT * FROM users WHERE id = 999 OR NOT false"
      );
      expect(rows.length).toBeGreaterThan(0);
    });

    test("Boolean cast in condition", async () => {
      const { rows } = await directSQLExpectSuccess(
        "SELECT * FROM users WHERE id = 999 OR 1::boolean"
      );
      expect(rows.length).toBeGreaterThan(0);
    });
  });

  /**
   * @kb-entry postgresql/fuzzing-obfuscation
   * @kb-section PostgreSQL-Specific Bypasses
   */
  describe("PostgreSQL-specific bypasses", () => {
    test("Array contains operator", async () => {
      const { rows } = await directSQLExpectSuccess(
        "SELECT * FROM users WHERE ARRAY[id] @> ARRAY[1]"
      );
      expect(rows.length).toBeGreaterThan(0);
    });

    test("ANY with array", async () => {
      const { rows } = await directSQLExpectSuccess(
        "SELECT * FROM users WHERE id = ANY('{1,2,3}'::int[])"
      );
      expect(rows.length).toBeGreaterThan(0);
    });

    test("Regex operator instead of LIKE", async () => {
      const { rows } = await directSQLExpectSuccess(
        "SELECT * FROM users WHERE username ~ '^admin'"
      );
      expect(rows.length).toBeGreaterThan(0);
    });

    test("Case-insensitive regex", async () => {
      const { rows } = await directSQLExpectSuccess(
        "SELECT * FROM users WHERE username ~* 'ADMIN'"
      );
      expect(rows.length).toBeGreaterThan(0);
    });
  });

  /**
   * @kb-entry postgresql/fuzzing-obfuscation
   * @kb-section Using Subqueries
   */
  describe("Using subqueries", () => {
    test("Subquery in WHERE clause", async () => {
      const { rows } = await directSQLExpectSuccess("SELECT * FROM users WHERE id = (SELECT 1)");
      expect(rows.length).toBeGreaterThan(0);
    });

    test("WITH clause (CTE)", async () => {
      const { rows } = await directSQLExpectSuccess(
        "WITH t AS (SELECT 1 AS id) SELECT * FROM users, t WHERE users.id = t.id"
      );
      expect(rows.length).toBeGreaterThan(0);
    });

    test("EXISTS subquery", async () => {
      const { rows } = await directSQLExpectSuccess(
        "SELECT * FROM users u WHERE EXISTS (SELECT 1 WHERE u.id = 1)"
      );
      expect(rows.length).toBeGreaterThan(0);
    });
  });

  /**
   * @kb-entry postgresql/fuzzing-obfuscation
   * @kb-section DO $$ Block WAF Bypass
   */
  describe("DO $$ Block WAF Bypass", () => {
    test("Execute basic DO block", async () => {
      // Basic anonymous block execution
      const { success } = await directSQL("DO $$ BEGIN RAISE NOTICE 'test'; END $$");
      expect(success).toBe(true);
    });

    test("Execute dynamic SQL in DO block", async () => {
      // Logic that might bypass WAFs by hiding keywords
      const { success } = await directSQL(`
        DO $$
        DECLARE
          ver text;
        BEGIN
          EXECUTE 'SELECT version()' INTO ver;
          -- We can't easily return data from DO block to client without side channels
          -- but success indicates the code ran
        END $$;
      `);
      expect(success).toBe(true);
    });

    test("Construct commands with CHR() in DO block", async () => {
      const { success } = await directSQL(`
        DO $$
        DECLARE
          cmd text;
        BEGIN
          -- Construct 'SELECT 1' via CHR
          cmd := CHR(83)||CHR(69)||CHR(76)||CHR(69)||CHR(67)||CHR(84)||' 1';
          EXECUTE cmd;
        END $$;
      `);
      expect(success).toBe(true);
    });
  });
});
