/**
 * PostgreSQL Avoiding Quotations Tests
 *
 * @kb-coverage postgresql/avoiding-quotations - Full coverage
 */

import { describe, test, expect, beforeAll, afterAll } from "vitest";
import {
  initDirectRunner,
  cleanupDirectRunner,
  directSQLExpectSuccess,
} from "../../src/runner/direct.js";
import { logger } from "../../src/utils/logger.js";

describe("PostgreSQL Avoiding Quotations", () => {
  beforeAll(async () => {
    logger.setLevel("warn");
    await initDirectRunner();
  }, 30000);

  afterAll(async () => {
    await cleanupDirectRunner();
  }, 10000);

  /**
   * @kb-entry postgresql/avoiding-quotations
   * @kb-section Using CHR() Function
   */
  describe("Using CHR() function", () => {
    test("CHR() concatenation spells 'admin'", async () => {
      const { rows } = await directSQLExpectSuccess(
        "SELECT CHR(97)||CHR(100)||CHR(109)||CHR(105)||CHR(110) as word"
      );
      expect((rows[0] as { word: string }).word).toBe("admin");
    });

    test("CHR(65) returns 'A'", async () => {
      const { rows } = await directSQLExpectSuccess("SELECT CHR(65) as char");
      expect((rows[0] as { char: string }).char).toBe("A");
    });

    test("CHR(66) returns 'B'", async () => {
      const { rows } = await directSQLExpectSuccess("SELECT CHR(66) as char");
      expect((rows[0] as { char: string }).char).toBe("B");
    });

    test("CHR() spells 'root'", async () => {
      const { rows } = await directSQLExpectSuccess(
        "SELECT CHR(114)||CHR(111)||CHR(111)||CHR(116) as word"
      );
      expect((rows[0] as { word: string }).word).toBe("root");
    });

    test("CHR() spells '/etc/passwd'", async () => {
      const { rows } = await directSQLExpectSuccess(`
        SELECT CHR(47)||CHR(101)||CHR(116)||CHR(99)||CHR(47)||CHR(112)||CHR(97)||CHR(115)||CHR(115)||CHR(119)||CHR(100) as path
      `);
      expect((rows[0] as { path: string }).path).toBe("/etc/passwd");
    });
  });

  /**
   * @kb-entry postgresql/avoiding-quotations
   * @kb-section Using Dollar-Quoting
   */
  describe("Using dollar-quoting", () => {
    test("Basic dollar-quoting $$admin$$", async () => {
      const { rows } = await directSQLExpectSuccess("SELECT $$admin$$ as word");
      expect((rows[0] as { word: string }).word).toBe("admin");
    });

    test("Tagged dollar-quoting $tag$admin$tag$", async () => {
      const { rows } = await directSQLExpectSuccess("SELECT $tag$admin$tag$ as word");
      expect((rows[0] as { word: string }).word).toBe("admin");
    });

    test("Dollar-quoting in WHERE clause", async () => {
      const { rows } = await directSQLExpectSuccess(
        "SELECT * FROM users WHERE username = $$admin$$"
      );
      expect(rows.length).toBeGreaterThan(0);
    });

    test("Dollar-quoting with special characters", async () => {
      const { rows } = await directSQLExpectSuccess(
        "SELECT $$string with 'quotes' and \"double quotes\"$$ as text"
      );
      expect((rows[0] as { text: string }).text).toContain("quotes");
    });
  });

  /**
   * @kb-entry postgresql/avoiding-quotations
   * @kb-section Using Hexadecimal
   */
  describe("Using hexadecimal", () => {
    test("convert_from with hex decode for 'admin'", async () => {
      const { rows } = await directSQLExpectSuccess(
        "SELECT convert_from(decode('61646d696e', 'hex'), 'UTF8') as word"
      );
      expect((rows[0] as { word: string }).word).toBe("admin");
    });

    test("E-string escape sequence", async () => {
      const { rows } = await directSQLExpectSuccess("SELECT E'\\x61\\x64\\x6d\\x69\\x6e' as word");
      expect((rows[0] as { word: string }).word).toBe("admin");
    });
  });

  /**
   * @kb-entry postgresql/avoiding-quotations
   * @kb-section Using ASCII Values
   */
  describe("Using ASCII values", () => {
    test("ASCII() returns character code", async () => {
      const { rows } = await directSQLExpectSuccess("SELECT ASCII('A') as code");
      expect((rows[0] as { code: number }).code).toBe(65);
    });

    test("ASCII() and CHR() are inverse", async () => {
      const { rows } = await directSQLExpectSuccess(
        "SELECT CHR(ASCII('A')) as char, ASCII(CHR(65)) as code"
      );
      const row = rows[0] as { char: string; code: number };
      expect(row.char).toBe("A");
      expect(row.code).toBe(65);
    });
  });

  /**
   * @kb-entry postgresql/avoiding-quotations
   * @kb-section Injection Examples
   */
  describe("Injection examples without quotes", () => {
    test("Query user with CHR() instead of quotes", async () => {
      const { rows } = await directSQLExpectSuccess(
        "SELECT * FROM users WHERE username=CHR(97)||CHR(100)||CHR(109)||CHR(105)||CHR(110)"
      );
      expect(rows.length).toBeGreaterThan(0);
      expect((rows[0] as { username: string }).username).toBe("admin");
    });

    test("Query user with dollar-quoting", async () => {
      const { rows } = await directSQLExpectSuccess("SELECT * FROM users WHERE username=$$admin$$");
      expect(rows.length).toBeGreaterThan(0);
    });

    test("UNION SELECT with CHR()", async () => {
      const { rows } = await directSQLExpectSuccess(`
        SELECT id, username FROM users WHERE id = 1
        UNION SELECT 999, CHR(97)||CHR(100)||CHR(109)||CHR(105)||CHR(110)
      `);
      const values = rows.map((r) => (r as { username: string }).username);
      expect(values).toContain("admin");
    });
  });

  /**
   * @kb-entry postgresql/avoiding-quotations
   * @kb-section Building Complex Strings
   */
  describe("Building complex strings", () => {
    test("Build SQL keyword without quotes", async () => {
      // Build 'SELECT' using CHR()
      const { rows } = await directSQLExpectSuccess(`
        SELECT CHR(83)||CHR(69)||CHR(76)||CHR(69)||CHR(67)||CHR(84) as keyword
      `);
      expect((rows[0] as { keyword: string }).keyword).toBe("SELECT");
    });

    test("Build table name without quotes", async () => {
      // Build 'users' using CHR()
      const { rows } = await directSQLExpectSuccess(`
        SELECT CHR(117)||CHR(115)||CHR(101)||CHR(114)||CHR(115) as tablename
      `);
      expect((rows[0] as { tablename: string }).tablename).toBe("users");
    });

    test("Combine multiple encoding techniques", async () => {
      const { rows } = await directSQLExpectSuccess(`
        SELECT
          CHR(97)||CHR(100)||CHR(109)||CHR(105)||CHR(110) as chr_method,
          $$admin$$ as dollar_method,
          convert_from(decode('61646d696e', 'hex'), 'UTF8') as hex_method
      `);
      const row = rows[0] as { chr_method: string; dollar_method: string; hex_method: string };
      expect(row.chr_method).toBe("admin");
      expect(row.dollar_method).toBe("admin");
      expect(row.hex_method).toBe("admin");
    });
  });
});
