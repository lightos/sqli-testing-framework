/**
 * PostgreSQL Constants Tests
 *
 * @kb-coverage postgresql/constants - Full coverage
 */

import { describe, test, expect, beforeAll, afterAll } from "vitest";
import {
  initDirectRunner,
  cleanupDirectRunner,
  directSQLExpectSuccess,
} from "../../src/runner/direct.js";
import { logger } from "../../src/utils/logger.js";

describe("PostgreSQL Constants", () => {
  beforeAll(async () => {
    logger.setLevel("warn");
    await initDirectRunner();
  }, 30000);

  afterAll(async () => {
    await cleanupDirectRunner();
  }, 10000);

  /**
   * @kb-entry postgresql/constants
   * @kb-section Numeric Constants
   */
  describe("Numeric constants", () => {
    test("Integer constant", async () => {
      const { rows } = await directSQLExpectSuccess("SELECT 1234 as num");
      expect((rows[0] as { num: number }).num).toBe(1234);
    });

    test("Negative integer constant", async () => {
      const { rows } = await directSQLExpectSuccess("SELECT -123 as num");
      expect((rows[0] as { num: number }).num).toBe(-123);
    });

    test("Decimal constant", async () => {
      const { rows } = await directSQLExpectSuccess("SELECT 123.45 as num");
      expect(parseFloat((rows[0] as { num: string }).num)).toBeCloseTo(123.45);
    });

    test("Scientific notation constant", async () => {
      const { rows } = await directSQLExpectSuccess("SELECT 1.23e2 as num");
      expect(parseFloat((rows[0] as { num: string }).num)).toBeCloseTo(123);
    });

    test("Boolean true constant", async () => {
      const { rows } = await directSQLExpectSuccess("SELECT true as val");
      expect((rows[0] as { val: boolean }).val).toBe(true);
    });

    test("Boolean false constant", async () => {
      const { rows } = await directSQLExpectSuccess("SELECT false as val");
      expect((rows[0] as { val: boolean }).val).toBe(false);
    });
  });

  /**
   * @kb-entry postgresql/constants
   * @kb-section String Constants
   */
  describe("String constants", () => {
    test("Single quote string", async () => {
      const { rows } = await directSQLExpectSuccess("SELECT 'text' as str");
      expect((rows[0] as { str: string }).str).toBe("text");
    });

    test("Dollar quote string", async () => {
      const { rows } = await directSQLExpectSuccess("SELECT $$text$$ as str");
      expect((rows[0] as { str: string }).str).toBe("text");
    });

    test("Tagged dollar quote string", async () => {
      const { rows } = await directSQLExpectSuccess("SELECT $x$text$x$ as str");
      expect((rows[0] as { str: string }).str).toBe("text");
    });

    test("Dollar quote with nested quotes", async () => {
      const { rows } = await directSQLExpectSuccess(
        "SELECT $outer$This has 'single' quotes$outer$ as str"
      );
      expect((rows[0] as { str: string }).str).toBe("This has 'single' quotes");
    });

    test("Escape string with newline", async () => {
      const { rows } = await directSQLExpectSuccess("SELECT E'line1\\nline2' as str");
      expect((rows[0] as { str: string }).str).toContain("\n");
    });
  });

  /**
   * @kb-entry postgresql/constants
   * @kb-section Special Constants
   */
  describe("Special constants", () => {
    test("NULL constant", async () => {
      const { rows } = await directSQLExpectSuccess("SELECT NULL as val");
      expect((rows[0] as { val: null }).val).toBeNull();
    });

    test("CURRENT_TIMESTAMP constant", async () => {
      const { rows } = await directSQLExpectSuccess("SELECT CURRENT_TIMESTAMP as ts");
      expect((rows[0] as { ts: Date }).ts).toBeTruthy();
    });

    test("CURRENT_DATE constant", async () => {
      const { rows } = await directSQLExpectSuccess("SELECT CURRENT_DATE as dt");
      expect((rows[0] as { dt: Date }).dt).toBeTruthy();
    });

    test("CURRENT_TIME constant", async () => {
      const { rows } = await directSQLExpectSuccess("SELECT CURRENT_TIME as tm");
      expect((rows[0] as { tm: string }).tm).toBeTruthy();
    });
  });

  /**
   * @kb-entry postgresql/constants
   * @kb-section System Information Functions
   */
  describe("System information functions", () => {
    test("version() function", async () => {
      const { rows } = await directSQLExpectSuccess("SELECT version() as ver");
      expect((rows[0] as { ver: string }).ver).toMatch(/PostgreSQL/i);
    });

    test("current_database() function", async () => {
      const { rows } = await directSQLExpectSuccess("SELECT current_database() as db");
      expect((rows[0] as { db: string }).db).toBe("vulndb");
    });

    test("current_user constant", async () => {
      const { rows } = await directSQLExpectSuccess("SELECT current_user as usr");
      expect((rows[0] as { usr: string }).usr).toBeTruthy();
    });

    test("session_user constant", async () => {
      const { rows } = await directSQLExpectSuccess("SELECT session_user as usr");
      expect((rows[0] as { usr: string }).usr).toBeTruthy();
    });

    test("inet_server_port() function", async () => {
      const { rows } = await directSQLExpectSuccess("SELECT inet_server_port() as port");
      expect((rows[0] as { port: number }).port).toBeTruthy();
    });
  });

  /**
   * @kb-entry postgresql/constants
   * @kb-section Configuration Settings
   */
  describe("Configuration settings", () => {
    test("current_setting for server_version", async () => {
      const { rows } = await directSQLExpectSuccess(
        "SELECT current_setting('server_version') as ver"
      );
      expect((rows[0] as { ver: string }).ver).toBeTruthy();
    });

    test("current_setting for port", async () => {
      const { rows } = await directSQLExpectSuccess("SELECT current_setting('port') as port");
      expect((rows[0] as { port: string }).port).toBe("5432");
    });
  });

  /**
   * @kb-entry postgresql/constants
   * @kb-section Boolean Expressions
   */
  describe("Boolean expressions", () => {
    test("1=1 evaluates to true", async () => {
      const { rows } = await directSQLExpectSuccess("SELECT (1=1) as result");
      expect((rows[0] as { result: boolean }).result).toBe(true);
    });

    test("1=0 evaluates to false", async () => {
      const { rows } = await directSQLExpectSuccess("SELECT (1=0) as result");
      expect((rows[0] as { result: boolean }).result).toBe(false);
    });

    test("NULL IS NULL evaluates to true", async () => {
      const { rows } = await directSQLExpectSuccess("SELECT (NULL IS NULL) as result");
      expect((rows[0] as { result: boolean }).result).toBe(true);
    });

    test("true AND true evaluates to true", async () => {
      const { rows } = await directSQLExpectSuccess("SELECT (true AND true) as result");
      expect((rows[0] as { result: boolean }).result).toBe(true);
    });
  });

  /**
   * @kb-entry postgresql/constants
   * @kb-section String Encoding Bypasses
   */
  describe("String encoding bypasses", () => {
    test("CHR() function builds strings", async () => {
      const { rows } = await directSQLExpectSuccess(
        "SELECT CHR(97)||CHR(100)||CHR(109)||CHR(105)||CHR(110) as str"
      );
      expect((rows[0] as { str: string }).str).toBe("admin");
    });

    test("convert_from with bytea hex", async () => {
      const { rows } = await directSQLExpectSuccess(
        "SELECT convert_from('\\x61646d696e'::bytea, 'UTF8') as str"
      );
      expect((rows[0] as { str: string }).str).toBe("admin");
    });
  });

  /**
   * @kb-entry postgresql/constants
   * @kb-section Injection Context Examples
   */
  describe("Injection context examples", () => {
    test("Dollar quote bypass in WHERE clause", async () => {
      const { rows } = await directSQLExpectSuccess(
        "SELECT * FROM users WHERE username = $$admin$$"
      );
      expect(rows.length).toBeGreaterThan(0);
    });

    test("Boolean constant in OR condition", async () => {
      const { rows } = await directSQLExpectSuccess("SELECT * FROM users WHERE id = 999 OR true");
      expect(rows.length).toBeGreaterThan(0);
    });

    test("UNION with dollar quotes", async () => {
      const { rows } = await directSQLExpectSuccess(
        "SELECT id, username FROM users WHERE id = 1 UNION SELECT 999, $$injected$$"
      );
      const usernames = rows.map((r) => (r as { username: string }).username);
      expect(usernames).toContain("injected");
    });
  });
});
