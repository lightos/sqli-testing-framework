/**
 * PostgreSQL Comment Out Query Tests
 *
 * Tests for SQL comment syntax used to comment out query remainders.
 *
 * @kb-coverage postgresql/comment-out-query - Full coverage
 */

import { describe, test, expect, beforeAll, afterAll } from "vitest";
import {
  initDirectRunner,
  cleanupDirectRunner,
  directSQL,
  directSQLExpectSuccess,
} from "../../src/runner/direct.js";
import { logger } from "../../src/utils/logger.js";

describe("PostgreSQL Comment Out Query", () => {
  beforeAll(async () => {
    logger.setLevel("warn");
    await initDirectRunner();
  }, 30000);

  afterAll(async () => {
    await cleanupDirectRunner();
  }, 10000);

  /**
   * @kb-entry postgresql/comment-out-query
   * @kb-section Line Comments (--)
   */
  describe("Line comments (--)", () => {
    test("Double dash comments out rest of line", async () => {
      const { rows } = await directSQLExpectSuccess("SELECT 1 as num -- this is commented out");
      expect((rows[0] as { num: number }).num).toBe(1);
    });

    test("Double dash in WHERE clause injection", async () => {
      const { rows } = await directSQLExpectSuccess(
        "SELECT * FROM users WHERE id = 1 -- AND password = 'wrong'"
      );
      expect(rows.length).toBeGreaterThan(0);
    });

    test("Double dash with OR 1=1 bypass", async () => {
      const { rows } = await directSQLExpectSuccess(
        "SELECT * FROM users WHERE username = 'nonexistent' OR 1=1 --'"
      );
      expect(rows.length).toBeGreaterThan(0);
    });

    test("Double dash requires space or end of string", async () => {
      // -- without space is still a comment in PostgreSQL
      const { rows } = await directSQLExpectSuccess("SELECT 1 as num--comment");
      expect((rows[0] as { num: number }).num).toBe(1);
    });
  });

  /**
   * @kb-entry postgresql/comment-out-query
   * @kb-section Block Comments
   */
  describe("Block comments (/* */)", () => {
    test("Block comment inline", async () => {
      const { rows } = await directSQLExpectSuccess("SELECT /* this is a comment */ 1 as num");
      expect((rows[0] as { num: number }).num).toBe(1);
    });

    test("Block comment to end query", async () => {
      const { rows } = await directSQLExpectSuccess(
        "SELECT * FROM users WHERE id = 1 /*' AND password = ''*/"
      );
      expect(rows.length).toBeGreaterThan(0);
    });

    test("Block comment replacing spaces", async () => {
      const { rows } = await directSQLExpectSuccess("SELECT/**/1/**/as/**/num");
      expect((rows[0] as { num: number }).num).toBe(1);
    });

    test("Block comment between keywords", async () => {
      const { rows } = await directSQLExpectSuccess(
        "SELECT/**/*/**/FROM/**/users/**/WHERE/**/id/**/=/**/1"
      );
      expect(rows.length).toBeGreaterThan(0);
    });
  });

  /**
   * @kb-entry postgresql/comment-out-query
   * @kb-section Nested Block Comments
   */
  describe("Nested block comments (PostgreSQL specific)", () => {
    test("PostgreSQL supports nested comments", async () => {
      const { rows } = await directSQLExpectSuccess(
        "SELECT /* outer /* nested */ comment */ 1 as num"
      );
      expect((rows[0] as { num: number }).num).toBe(1);
    });

    test("Multiple nesting levels", async () => {
      const { rows } = await directSQLExpectSuccess(
        "SELECT /* level1 /* level2 /* level3 */ back to 2 */ back to 1 */ 1 as num"
      );
      expect((rows[0] as { num: number }).num).toBe(1);
    });
  });

  /**
   * @kb-entry postgresql/comment-out-query
   * @kb-section Hash Comment (Not Supported)
   */
  describe("Hash comment (# - NOT supported in PostgreSQL)", () => {
    test("Hash is NOT a comment in PostgreSQL", async () => {
      // In PostgreSQL, # is not a comment character (unlike MySQL)
      // This should fail with a syntax error
      const { success, error } = await directSQL("SELECT 1 # this is not a comment");
      expect(success).toBe(false);
      expect(error?.message).toMatch(/syntax error|ERROR/i);
    });
  });

  /**
   * @kb-entry postgresql/comment-out-query
   * @kb-section Comment Injection Patterns
   */
  describe("Comment injection patterns", () => {
    test("OR bypass with line comment", async () => {
      const { rows } = await directSQLExpectSuccess(
        "SELECT * FROM users WHERE username = '' OR 1=1 --' AND password = ''"
      );
      expect(rows.length).toBeGreaterThan(0);
    });

    test("UNION with line comment", async () => {
      const { rows } = await directSQLExpectSuccess(
        "SELECT id, username FROM users WHERE id = 1 UNION SELECT 999, 'injected' --"
      );
      const usernames = rows.map((r) => (r as { username: string }).username);
      expect(usernames).toContain("injected");
    });

    test("Block comment to hide injection", async () => {
      const { rows } = await directSQLExpectSuccess(
        "SELECT * FROM users WHERE id = 1/**/OR/**/1=1"
      );
      expect(rows.length).toBeGreaterThan(0);
    });

    test("Mixed comment styles", async () => {
      const { rows } = await directSQLExpectSuccess("SELECT /* block */ 1 as num -- line comment");
      expect((rows[0] as { num: number }).num).toBe(1);
    });
  });

  /**
   * @kb-entry postgresql/comment-out-query
   * @kb-section Comment with Special Characters
   */
  describe("Comments with special characters", () => {
    test("Comment containing single quotes", async () => {
      const { rows } = await directSQLExpectSuccess("SELECT 1 as num -- comment with 'quotes'");
      expect((rows[0] as { num: number }).num).toBe(1);
    });

    test("Comment containing double quotes", async () => {
      const { rows } = await directSQLExpectSuccess('SELECT 1 as num /* comment with "quotes" */');
      expect((rows[0] as { num: number }).num).toBe(1);
    });

    test("Comment containing SQL keywords", async () => {
      const { rows } = await directSQLExpectSuccess(
        "SELECT 1 as num -- SELECT DROP DELETE UPDATE INSERT"
      );
      expect((rows[0] as { num: number }).num).toBe(1);
    });
  });

  /**
   * @kb-entry postgresql/comment-out-query
   * @kb-section Multi-line Comments
   */
  describe("Multi-line block comments", () => {
    test("Block comment spanning multiple logical sections", async () => {
      const { rows } = await directSQLExpectSuccess(`
        SELECT 1 as num
        /* This comment
           spans multiple
           lines */
      `);
      expect((rows[0] as { num: number }).num).toBe(1);
    });
  });
});
