/**
 * PostgreSQL Version Detection Tests
 *
 * @kb-coverage postgresql/testing-version - Full coverage
 */

import { describe, test, expect, beforeAll, afterAll } from "vitest";
import {
  initDirectRunner,
  cleanupDirectRunner,
  directSQL,
  directSQLExpectSuccess,
} from "../../src/runner/direct.js";
import { logger } from "../../src/utils/logger.js";

describe("PostgreSQL Version Detection", () => {
  beforeAll(async () => {
    logger.setLevel("warn");
    await initDirectRunner();
  }, 30000);

  afterAll(async () => {
    await cleanupDirectRunner();
  }, 10000);

  /**
   * @kb-entry postgresql/testing-version
   * @kb-section Basic Version Queries
   */
  describe("Basic version queries", () => {
    test("version() returns PostgreSQL version string", async () => {
      const { rows } = await directSQLExpectSuccess("SELECT version()");
      const version = (rows[0] as { version: string }).version;
      expect(version).toMatch(/PostgreSQL/i);
    });

    test("current_setting('server_version') returns version", async () => {
      const { rows } = await directSQLExpectSuccess("SELECT current_setting('server_version')");
      const version = (rows[0] as { current_setting: string }).current_setting;
      expect(version).toMatch(/^\d+\.\d+/);
    });

    test("current_setting('server_version_num') returns numeric version", async () => {
      const { rows } = await directSQLExpectSuccess("SELECT current_setting('server_version_num')");
      const versionNum = (rows[0] as { current_setting: string }).current_setting;
      expect(parseInt(versionNum, 10)).toBeGreaterThan(100000);
    });

    test("SHOW server_version returns version", async () => {
      const { rows } = await directSQLExpectSuccess("SHOW server_version");
      const version = (rows[0] as { server_version: string }).server_version;
      expect(version).toMatch(/^\d+\.\d+/);
    });

    test("SHOW server_version_num returns numeric version", async () => {
      const { rows } = await directSQLExpectSuccess("SHOW server_version_num");
      const versionNum = (rows[0] as { server_version_num: string }).server_version_num;
      expect(parseInt(versionNum, 10)).toBeGreaterThan(100000);
    });
  });

  /**
   * @kb-entry postgresql/testing-version
   * @kb-section Version Parsing
   */
  describe("Version parsing", () => {
    test("split_part extracts major version", async () => {
      const { rows } = await directSQLExpectSuccess("SELECT split_part(version(), ' ', 2) as ver");
      const ver = (rows[0] as { ver: string }).ver;
      expect(ver).toMatch(/^\d+\.\d+/);
    });

    test("CASE WHEN for version comparison", async () => {
      const { rows } = await directSQLExpectSuccess(`
        SELECT CASE
          WHEN current_setting('server_version_num')::int > 100000
          THEN 'Version 10+'
          ELSE 'Version < 10'
        END as version_check
      `);
      const check = (rows[0] as { version_check: string }).version_check;
      expect(check).toBe("Version 10+");
    });
  });

  /**
   * @kb-entry postgresql/testing-version
   * @kb-section Version in Injection Context
   */
  describe("Version in injection context", () => {
    test("UNION SELECT with version()", async () => {
      const { rows } = await directSQLExpectSuccess(`
        SELECT id, username FROM users WHERE id = 1
        UNION SELECT 999, version()
      `);
      const usernames = rows.map((r) => (r as { username: string }).username);
      expect(usernames.some((u) => u.includes("PostgreSQL"))).toBe(true);
    });

    test("Error-based version extraction via CAST", async () => {
      const { success, error } = await directSQL("SELECT CAST(version() AS int)");
      expect(success).toBe(false);
      expect(error?.message).toMatch(/PostgreSQL/i);
    });

    test("Boolean-based version detection", async () => {
      const { rows } = await directSQLExpectSuccess(
        "SELECT CASE WHEN SUBSTRING(version(),1,1)='P' THEN 1 ELSE 0 END as result"
      );
      const result = (rows[0] as { result: number }).result;
      expect(result).toBe(1);
    });
  });

  /**
   * @kb-entry postgresql/testing-version
   * @kb-section Feature Availability
   */
  describe("Feature availability by version", () => {
    test("pg_sleep() is available (PostgreSQL > 8.2)", async () => {
      const { success } = await directSQL("SELECT pg_sleep(0)");
      expect(success).toBe(true);
    });

    test("string_agg() is available (PostgreSQL > 9.0)", async () => {
      const { success } = await directSQL(
        "SELECT string_agg(table_name, ',') FROM information_schema.tables WHERE table_schema = 'public'"
      );
      expect(success).toBe(true);
    });

    test("pg_settings view is available", async () => {
      const { success } = await directSQL("SELECT count(*) FROM pg_settings");
      expect(success).toBe(true);
    });
  });
});
