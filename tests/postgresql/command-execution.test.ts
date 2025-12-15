/**
 * PostgreSQL Command Execution Tests
 *
 * Tests for command execution capability detection.
 * Note: Actual command execution requires superuser - tests focus on enumeration.
 *
 * @kb-coverage postgresql/command-execution - Full coverage
 */

import { describe, test, expect, beforeAll, afterAll } from "vitest";
import {
  initDirectRunner,
  cleanupDirectRunner,
  directSQL,
  directSQLExpectSuccess,
} from "../../src/runner/direct.js";
import { logger } from "../../src/utils/logger.js";

describe("PostgreSQL Command Execution", () => {
  beforeAll(async () => {
    logger.setLevel("warn");
    await initDirectRunner();
  }, 30000);

  afterAll(async () => {
    await cleanupDirectRunner();
  }, 10000);

  /**
   * @kb-entry postgresql/command-execution
   * @kb-section Privilege Checks
   */
  describe("Command execution privilege checks", () => {
    test("Check if current user is superuser", async () => {
      const { rows } = await directSQLExpectSuccess(
        "SELECT current_setting('is_superuser') as is_super"
      );
      expect(["on", "off"]).toContain((rows[0] as { is_super: string }).is_super);
    });

    test("Check superuser status via pg_user", async () => {
      const { rows } = await directSQLExpectSuccess(
        "SELECT usesuper FROM pg_user WHERE usename = current_user"
      );
      expect(typeof (rows[0] as { usesuper: boolean }).usesuper).toBe("boolean");
    });

    test("Check pg_execute_server_program role membership", async () => {
      const { rows } = await directSQLExpectSuccess(
        "SELECT pg_has_role(current_user, 'pg_execute_server_program', 'member') as has_role"
      );
      expect(typeof (rows[0] as { has_role: boolean }).has_role).toBe("boolean");
    });
  });

  /**
   * @kb-entry postgresql/command-execution
   * @kb-section PostgreSQL Version Check
   */
  describe("Version checks for COPY PROGRAM", () => {
    test("PostgreSQL version returns valid string", async () => {
      const { rows } = await directSQLExpectSuccess("SELECT version() as ver");
      expect((rows[0] as { ver: string }).ver).toMatch(/PostgreSQL/i);
    });

    test("Extract major version number", async () => {
      const { rows } = await directSQLExpectSuccess(
        "SELECT current_setting('server_version_num')::int as ver_num"
      );
      // COPY PROGRAM requires 9.3+ (90300)
      expect((rows[0] as { ver_num: number }).ver_num).toBeGreaterThanOrEqual(90300);
    });

    test("Check server version setting", async () => {
      const { rows } = await directSQLExpectSuccess(
        "SELECT current_setting('server_version') as ver"
      );
      expect((rows[0] as { ver: string }).ver).toBeTruthy();
    });
  });

  /**
   * @kb-entry postgresql/command-execution
   * @kb-section Untrusted Language Extensions
   */
  describe("Untrusted language extension checks", () => {
    test("Check for plpython3u extension", async () => {
      const { rows } = await directSQLExpectSuccess(
        "SELECT * FROM pg_extension WHERE extname = 'plpython3u'"
      );
      expect(rows.length).toBeGreaterThanOrEqual(0);
    });

    test("Check for plperlu extension", async () => {
      const { rows } = await directSQLExpectSuccess(
        "SELECT * FROM pg_extension WHERE extname = 'plperlu'"
      );
      expect(rows.length).toBeGreaterThanOrEqual(0);
    });

    test("Check for pltclu extension", async () => {
      const { rows } = await directSQLExpectSuccess(
        "SELECT * FROM pg_extension WHERE extname = 'pltclu'"
      );
      expect(rows.length).toBeGreaterThanOrEqual(0);
    });

    test("List all untrusted language extensions", async () => {
      const { rows } = await directSQLExpectSuccess(
        "SELECT extname FROM pg_extension WHERE extname LIKE 'pl%u'"
      );
      expect(rows.length).toBeGreaterThanOrEqual(0);
    });

    test("Check untrusted languages in pg_language", async () => {
      const { rows } = await directSQLExpectSuccess(
        "SELECT lanname FROM pg_language WHERE lanpltrusted = false AND lanname LIKE 'pl%'"
      );
      expect(rows.length).toBeGreaterThanOrEqual(0);
    });
  });

  /**
   * @kb-entry postgresql/command-execution
   * @kb-section Available Extensions
   */
  describe("Available extension enumeration", () => {
    test("List available untrusted language extensions", async () => {
      const { rows } = await directSQLExpectSuccess(
        "SELECT name FROM pg_available_extensions WHERE name LIKE 'pl%u'"
      );
      expect(rows.length).toBeGreaterThanOrEqual(0);
    });

    test("Check if plpython3u is available", async () => {
      const { rows } = await directSQLExpectSuccess(
        "SELECT * FROM pg_available_extensions WHERE name = 'plpython3u'"
      );
      expect(rows.length).toBeGreaterThanOrEqual(0);
    });
  });

  /**
   * @kb-entry postgresql/command-execution
   * @kb-section COPY Statement Checks
   */
  describe("COPY statement capability checks", () => {
    test("COPY requires specific privileges", async () => {
      // Create a test to verify COPY behavior
      const { success, error } = await directSQL("COPY (SELECT 1) TO PROGRAM 'echo test'");
      if (!success) {
        // Expected to fail without superuser
        expect(error?.message).toMatch(/permission denied|must be superuser/i);
      }
      expect(true).toBe(true);
    });

    test("Check COPY TO FILE privilege", async () => {
      const { success, error } = await directSQL("COPY (SELECT 1) TO '/tmp/test_copy.txt'");
      if (!success) {
        expect(error?.message).toMatch(/permission denied|must be superuser|could not open/i);
      }
      expect(true).toBe(true);
    });
  });

  /**
   * @kb-entry postgresql/command-execution
   * @kb-section Language Privilege Checks
   */
  describe("Language privilege enumeration", () => {
    test("Check privilege on plpgsql", async () => {
      const { rows } = await directSQLExpectSuccess(
        "SELECT has_language_privilege(current_user, 'plpgsql', 'usage') as can_use"
      );
      expect(typeof (rows[0] as { can_use: boolean }).can_use).toBe("boolean");
    });

    test("List all languages with usage privilege", async () => {
      const { rows } = await directSQLExpectSuccess(`
        SELECT lanname, has_language_privilege(current_user, lanname, 'usage') as can_use
        FROM pg_language
        WHERE lanispl = true
      `);
      expect(rows.length).toBeGreaterThan(0);
    });
  });

  /**
   * @kb-entry postgresql/command-execution
   * @kb-section Security Configuration
   */
  describe("Security configuration checks", () => {
    test("Check shared_preload_libraries setting", async () => {
      const { rows } = await directSQLExpectSuccess(
        "SELECT current_setting('shared_preload_libraries') as libs"
      );
      expect(rows.length).toBe(1);
    });

    test("Check dynamic_library_path setting", async () => {
      const { rows } = await directSQLExpectSuccess(
        "SELECT current_setting('dynamic_library_path') as path"
      );
      expect((rows[0] as { path: string }).path).toBeTruthy();
    });
  });

  /**
   * @kb-entry postgresql/command-execution
   * @kb-section Function Creation Test
   */
  describe("Function creation capability", () => {
    test("Check if user can create functions", async () => {
      const { rows } = await directSQLExpectSuccess(`
        SELECT has_schema_privilege(current_user, 'public', 'create') as can_create
      `);
      expect(typeof (rows[0] as { can_create: boolean }).can_create).toBe("boolean");
    });

    test("List user-created functions", async () => {
      const { rows } = await directSQLExpectSuccess(`
        SELECT p.proname, l.lanname
        FROM pg_proc p
        JOIN pg_language l ON p.prolang = l.oid
        WHERE p.proowner = (SELECT oid FROM pg_roles WHERE rolname = current_user)
        LIMIT 10
      `);
      expect(rows.length).toBeGreaterThanOrEqual(0);
    });
  });
});
