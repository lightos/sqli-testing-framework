/**
 * PostgreSQL Privileges Tests
 *
 * @kb-coverage postgresql/privileges - Full coverage
 */

import { describe, test, expect, beforeAll, afterAll } from "vitest";
import {
  initDirectRunner,
  cleanupDirectRunner,
  directSQL,
  directSQLExpectSuccess,
} from "../../src/runner/direct.js";
import { logger } from "../../src/utils/logger.js";

describe("PostgreSQL Privileges", () => {
  beforeAll(async () => {
    logger.setLevel("warn");
    await initDirectRunner();
  }, 30000);

  afterAll(async () => {
    await cleanupDirectRunner();
  }, 10000);

  /**
   * @kb-entry postgresql/privileges
   * @kb-section Checking Superuser Status
   */
  describe("Checking superuser status", () => {
    test("current_setting('is_superuser') returns status", async () => {
      const { rows } = await directSQLExpectSuccess(
        "SELECT current_setting('is_superuser') as is_super"
      );
      const isSuper = (rows[0] as { is_super: string }).is_super;
      expect(["on", "off"]).toContain(isSuper);
    });

    test("Check superuser via pg_user", async () => {
      const { rows } = await directSQLExpectSuccess(
        "SELECT usesuper FROM pg_user WHERE usename = current_user"
      );
      expect(rows.length).toBe(1);
      expect(typeof (rows[0] as { usesuper: boolean }).usesuper).toBe("boolean");
    });

    test("Check superuser via pg_roles", async () => {
      const { rows } = await directSQLExpectSuccess(
        "SELECT rolsuper FROM pg_roles WHERE rolname = current_user"
      );
      expect(rows.length).toBe(1);
    });
  });

  /**
   * @kb-entry postgresql/privileges
   * @kb-section User Privileges
   */
  describe("User privileges", () => {
    test("Query current user role attributes", async () => {
      const { rows } = await directSQLExpectSuccess(`
        SELECT rolname, rolsuper, rolinherit, rolcreaterole, rolcreatedb, rolcanlogin
        FROM pg_roles WHERE rolname = current_user
      `);
      expect(rows.length).toBe(1);
      const role = rows[0] as { rolname: string; rolsuper: boolean };
      expect(role.rolname).toBeTruthy();
    });
  });

  /**
   * @kb-entry postgresql/privileges
   * @kb-section Table-Level Privileges
   */
  describe("Table-level privileges", () => {
    test("Query table privileges for users table", async () => {
      const { rows } = await directSQLExpectSuccess(`
        SELECT grantee, privilege_type
        FROM information_schema.table_privileges
        WHERE table_name = 'users'
      `);
      expect(rows.length).toBeGreaterThan(0);
    });

    test("Query privileges granted to current user", async () => {
      const { rows } = await directSQLExpectSuccess(`
        SELECT table_schema, table_name, privilege_type
        FROM information_schema.table_privileges
        WHERE grantee = current_user
        LIMIT 10
      `);
      expect(rows.length).toBeGreaterThanOrEqual(0);
    });
  });

  /**
   * @kb-entry postgresql/privileges
   * @kb-section Schema Privileges
   */
  describe("Schema privileges", () => {
    test("Query schema ACL for public", async () => {
      const { rows } = await directSQLExpectSuccess(
        "SELECT nspname, nspacl FROM pg_namespace WHERE nspname = 'public'"
      );
      expect(rows.length).toBe(1);
    });
  });

  /**
   * @kb-entry postgresql/privileges
   * @kb-section Function Privileges
   */
  describe("Function privileges", () => {
    test("Check pg_read_file execute privilege", async () => {
      const { rows } = await directSQLExpectSuccess(
        "SELECT has_function_privilege(current_user, 'pg_read_file(text)', 'execute') as can_exec"
      );
      expect(typeof (rows[0] as { can_exec: boolean }).can_exec).toBe("boolean");
    });

    test("Check generic function privilege", async () => {
      const { rows } = await directSQLExpectSuccess(
        "SELECT has_function_privilege('version()', 'execute') as can_exec"
      );
      expect((rows[0] as { can_exec: boolean }).can_exec).toBe(true);
    });
  });

  /**
   * @kb-entry postgresql/privileges
   * @kb-section Injection Examples
   */
  describe("Injection context examples", () => {
    test("UNION SELECT superuser status", async () => {
      const { rows } = await directSQLExpectSuccess(`
        SELECT id, username FROM users WHERE id = 1
        UNION SELECT 999, current_setting('is_superuser')
      `);
      const values = rows.map((r) => (r as { username: string }).username);
      expect(values.some((v) => v === "on" || v === "off")).toBe(true);
    });

    test("UNION SELECT privilege types", async () => {
      const { success } = await directSQL(`
        SELECT id, username FROM users WHERE id = 1
        UNION SELECT 999, string_agg(privilege_type,',')
        FROM information_schema.table_privileges WHERE grantee=current_user
      `);
      expect(success).toBe(true);
    });

    test("UNION SELECT superuser check", async () => {
      const { rows } = await directSQLExpectSuccess(`
        SELECT id, username FROM users WHERE id = 1
        UNION SELECT 999, CASE WHEN usesuper THEN 'SUPERUSER' ELSE 'NOT SUPERUSER' END
        FROM pg_user WHERE usename=current_user
      `);
      expect(rows.length).toBeGreaterThan(0);
    });

    test("UNION SELECT superuser list", async () => {
      const { success } = await directSQL(`
        SELECT id, username FROM users WHERE id = 1
        UNION SELECT 999, string_agg(usename,',') FROM pg_user WHERE usesuper=true
      `);
      expect(success).toBe(true);
    });
  });

  /**
   * @kb-entry postgresql/privileges
   * @kb-section Extension Capabilities
   */
  describe("Extension capabilities", () => {
    test("List installed extensions", async () => {
      const { rows } = await directSQLExpectSuccess("SELECT extname, extversion FROM pg_extension");
      expect(rows.length).toBeGreaterThan(0);
      const extNames = rows.map((r) => (r as { extname: string }).extname);
      expect(extNames).toContain("plpgsql");
    });

    test("Check for dangerous extensions", async () => {
      const { success } = await directSQL(`
        SELECT * FROM pg_extension
        WHERE extname IN ('adminpack', 'file_fdw', 'dblink')
      `);
      expect(success).toBe(true);
    });
  });

  /**
   * @kb-entry postgresql/privileges
   * @kb-section Role Membership
   */
  describe("Role membership", () => {
    test("Query role membership hierarchy", async () => {
      const { success } = await directSQL(`
        SELECT r.rolname as role, m.rolname as member
        FROM pg_auth_members am
        JOIN pg_roles r ON am.roleid = r.oid
        JOIN pg_roles m ON am.member = m.oid
      `);
      expect(success).toBe(true);
    });

    test("Check role membership with pg_has_role", async () => {
      const { rows } = await directSQLExpectSuccess(
        "SELECT pg_has_role(current_user, 'postgres', 'member') as is_member"
      );
      expect(typeof (rows[0] as { is_member: boolean }).is_member).toBe("boolean");
    });
  });
});
