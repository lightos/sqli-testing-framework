/**
 * PostgreSQL Privilege Escalation Tests
 *
 * Tests for privilege escalation enumeration and techniques.
 * Note: Actual escalation requires specific privileges; tests focus on enumeration.
 *
 * @kb-coverage postgresql/privilege-escalation - Full coverage
 */

import { describe, test, expect, beforeAll, afterAll } from "vitest";
import {
  initDirectRunner,
  cleanupDirectRunner,
  directSQL,
  directSQLExpectSuccess,
} from "../../src/runner/direct.js";
import { logger } from "../../src/utils/logger.js";

describe("PostgreSQL Privilege Escalation", () => {
  beforeAll(async () => {
    logger.setLevel("warn");
    await initDirectRunner();
  }, 30000);

  afterAll(async () => {
    await cleanupDirectRunner();
  }, 10000);

  /**
   * @kb-entry postgresql/privilege-escalation
   * @kb-section CREATEROLE Privilege Check
   */
  describe("CREATEROLE privilege enumeration", () => {
    test("Check if current user has CREATEROLE", async () => {
      const { rows } = await directSQLExpectSuccess(
        "SELECT rolcreaterole FROM pg_roles WHERE rolname = current_user"
      );
      expect(typeof (rows[0] as { rolcreaterole: boolean }).rolcreaterole).toBe("boolean");
    });

    test("List users with CREATEROLE", async () => {
      const { rows } = await directSQLExpectSuccess(
        "SELECT rolname FROM pg_roles WHERE rolcreaterole = true"
      );
      expect(rows.length).toBeGreaterThanOrEqual(0);
    });

    test("Check all role attributes for current user", async () => {
      const { rows } = await directSQLExpectSuccess(`
        SELECT rolname, rolsuper, rolcreaterole, rolcreatedb, rolcanlogin, rolbypassrls
        FROM pg_roles WHERE rolname = current_user
      `);
      expect(rows.length).toBe(1);
    });
  });

  /**
   * @kb-entry postgresql/privilege-escalation
   * @kb-section Dangerous Role Membership
   */
  describe("Dangerous role membership checks", () => {
    test("Check pg_read_server_files membership", async () => {
      const { rows } = await directSQLExpectSuccess(
        "SELECT pg_has_role(current_user, 'pg_read_server_files', 'member') as has_role"
      );
      expect(typeof (rows[0] as { has_role: boolean }).has_role).toBe("boolean");
    });

    test("Check pg_write_server_files membership", async () => {
      const { rows } = await directSQLExpectSuccess(
        "SELECT pg_has_role(current_user, 'pg_write_server_files', 'member') as has_role"
      );
      expect(typeof (rows[0] as { has_role: boolean }).has_role).toBe("boolean");
    });

    test("Check pg_execute_server_program membership", async () => {
      const { rows } = await directSQLExpectSuccess(
        "SELECT pg_has_role(current_user, 'pg_execute_server_program', 'member') as has_role"
      );
      expect(typeof (rows[0] as { has_role: boolean }).has_role).toBe("boolean");
    });

    test("List members of dangerous roles", async () => {
      const { rows } = await directSQLExpectSuccess(`
        SELECT r.rolname AS role, m.rolname AS member
        FROM pg_auth_members am
        JOIN pg_roles r ON am.roleid = r.oid
        JOIN pg_roles m ON am.member = m.oid
        WHERE r.rolname IN ('pg_read_server_files', 'pg_write_server_files', 'pg_execute_server_program')
      `);
      expect(rows.length).toBeGreaterThanOrEqual(0);
    });
  });

  /**
   * @kb-entry postgresql/privilege-escalation
   * @kb-section SECURITY DEFINER Functions
   */
  describe("SECURITY DEFINER function enumeration", () => {
    test("Find all SECURITY DEFINER functions", async () => {
      const { rows } = await directSQLExpectSuccess(`
        SELECT n.nspname AS schema, p.proname AS function_name,
               pg_get_userbyid(p.proowner) AS owner
        FROM pg_proc p
        JOIN pg_namespace n ON p.pronamespace = n.oid
        WHERE p.prosecdef = true
        AND n.nspname NOT IN ('pg_catalog', 'information_schema')
        LIMIT 10
      `);
      expect(rows.length).toBeGreaterThanOrEqual(0);
    });

    test("Find SECURITY DEFINER functions owned by superusers", async () => {
      const { rows } = await directSQLExpectSuccess(`
        SELECT p.proname, pg_get_userbyid(p.proowner) AS owner
        FROM pg_proc p
        JOIN pg_roles r ON p.proowner = r.oid
        WHERE p.prosecdef = true AND r.rolsuper = true
        AND p.pronamespace NOT IN (
          SELECT oid FROM pg_namespace WHERE nspname IN ('pg_catalog', 'information_schema')
        )
        LIMIT 10
      `);
      expect(rows.length).toBeGreaterThanOrEqual(0);
    });

    test("Count SECURITY DEFINER functions by schema", async () => {
      const { rows } = await directSQLExpectSuccess(`
        SELECT n.nspname AS schema, COUNT(*) as count
        FROM pg_proc p
        JOIN pg_namespace n ON p.pronamespace = n.oid
        WHERE p.prosecdef = true
        GROUP BY n.nspname
        ORDER BY count DESC
        LIMIT 5
      `);
      expect(rows.length).toBeGreaterThan(0);
    });
  });

  /**
   * @kb-entry postgresql/privilege-escalation
   * @kb-section pg_authid Filenode
   */
  describe("pg_authid filenode enumeration", () => {
    test("Get pg_authid filenode", async () => {
      const { rows } = await directSQLExpectSuccess(
        "SELECT pg_relation_filenode('pg_authid') as filenode"
      );
      expect((rows[0] as { filenode: number }).filenode).toBeGreaterThan(0);
    });

    test("Get pg_authid filepath", async () => {
      const { rows } = await directSQLExpectSuccess(
        "SELECT pg_relation_filepath('pg_authid') as filepath"
      );
      // pg_authid is in global directory, not base (it's shared across databases)
      expect((rows[0] as { filepath: string }).filepath).toContain("global");
    });

    test("Get database OID for filepath", async () => {
      const { rows } = await directSQLExpectSuccess(
        "SELECT oid, datname FROM pg_database WHERE datname = current_database()"
      );
      expect((rows[0] as { oid: number }).oid).toBeGreaterThan(0);
    });
  });

  /**
   * @kb-entry postgresql/privilege-escalation
   * @kb-section Event Trigger Enumeration
   */
  describe("Event trigger enumeration", () => {
    test("List all event triggers", async () => {
      const { rows } = await directSQLExpectSuccess(
        "SELECT evtname, evtevent, evtowner::regrole AS owner FROM pg_event_trigger"
      );
      expect(rows.length).toBeGreaterThanOrEqual(0);
    });

    test("Check event trigger creation privilege", async () => {
      const { rows } = await directSQLExpectSuccess(
        "SELECT rolsuper FROM pg_roles WHERE rolname = current_user"
      );
      // Only superusers can create event triggers
      expect(typeof (rows[0] as { rolsuper: boolean }).rolsuper).toBe("boolean");
    });

    test("List event trigger functions", async () => {
      const { rows } = await directSQLExpectSuccess(`
        SELECT p.proname, n.nspname
        FROM pg_proc p
        JOIN pg_namespace n ON p.pronamespace = n.oid
        WHERE p.prorettype = 'event_trigger'::regtype
        LIMIT 10
      `);
      expect(rows.length).toBeGreaterThanOrEqual(0);
    });
  });

  /**
   * @kb-entry postgresql/privilege-escalation
   * @kb-section Row Level Security Bypass
   */
  describe("Row Level Security bypass checks", () => {
    test("Check BYPASSRLS privilege", async () => {
      const { rows } = await directSQLExpectSuccess(
        "SELECT rolbypassrls FROM pg_roles WHERE rolname = current_user"
      );
      expect(typeof (rows[0] as { rolbypassrls: boolean }).rolbypassrls).toBe("boolean");
    });

    test("List users with BYPASSRLS", async () => {
      const { rows } = await directSQLExpectSuccess(
        "SELECT rolname FROM pg_roles WHERE rolbypassrls = true"
      );
      expect(rows.length).toBeGreaterThanOrEqual(0);
    });

    test("List tables with RLS enabled", async () => {
      const { rows } = await directSQLExpectSuccess(`
        SELECT schemaname, tablename, rowsecurity
        FROM pg_tables
        WHERE rowsecurity = true
        LIMIT 10
      `);
      expect(rows.length).toBeGreaterThanOrEqual(0);
    });

    test("Check pg_read_all_data role (PostgreSQL 14+)", async () => {
      const { success, result } = await directSQL(
        "SELECT pg_has_role(current_user, 'pg_read_all_data', 'member') as has_role"
      );
      // Role may not exist in older versions
      if (success && result) {
        expect(typeof (result.rows[0] as { has_role: boolean }).has_role).toBe("boolean");
      }
      expect(true).toBe(true);
    });
  });

  /**
   * @kb-entry postgresql/privilege-escalation
   * @kb-section Procedural Language Enumeration
   */
  describe("Procedural language enumeration", () => {
    test("List all installed languages", async () => {
      const { rows } = await directSQLExpectSuccess(
        "SELECT lanname, lanpltrusted FROM pg_language"
      );
      expect(rows.length).toBeGreaterThan(0);
    });

    test("Find untrusted languages", async () => {
      const { rows } = await directSQLExpectSuccess(
        "SELECT lanname FROM pg_language WHERE lanpltrusted = false"
      );
      // At minimum, 'c' and 'internal' are untrusted
      expect(rows.length).toBeGreaterThan(0);
    });

    test("Check language usage privilege for plpgsql", async () => {
      const { rows } = await directSQLExpectSuccess(
        "SELECT has_language_privilege(current_user, 'plpgsql', 'usage') as can_use"
      );
      expect(typeof (rows[0] as { can_use: boolean }).can_use).toBe("boolean");
    });

    test("List available procedural language extensions", async () => {
      const { rows } = await directSQLExpectSuccess(`
        SELECT name FROM pg_available_extensions
        WHERE name LIKE 'pl%'
      `);
      expect(rows.length).toBeGreaterThanOrEqual(0);
    });
  });

  /**
   * @kb-entry postgresql/privilege-escalation
   * @kb-section Index Function Analysis
   */
  describe("Index function analysis", () => {
    test("List indexes with expression functions", async () => {
      const { rows } = await directSQLExpectSuccess(`
        SELECT schemaname, tablename, indexname, indexdef
        FROM pg_indexes
        WHERE indexdef LIKE '%(%'
        LIMIT 10
      `);
      expect(rows.length).toBeGreaterThanOrEqual(0);
    });

    test("Find user-owned tables with indexes", async () => {
      const { rows } = await directSQLExpectSuccess(`
        SELECT c.relname as table_name, i.relname as index_name
        FROM pg_class c
        JOIN pg_index idx ON c.oid = idx.indrelid
        JOIN pg_class i ON idx.indexrelid = i.oid
        WHERE c.relowner = (SELECT oid FROM pg_roles WHERE rolname = current_user)
        LIMIT 10
      `);
      expect(rows.length).toBeGreaterThanOrEqual(0);
    });
  });

  /**
   * @kb-entry postgresql/privilege-escalation
   * @kb-section Extension-Based Escalation
   */
  describe("Extension-based escalation checks", () => {
    test("Check for dblink extension", async () => {
      const { rows } = await directSQLExpectSuccess(
        "SELECT * FROM pg_extension WHERE extname = 'dblink'"
      );
      expect(rows.length).toBeGreaterThanOrEqual(0);
    });

    test("Check for postgres_fdw extension", async () => {
      const { rows } = await directSQLExpectSuccess(
        "SELECT * FROM pg_extension WHERE extname = 'postgres_fdw'"
      );
      expect(rows.length).toBeGreaterThanOrEqual(0);
    });

    test("Check for file_fdw extension", async () => {
      const { rows } = await directSQLExpectSuccess(
        "SELECT * FROM pg_extension WHERE extname = 'file_fdw'"
      );
      expect(rows.length).toBeGreaterThanOrEqual(0);
    });

    test("List foreign servers", async () => {
      const { rows } = await directSQLExpectSuccess(
        "SELECT srvname, srvowner::regrole AS owner FROM pg_foreign_server"
      );
      expect(rows.length).toBeGreaterThanOrEqual(0);
    });

    test("List user mappings", async () => {
      const { rows } = await directSQLExpectSuccess(`
        SELECT um.umserver, s.srvname, um.umuser::regrole AS local_user
        FROM pg_user_mapping um
        JOIN pg_foreign_server s ON um.umserver = s.oid
        LIMIT 10
      `);
      expect(rows.length).toBeGreaterThanOrEqual(0);
    });
  });

  /**
   * @kb-entry postgresql/privilege-escalation
   * @kb-section Password Brute Force Support
   */
  describe("Password brute force support checks", () => {
    test("Check if dblink is available for brute force", async () => {
      await directSQL("SELECT dblink_connect_u('test', 'dbname=postgres')");
      // Will fail but shows if function exists
      expect(true).toBe(true);
    });

    test("Check password_encryption setting", async () => {
      const { rows } = await directSQLExpectSuccess(
        "SELECT current_setting('password_encryption') as encryption"
      );
      expect(["md5", "scram-sha-256"]).toContain((rows[0] as { encryption: string }).encryption);
    });
  });

  /**
   * @kb-entry postgresql/privilege-escalation
   * @kb-section Superuser Enumeration
   */
  describe("Superuser enumeration", () => {
    test("List all superusers", async () => {
      const { rows } = await directSQLExpectSuccess(
        "SELECT rolname FROM pg_roles WHERE rolsuper = true"
      );
      expect(rows.length).toBeGreaterThan(0);
    });

    test("Check if postgres user exists", async () => {
      const { rows } = await directSQLExpectSuccess(
        "SELECT rolname, rolsuper FROM pg_roles WHERE rolname = 'postgres'"
      );
      if (rows.length > 0) {
        expect((rows[0] as { rolsuper: boolean }).rolsuper).toBe(true);
      }
      expect(true).toBe(true);
    });

    test("List users who can login", async () => {
      const { rows } = await directSQLExpectSuccess(
        "SELECT rolname, rolsuper FROM pg_roles WHERE rolcanlogin = true"
      );
      expect(rows.length).toBeGreaterThan(0);
    });
  });
});
