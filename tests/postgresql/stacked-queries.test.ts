/**
 * PostgreSQL Stacked Queries SQL Injection Tests
 *
 * These tests validate stacked query (multi-statement) SQL injection techniques
 * documented in the SQL Injection Knowledge Base.
 *
 * @kb-coverage postgresql/stacked-queries - Full coverage
 * @kb-coverage postgresql/tables-and-columns - Partial (information_schema queries)
 * @kb-coverage postgresql/privileges - Partial (role escalation patterns)
 */

import { describe, test, expect, beforeAll, afterAll, beforeEach } from "vitest";
import {
  initDirectRunner,
  cleanupDirectRunner,
  directSQL,
  directSQLParameterized,
} from "../../src/runner/direct.js";
import { logger } from "../../src/utils/logger.js";

describe("PostgreSQL Stacked Queries", () => {
  beforeAll(async () => {
    logger.setLevel("warn");
    await initDirectRunner();
  }, 30000);

  afterAll(async () => {
    await cleanupDirectRunner();
  }, 10000);

  // Reset test data before each test
  beforeEach(async () => {
    // Ensure test table exists and has clean state
    await directSQL(`
      DELETE FROM logs WHERE action LIKE '%test_%';
    `);
  });

  /**
   * @kb-entry postgresql/stacked-queries
   * @kb-section Basic Syntax
   */
  describe("Basic stacked query execution", () => {
    test("Multiple SELECT statements execute sequentially", async () => {
      const { success } = await directSQL("SELECT 1 as a; SELECT 2 as b;");

      // PostgreSQL executes both statements - pg library returns first statement's result
      // The key point is that both statements execute without error
      expect(success).toBe(true);
    });

    test("SELECT followed by INSERT", async () => {
      const testAction = `test_insert_${Date.now()}`;

      const { success } = await directSQL(`
        SELECT 1;
        INSERT INTO logs (action, ip_address) VALUES ('${testAction}', '127.0.0.1');
      `);

      expect(success).toBe(true);

      // Verify the insert worked
      const { result: verifyResult } = await directSQL(
        `SELECT * FROM logs WHERE action = '${testAction}'`
      );
      expect(verifyResult?.rows).toHaveLength(1);
    });

    test("SELECT followed by UPDATE", async () => {
      // First insert a test record
      const testAction = `test_update_${Date.now()}`;
      await directSQL(
        `INSERT INTO logs (action, ip_address) VALUES ('${testAction}', '127.0.0.1')`
      );

      // Update via stacked query
      const { success } = await directSQL(`
        SELECT 1;
        UPDATE logs SET ip_address = '192.168.1.1' WHERE action = '${testAction}';
      `);

      expect(success).toBe(true);

      // Verify the update worked
      const { result: verifyResult } = await directSQL(
        `SELECT ip_address FROM logs WHERE action = '${testAction}'`
      );
      expect((verifyResult?.rows[0] as { ip_address: string } | undefined)?.ip_address).toBe(
        "192.168.1.1"
      );
    });

    test("SELECT followed by DELETE", async () => {
      // First insert a test record
      const testAction = `test_delete_${Date.now()}`;
      await directSQL(
        `INSERT INTO logs (action, ip_address) VALUES ('${testAction}', '127.0.0.1')`
      );

      // Delete via stacked query
      const { success } = await directSQL(`
        SELECT 1;
        DELETE FROM logs WHERE action = '${testAction}';
      `);

      expect(success).toBe(true);

      // Verify the delete worked
      const { result: verifyResult } = await directSQL(
        `SELECT * FROM logs WHERE action = '${testAction}'`
      );
      expect(verifyResult?.rows).toHaveLength(0);
    });
  });

  /**
   * @kb-entry postgresql/stacked-queries
   * @kb-section DDL via Stacked Queries
   */
  describe("Schema manipulation via stacked queries", () => {
    const testTableName = "sqli_test_table";

    afterAll(async () => {
      // Cleanup test table
      await directSQL(`DROP TABLE IF EXISTS ${testTableName}`);
    });

    test("CREATE TABLE via stacked query", async () => {
      // First ensure table doesn't exist
      await directSQL(`DROP TABLE IF EXISTS ${testTableName}`);

      const { success } = await directSQL(`
        SELECT 1;
        CREATE TABLE ${testTableName} (id SERIAL PRIMARY KEY, data TEXT);
      `);

      expect(success).toBe(true);

      // Verify table was created
      const { result } = await directSQL(`
        SELECT table_name FROM information_schema.tables
        WHERE table_name = '${testTableName}'
      `);
      expect(result?.rows).toHaveLength(1);
    });

    test("ALTER TABLE via stacked query", async () => {
      const { success } = await directSQL(`
        SELECT 1;
        ALTER TABLE ${testTableName} ADD COLUMN extra VARCHAR(50);
      `);

      expect(success).toBe(true);

      // Verify column was added
      const { result } = await directSQL(`
        SELECT column_name FROM information_schema.columns
        WHERE table_name = '${testTableName}' AND column_name = 'extra'
      `);
      expect(result?.rows).toHaveLength(1);
    });

    test("DROP TABLE via stacked query", async () => {
      const { success } = await directSQL(`
        SELECT 1;
        DROP TABLE IF EXISTS ${testTableName};
      `);

      expect(success).toBe(true);

      // Verify table was dropped
      const { result } = await directSQL(`
        SELECT table_name FROM information_schema.tables
        WHERE table_name = '${testTableName}'
      `);
      expect(result?.rows).toHaveLength(0);
    });
  });

  /**
   * @kb-entry postgresql/stacked-queries
   * @kb-section Privilege Escalation
   * @kb-entry postgresql/privileges
   * @kb-section Role Manipulation
   */
  describe("Privilege escalation patterns", () => {
    test("Insert new user record", async () => {
      const testUser = `testuser_${Date.now()}`;

      const { success } = await directSQL(`
        SELECT 1;
        INSERT INTO users (username, password, role) VALUES ('${testUser}', 'password', 'admin');
      `);

      expect(success).toBe(true);

      // Verify user was created with admin role
      const { result } = await directSQL(`SELECT role FROM users WHERE username = '${testUser}'`);
      expect((result?.rows[0] as { role: string } | undefined)?.role).toBe("admin");

      // Cleanup
      await directSQL(`DELETE FROM users WHERE username = '${testUser}'`);
    });

    test("Update existing user role", async () => {
      // Get a non-admin user
      const { result: userResult } = await directSQL(
        "SELECT username FROM users WHERE role = 'user' LIMIT 1"
      );
      const username = (userResult?.rows[0] as { username: string } | undefined)?.username;

      if (!username) {
        // Skip if no user exists
        return;
      }

      // Store original role for restoration
      const { result: originalRole } = await directSQL(
        `SELECT role FROM users WHERE username = '${username}'`
      );

      // Attempt privilege escalation
      const { success } = await directSQL(`
        SELECT 1;
        UPDATE users SET role = 'admin' WHERE username = '${username}';
      `);

      expect(success).toBe(true);

      // Verify role was changed
      const { result: newRole } = await directSQL(
        `SELECT role FROM users WHERE username = '${username}'`
      );
      expect((newRole?.rows[0] as { role: string } | undefined)?.role).toBe("admin");

      // Restore original role
      const origRole = (originalRole?.rows[0] as { role: string } | undefined)?.role ?? "user";
      await directSQL(`UPDATE users SET role = '${origRole}' WHERE username = '${username}'`);
    });
  });

  /**
   * @kb-entry postgresql/stacked-queries
   * @kb-section Stacked Queries with Timing
   * @kb-entry postgresql/timing
   * @kb-section pg_sleep() in Multi-Statement Context
   */
  describe("Timing attack via stacked queries", () => {
    test("pg_sleep in stacked query", async () => {
      const startTime = Date.now();

      const { success } = await directSQL(`
        SELECT 1;
        SELECT pg_sleep(2);
      `);

      const elapsed = Date.now() - startTime;

      expect(success).toBe(true);
      expect(elapsed).toBeGreaterThan(1800); // At least 1.8 seconds
    });
  });

  /**
   * @kb-entry postgresql/stacked-queries
   * @kb-section Information Gathering
   * @kb-entry postgresql/tables-and-columns
   * @kb-section Enumerating Tables and Columns
   */
  describe("Information gathering via stacked queries", () => {
    test("Query pg_tables via stacked query", async () => {
      // Execute stacked query - pg library returns first statement's result
      const { success } = await directSQL(`
        SELECT 1;
        SELECT tablename FROM pg_tables WHERE schemaname = 'public';
      `);

      // Verify both statements executed successfully
      expect(success).toBe(true);

      // Verify second statement worked by running the info query directly
      const { result } = await directSQL(
        "SELECT tablename FROM pg_tables WHERE schemaname = 'public'"
      );
      const tableNames = result?.rows.map((r) => (r as { tablename: string }).tablename) ?? [];
      expect(tableNames).toContain("users");
      expect(tableNames).toContain("products");
    });

    test("Query column information via stacked query", async () => {
      // Execute stacked query - pg library returns first statement's result
      const { success } = await directSQL(`
        SELECT 1;
        SELECT column_name, data_type
        FROM information_schema.columns
        WHERE table_name = 'users';
      `);

      // Verify both statements executed successfully
      expect(success).toBe(true);

      // Verify second statement worked by running the info query directly
      const { result } = await directSQL(`
        SELECT column_name FROM information_schema.columns WHERE table_name = 'users'
      `);
      const columns = result?.rows.map((r) => (r as { column_name: string }).column_name) ?? [];
      expect(columns).toContain("username");
      expect(columns).toContain("password");
      expect(columns).toContain("role");
    });
  });

  /**
   * @kb-entry postgresql/stacked-queries
   * @kb-section Driver Support - Parameterized Queries
   *
   * Tests that parameterized queries do NOT support multi-statements.
   * This is a PostgreSQL protocol limitation, not driver-specific.
   */
  describe("Parameterized query multi-statement limitations", () => {
    test("Parameterized multi-statement fails with protocol error", async () => {
      // PostgreSQL's extended query protocol does not allow multiple commands
      // in a prepared statement - this should fail
      const { success, error } = await directSQLParameterized("SELECT $1; SELECT $2", [1, 2]);

      expect(success).toBe(false);
      expect(error).toBeDefined();
      expect(error?.message).toMatch(/cannot insert multiple commands into a prepared statement/i);
    });

    test("Single parameterized query succeeds", async () => {
      // Single statement with parameters should work fine
      const { success, result } = await directSQLParameterized(
        "SELECT $1::int + $2::int as sum",
        [5, 3]
      );

      expect(success).toBe(true);
      expect((result?.rows[0] as { sum: number } | undefined)?.sum).toBe(8);
    });

    test("Non-parameterized multi-statement succeeds (for comparison)", async () => {
      // Non-parameterized queries use simple query protocol which allows multi-statements
      const { success } = await directSQL("SELECT 1; SELECT 2;");

      expect(success).toBe(true);
    });
  });
});
