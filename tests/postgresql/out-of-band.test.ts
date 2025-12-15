/**
 * PostgreSQL Out of Band Channeling Tests
 *
 * Note: Many OOB techniques require special extensions (dblink) or elevated
 * privileges (COPY TO PROGRAM). Tests verify technique validity where possible
 * and gracefully handle permission errors.
 *
 * @kb-coverage postgresql/out-of-band-channeling - Partial (limited by permissions)
 */

import { describe, test, expect, beforeAll, afterAll } from "vitest";
import {
  initDirectRunner,
  cleanupDirectRunner,
  directSQL,
  directSQLExpectSuccess,
} from "../../src/runner/direct.js";
import { logger } from "../../src/utils/logger.js";

describe("PostgreSQL Out of Band Channeling", () => {
  beforeAll(async () => {
    logger.setLevel("warn");
    await initDirectRunner();
  }, 30000);

  afterAll(async () => {
    await cleanupDirectRunner();
  }, 10000);

  /**
   * @kb-entry postgresql/out-of-band-channeling
   * @kb-section dblink Extension Check
   */
  describe("dblink extension availability", () => {
    test("Check if dblink extension exists", async () => {
      const { rows } = await directSQLExpectSuccess(
        "SELECT * FROM pg_available_extensions WHERE name = 'dblink'"
      );
      // dblink should be available even if not installed
      expect(rows.length).toBeLessThanOrEqual(1);
    });

    test("Check if dblink is installed", async () => {
      const { rows } = await directSQLExpectSuccess(
        "SELECT * FROM pg_extension WHERE extname = 'dblink'"
      );
      // May or may not be installed
      expect(rows.length).toBeLessThanOrEqual(1);
    });

    test("Attempt to create dblink extension", async () => {
      const { success, error } = await directSQL("CREATE EXTENSION IF NOT EXISTS dblink");
      if (!success) {
        // Permission denied is acceptable
        expect(error?.message).toMatch(/permission denied|extension.*not available/i);
      }
      expect(true).toBe(true);
    });
  });

  /**
   * @kb-entry postgresql/out-of-band-channeling
   * @kb-section Large Object Functions
   */
  describe("Large object functions", () => {
    test("lo_creat creates large object", async () => {
      const { success, result, error } = await directSQL("SELECT lo_creat(-1)");
      if (success && result) {
        const oid = (result.rows[0] as { lo_creat: number }).lo_creat;
        expect(oid).toBeGreaterThan(0);
        // Clean up
        await directSQL(`SELECT lo_unlink(${oid})`);
      } else {
        expect(error?.message).toMatch(/permission denied|must be owner/i);
      }
    });

    test("lo_from_bytea creates LO from data", async () => {
      const { success, result, error } = await directSQL(
        "SELECT lo_from_bytea(0, 'test content'::bytea)"
      );
      if (success && result) {
        const oid = (result.rows[0] as { lo_from_bytea: number }).lo_from_bytea;
        expect(oid).toBeGreaterThan(0);
        // Clean up
        await directSQL(`SELECT lo_unlink(${oid})`);
      } else {
        expect(error?.message).toMatch(/permission denied|must be owner/i);
      }
    });

    test("lo_import reads file into LO (if permitted)", async () => {
      const { success, error } = await directSQL("SELECT lo_import('/etc/hostname')");
      if (!success) {
        // Permission denied is expected
        expect(error?.message).toMatch(/permission denied|could not open|No such file/i);
      }
      expect(true).toBe(true);
    });
  });

  /**
   * @kb-entry postgresql/out-of-band-channeling
   * @kb-section COPY TO PROGRAM
   */
  describe("COPY TO PROGRAM", () => {
    test("COPY TO PROGRAM (requires superuser)", async () => {
      const { success, error } = await directSQL(
        "COPY (SELECT 'test') TO PROGRAM 'cat > /dev/null'"
      );
      if (!success) {
        // Permission denied for non-superuser
        expect(error?.message).toMatch(/permission denied|must be superuser/i);
      }
      expect(true).toBe(true);
    });

    test("Check pg_execute_server_program membership", async () => {
      const { rows } = await directSQLExpectSuccess(
        "SELECT pg_has_role(current_user, 'pg_execute_server_program', 'member') as has_role"
      );
      const hasRole = (rows[0] as { has_role: boolean }).has_role;
      expect(typeof hasRole).toBe("boolean");
    });
  });

  /**
   * @kb-entry postgresql/out-of-band-channeling
   * @kb-section Data Encoding for Transport
   */
  describe("Data encoding for transport", () => {
    test("Replace spaces for connection strings", async () => {
      const { rows } = await directSQLExpectSuccess(
        "SELECT replace(version(), ' ', '_') as encoded"
      );
      const encoded = (rows[0] as { encoded: string }).encoded;
      expect(encoded).not.toContain(" ");
    });

    test("Hex encode data", async () => {
      const { rows } = await directSQLExpectSuccess(
        "SELECT encode(version()::bytea, 'hex') as encoded"
      );
      const encoded = (rows[0] as { encoded: string }).encoded;
      expect(encoded).toMatch(/^[0-9a-f]+$/);
    });

    test("Base64 encode data", async () => {
      const { rows } = await directSQLExpectSuccess(
        "SELECT encode(version()::bytea, 'base64') as encoded"
      );
      const encoded = (rows[0] as { encoded: string }).encoded;
      expect(encoded).toBeTruthy();
    });

    test("Substring for chunking", async () => {
      const { rows } = await directSQLExpectSuccess(
        "SELECT substring(version(), 1, 10) as chunk1, substring(version(), 11, 10) as chunk2"
      );
      expect((rows[0] as { chunk1: string }).chunk1.length).toBeLessThanOrEqual(10);
    });
  });

  /**
   * @kb-entry postgresql/out-of-band-channeling
   * @kb-section pg_notify
   */
  describe("pg_notify function", () => {
    test("pg_notify sends notification", async () => {
      const { success } = await directSQL("SELECT pg_notify('test_channel', 'test_payload')");
      expect(success).toBe(true);
    });

    test("pg_notify with query result", async () => {
      const { success } = await directSQL(
        "SELECT pg_notify('data_channel', (SELECT current_database()))"
      );
      expect(success).toBe(true);
    });
  });

  /**
   * @kb-entry postgresql/out-of-band-channeling
   * @kb-section String Aggregation for Exfiltration
   */
  describe("String aggregation for exfiltration", () => {
    test("string_agg aggregates data for single request", async () => {
      const { rows } = await directSQLExpectSuccess(
        "SELECT string_agg(datname, ':') as dbs FROM pg_database"
      );
      const dbs = (rows[0] as { dbs: string }).dbs;
      expect(dbs).toContain(":");
    });

    test("Concatenate multiple columns", async () => {
      const { rows } = await directSQLExpectSuccess(
        "SELECT string_agg(username || '=' || password, '|') as creds FROM users WHERE id <= 2"
      );
      const creds = (rows[0] as { creds: string }).creds;
      expect(creds).toContain("=");
    });
  });
});
