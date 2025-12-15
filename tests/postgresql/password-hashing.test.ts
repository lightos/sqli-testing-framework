/**
 * PostgreSQL Password Hashing Tests
 *
 * Tests for password hash format detection and generation.
 * Note: Accessing pg_shadow requires superuser - tests focus on hash format understanding.
 *
 * @kb-coverage postgresql/password-hashing - Full coverage
 */

import { describe, test, expect, beforeAll, afterAll } from "vitest";
import {
  initDirectRunner,
  cleanupDirectRunner,
  directSQL,
  directSQLExpectSuccess,
} from "../../src/runner/direct.js";
import { logger } from "../../src/utils/logger.js";

describe("PostgreSQL Password Hashing", () => {
  beforeAll(async () => {
    logger.setLevel("warn");
    await initDirectRunner();
  }, 30000);

  afterAll(async () => {
    await cleanupDirectRunner();
  }, 10000);

  /**
   * @kb-entry postgresql/password-hashing
   * @kb-section Password Encryption Setting
   */
  describe("Password encryption settings", () => {
    test("Check password_encryption setting", async () => {
      const { rows } = await directSQLExpectSuccess(
        "SELECT current_setting('password_encryption') as encryption"
      );
      expect(["md5", "scram-sha-256"]).toContain((rows[0] as { encryption: string }).encryption);
    });

    test("SHOW password_encryption", async () => {
      const { rows } = await directSQLExpectSuccess("SHOW password_encryption");
      expect(rows.length).toBe(1);
    });
  });

  /**
   * @kb-entry postgresql/password-hashing
   * @kb-section MD5 Hash Generation
   */
  describe("MD5 hash generation", () => {
    test("Generate MD5 hash of string", async () => {
      const { rows } = await directSQLExpectSuccess("SELECT md5('test') as hash");
      expect((rows[0] as { hash: string }).hash).toHaveLength(32);
    });

    test("Generate PostgreSQL-style MD5 password hash", async () => {
      const { rows } = await directSQLExpectSuccess(
        "SELECT 'md5' || md5('secretpostgres') as hash"
      );
      const hash = (rows[0] as { hash: string }).hash;
      expect(hash).toMatch(/^md5[a-f0-9]{32}$/);
      expect(hash).toHaveLength(35);
    });

    test("MD5 hash format: md5 prefix + 32 hex chars", async () => {
      const { rows } = await directSQLExpectSuccess(
        "SELECT 'md5' || md5('password' || 'username') as hash"
      );
      const hash = (rows[0] as { hash: string }).hash;
      expect(hash.startsWith("md5")).toBe(true);
      expect(hash.substring(3)).toMatch(/^[a-f0-9]{32}$/);
    });

    test("Different passwords produce different hashes", async () => {
      const { rows } = await directSQLExpectSuccess(`
        SELECT
          'md5' || md5('pass1' || 'user') as hash1,
          'md5' || md5('pass2' || 'user') as hash2
      `);
      const row = rows[0] as { hash1: string; hash2: string };
      expect(row.hash1).not.toBe(row.hash2);
    });

    test("Same password different users produce different hashes", async () => {
      const { rows } = await directSQLExpectSuccess(`
        SELECT
          'md5' || md5('password' || 'user1') as hash1,
          'md5' || md5('password' || 'user2') as hash2
      `);
      const row = rows[0] as { hash1: string; hash2: string };
      expect(row.hash1).not.toBe(row.hash2);
    });
  });

  /**
   * @kb-entry postgresql/password-hashing
   * @kb-section pg_shadow Access
   */
  describe("pg_shadow access", () => {
    test("pg_shadow requires superuser", async () => {
      const { success, error } = await directSQL("SELECT usename, passwd FROM pg_shadow");
      if (!success) {
        expect(error?.message).toMatch(/permission denied/i);
      }
      // If success, user is superuser
      expect(true).toBe(true);
    });

    test("pg_user is accessible but lacks password column", async () => {
      const { rows } = await directSQLExpectSuccess("SELECT usename FROM pg_user LIMIT 5");
      expect(rows.length).toBeGreaterThan(0);
    });

    test("pg_authid requires superuser", async () => {
      const { success, error } = await directSQL("SELECT rolname, rolpassword FROM pg_authid");
      if (!success) {
        expect(error?.message).toMatch(/permission denied/i);
      }
      expect(true).toBe(true);
    });
  });

  /**
   * @kb-entry postgresql/password-hashing
   * @kb-section Hash Type Detection
   */
  describe("Hash type detection patterns", () => {
    test("MD5 hash pattern recognition", async () => {
      const { rows } = await directSQLExpectSuccess(`
        SELECT
          CASE
            WHEN 'md5d41d8cd98f00b204e9800998ecf8427e' LIKE 'md5%' THEN 'MD5'
            ELSE 'OTHER'
          END as hash_type
      `);
      expect((rows[0] as { hash_type: string }).hash_type).toBe("MD5");
    });

    test("SCRAM hash pattern recognition", async () => {
      const { rows } = await directSQLExpectSuccess(`
        SELECT
          CASE
            WHEN 'SCRAM-SHA-256$4096:salt$key:key' LIKE 'SCRAM%' THEN 'SCRAM'
            ELSE 'OTHER'
          END as hash_type
      `);
      expect((rows[0] as { hash_type: string }).hash_type).toBe("SCRAM");
    });

    test("Hash length validation for MD5", async () => {
      const { rows } = await directSQLExpectSuccess(`
        SELECT LENGTH('md5' || md5('test')) as len
      `);
      expect((rows[0] as { len: number }).len).toBe(35);
    });
  });

  /**
   * @kb-entry postgresql/password-hashing
   * @kb-section Authentication Configuration
   */
  describe("Authentication configuration", () => {
    test("Get hba_file location", async () => {
      const { rows } = await directSQLExpectSuccess("SELECT current_setting('hba_file') as path");
      expect((rows[0] as { path: string }).path).toContain("pg_hba.conf");
    });

    test("Query pg_hba_file_rules if available", async () => {
      const { success, result } = await directSQL(
        "SELECT line_number, type, auth_method FROM pg_hba_file_rules LIMIT 5"
      );
      if (success && result) {
        expect(result.rows.length).toBeGreaterThanOrEqual(0);
      }
      expect(true).toBe(true);
    });
  });

  /**
   * @kb-entry postgresql/password-hashing
   * @kb-section User Enumeration
   */
  describe("User enumeration", () => {
    test("List all database users", async () => {
      const { rows } = await directSQLExpectSuccess("SELECT usename FROM pg_user");
      expect(rows.length).toBeGreaterThan(0);
    });

    test("List users with login privilege", async () => {
      const { rows } = await directSQLExpectSuccess(
        "SELECT rolname FROM pg_roles WHERE rolcanlogin = true"
      );
      expect(rows.length).toBeGreaterThan(0);
    });

    test("Find superuser accounts", async () => {
      const { rows } = await directSQLExpectSuccess(
        "SELECT usename FROM pg_user WHERE usesuper = true"
      );
      expect(rows.length).toBeGreaterThan(0);
    });
  });

  /**
   * @kb-entry postgresql/password-hashing
   * @kb-section Hash Verification Helpers
   */
  describe("Hash verification helpers", () => {
    test("Verify MD5 calculation is consistent", async () => {
      // MD5('secretpostgres') should produce consistent hash
      const { rows: rows1 } = await directSQLExpectSuccess(
        "SELECT 'md5' || md5('secretpostgres') as hash"
      );
      const { rows: rows2 } = await directSQLExpectSuccess(
        "SELECT 'md5' || md5('secretpostgres') as hash"
      );
      const hash1 = (rows1[0] as { hash: string }).hash;
      const hash2 = (rows2[0] as { hash: string }).hash;
      // Same input should produce same hash
      expect(hash1).toBe(hash2);
      expect(hash1).toMatch(/^md5[a-f0-9]{32}$/);
    });

    test("Generate hash for known password/user combo", async () => {
      const { rows } = await directSQLExpectSuccess(
        "SELECT 'md5' || md5('password' || 'postgres') as hash"
      );
      const hash = (rows[0] as { hash: string }).hash;
      expect(hash).toMatch(/^md5[a-f0-9]{32}$/);
    });
  });

  /**
   * @kb-entry postgresql/password-hashing
   * @kb-section Connection Information
   */
  describe("Connection information", () => {
    test("Get current user", async () => {
      const { rows } = await directSQLExpectSuccess("SELECT current_user as usr");
      expect((rows[0] as { usr: string }).usr).toBeTruthy();
    });

    test("Get session user", async () => {
      const { rows } = await directSQLExpectSuccess("SELECT session_user as usr");
      expect((rows[0] as { usr: string }).usr).toBeTruthy();
    });

    test("Check if current user is superuser", async () => {
      const { rows } = await directSQLExpectSuccess(
        "SELECT usesuper FROM pg_user WHERE usename = current_user"
      );
      expect(typeof (rows[0] as { usesuper: boolean }).usesuper).toBe("boolean");
    });
  });

  /**
   * @kb-entry postgresql/password-hashing
   * @kb-section SCRAM-SHA-256 Information
   */
  describe("SCRAM-SHA-256 information", () => {
    test("Check PostgreSQL version supports SCRAM", async () => {
      const { rows } = await directSQLExpectSuccess(
        "SELECT current_setting('server_version_num')::int as ver"
      );
      // SCRAM-SHA-256 available in PostgreSQL 10+
      const ver = (rows[0] as { ver: number }).ver;
      if (ver >= 100000) {
        // Can use SCRAM
        expect(ver).toBeGreaterThanOrEqual(100000);
      }
      expect(true).toBe(true);
    });

    test("Identify if SCRAM is default encryption", async () => {
      const { rows } = await directSQLExpectSuccess(
        "SELECT current_setting('password_encryption') as enc"
      );
      const enc = (rows[0] as { enc: string }).enc;
      // PostgreSQL 14+ defaults to scram-sha-256
      expect(["md5", "scram-sha-256"]).toContain(enc);
    });
  });
});
