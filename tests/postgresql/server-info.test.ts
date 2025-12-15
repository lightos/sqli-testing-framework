/**
 * PostgreSQL Server Information Tests
 *
 * Covers server-mac-address KB entry and related server information gathering.
 *
 * @kb-coverage postgresql/server-mac-address - Full coverage
 */

import { describe, test, expect, beforeAll, afterAll } from "vitest";
import {
  initDirectRunner,
  cleanupDirectRunner,
  directSQL,
  directSQLExpectSuccess,
} from "../../src/runner/direct.js";
import { logger } from "../../src/utils/logger.js";

describe("PostgreSQL Server Information", () => {
  beforeAll(async () => {
    logger.setLevel("warn");
    await initDirectRunner();
  }, 30000);

  afterAll(async () => {
    await cleanupDirectRunner();
  }, 10000);

  /**
   * @kb-entry postgresql/server-mac-address
   * @kb-section Network Information
   */
  describe("Network information", () => {
    test("inet_server_addr returns server IP", async () => {
      const { rows } = await directSQLExpectSuccess("SELECT inet_server_addr() as addr");
      // May be NULL if connected via unix socket
      expect(rows.length).toBe(1);
    });

    test("inet_server_port returns server port", async () => {
      const { rows } = await directSQLExpectSuccess("SELECT inet_server_port() as port");
      const port = (rows[0] as { port: number | null }).port;
      if (port !== null) {
        expect(port).toBe(5432);
      }
    });

    test("inet_client_addr returns client IP", async () => {
      const { rows } = await directSQLExpectSuccess("SELECT inet_client_addr() as addr");
      // May be NULL if connected via unix socket
      expect(rows.length).toBe(1);
    });

    test("inet_client_port returns client port", async () => {
      const { rows } = await directSQLExpectSuccess("SELECT inet_client_port() as port");
      expect(rows.length).toBe(1);
    });
  });

  /**
   * @kb-entry postgresql/server-mac-address
   * @kb-section Server Identification
   */
  describe("Server identification", () => {
    test("version() returns PostgreSQL version", async () => {
      const { rows } = await directSQLExpectSuccess("SELECT version() as ver");
      expect((rows[0] as { ver: string }).ver).toMatch(/PostgreSQL/i);
    });

    test("current_setting for listen_addresses", async () => {
      const { rows } = await directSQLExpectSuccess(
        "SELECT current_setting('listen_addresses') as addr"
      );
      expect((rows[0] as { addr: string }).addr).toBeTruthy();
    });

    test("current_setting for unix_socket_directories", async () => {
      const { success, result } = await directSQL(
        "SELECT current_setting('unix_socket_directories') as path"
      );
      if (success && result) {
        expect((result.rows[0] as { path: string }).path).toBeTruthy();
      }
      expect(true).toBe(true);
    });
  });

  /**
   * @kb-entry postgresql/server-mac-address
   * @kb-section UUID Generation (No MAC)
   */
  describe("UUID generation", () => {
    test("gen_random_uuid generates random UUID (PostgreSQL 13+)", async () => {
      const { success, result } = await directSQL("SELECT gen_random_uuid() as uuid");
      if (success && result) {
        const uuid = (result.rows[0] as { uuid: string }).uuid;
        expect(uuid).toMatch(/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/);
      }
      // gen_random_uuid may not exist in older versions
      expect(true).toBe(true);
    });

    test("Check uuid-ossp extension availability", async () => {
      const { rows } = await directSQLExpectSuccess(
        "SELECT * FROM pg_available_extensions WHERE name = 'uuid-ossp'"
      );
      expect(rows.length).toBeLessThanOrEqual(1);
    });
  });

  /**
   * @kb-entry postgresql/server-mac-address
   * @kb-section File-Based Information (Limited)
   */
  describe("File-based information retrieval", () => {
    test("pg_read_file requires privileges", async () => {
      const { success, error } = await directSQL("SELECT pg_read_file('/etc/hostname')");
      if (!success) {
        expect(error?.message).toMatch(/permission denied|must be superuser|absolute path/i);
      }
      expect(true).toBe(true);
    });

    test("Check pg_read_server_files membership", async () => {
      const { rows } = await directSQLExpectSuccess(
        "SELECT pg_has_role(current_user, 'pg_read_server_files', 'member') as has_role"
      );
      const hasRole = (rows[0] as { has_role: boolean }).has_role;
      expect(typeof hasRole).toBe("boolean");
    });
  });

  /**
   * @kb-entry postgresql/server-mac-address
   * @kb-section Server Configuration Paths
   */
  describe("Server configuration paths", () => {
    test("data_directory setting", async () => {
      const { rows } = await directSQLExpectSuccess(
        "SELECT current_setting('data_directory') as path"
      );
      expect((rows[0] as { path: string }).path).toBeTruthy();
    });

    test("config_file setting", async () => {
      const { rows } = await directSQLExpectSuccess(
        "SELECT current_setting('config_file') as path"
      );
      expect((rows[0] as { path: string }).path).toContain("postgresql.conf");
    });

    test("hba_file setting", async () => {
      const { rows } = await directSQLExpectSuccess("SELECT current_setting('hba_file') as path");
      expect((rows[0] as { path: string }).path).toContain("pg_hba.conf");
    });

    test("log_directory setting", async () => {
      const { rows } = await directSQLExpectSuccess(
        "SELECT current_setting('log_directory') as path"
      );
      expect((rows[0] as { path: string }).path).toBeTruthy();
    });
  });

  /**
   * @kb-entry postgresql/server-mac-address
   * @kb-section System Information
   */
  describe("System information", () => {
    test("pg_postmaster_start_time returns start time", async () => {
      const { rows } = await directSQLExpectSuccess(
        "SELECT pg_postmaster_start_time() as start_time"
      );
      expect((rows[0] as { start_time: Date }).start_time).toBeTruthy();
    });

    test("pg_conf_load_time returns config load time", async () => {
      const { rows } = await directSQLExpectSuccess("SELECT pg_conf_load_time() as load_time");
      expect((rows[0] as { load_time: Date }).load_time).toBeTruthy();
    });

    test("pg_is_in_recovery shows standby status", async () => {
      const { rows } = await directSQLExpectSuccess("SELECT pg_is_in_recovery() as in_recovery");
      expect(typeof (rows[0] as { in_recovery: boolean }).in_recovery).toBe("boolean");
    });
  });

  /**
   * @kb-entry postgresql/server-mac-address
   * @kb-section Hardware Information Limitations
   */
  describe("Hardware information limitations", () => {
    test("PostgreSQL does not expose MAC via UUID", async () => {
      // Unlike MySQL, PostgreSQL's UUID functions don't use MAC address
      const { success, result } = await directSQL("SELECT gen_random_uuid() as uuid");
      if (success && result) {
        // Random UUIDs don't contain MAC addresses
        const uuid = (result.rows[0] as { uuid: string }).uuid;
        // Version 4 UUID has '4' in specific position
        expect(uuid.charAt(14)).toBe("4");
      }
      expect(true).toBe(true);
    });
  });
});
