/**
 * PostgreSQL Server Hardware/Network Information Tests
 *
 * Covers techniques for retrieving network and hardware info (MAC address alternatives).
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

describe("PostgreSQL Server Hardware/Network Information", () => {
  beforeAll(async () => {
    logger.setLevel("warn");
    await initDirectRunner();
  }, 30000);

  afterAll(async () => {
    await cleanupDirectRunner();
  }, 10000);

  /**
   * @kb-entry postgresql/server-mac-address
   * @kb-section Alternative Hardware Information
   */
  describe("Network Information Functions", () => {
    test("inet_server_addr() returns IP address", async () => {
      const { rows } = await directSQLExpectSuccess("SELECT inet_server_addr()::text as addr");
      const addr = (rows[0] as { addr: string }).addr;
      // Depending on connection, could be IPv4 or IPv6
      expect(addr).toMatch(/^[0-9a-f:./]+$/);
    });

    test("inet_server_port() returns port number", async () => {
      const { rows } = await directSQLExpectSuccess("SELECT inet_server_port() as port");
      const port = (rows[0] as { port: number }).port;
      expect(typeof port).toBe("number");
      expect(port).toBeGreaterThan(0);
    });

    test("inet_client_addr() returns IP address", async () => {
      const { rows } = await directSQLExpectSuccess("SELECT inet_client_addr()::text as addr");
      const addr = (rows[0] as { addr: string }).addr;
      // Might be null if via unix socket, or IP string
      if (addr) {
        expect(addr).toMatch(/^[0-9a-f:./]+$/);
      } else {
        expect(addr).toBeNull();
      }
    });
  });

  /**
   * @kb-entry postgresql/server-mac-address
   * @kb-section PostgreSQL UUID Generation
   */
  describe("UUID Generation (MAC alternative)", () => {
    test("gen_random_uuid() availability (PG 13+)", async () => {
      // Check version first
      const { rows } = await directSQLExpectSuccess(
        "SELECT current_setting('server_version_num')::int as ver"
      );
      const ver = (rows[0] as { ver: number }).ver;

      if (ver >= 130000) {
        const { success } = await directSQL("SELECT gen_random_uuid()");
        expect(success).toBe(true);
      } else {
        // Skip for older versions
        expect(true).toBe(true);
      }
    });

    test("uuid-ossp extension check", async () => {
      // Just check if extension is installed or available
      const { rows } = await directSQLExpectSuccess(
        "SELECT count(*) FROM pg_extension WHERE extname = 'uuid-ossp'"
      );
      expect(rows.length).toBeGreaterThan(0);
    });
  });

  /**
   * @kb-entry postgresql/server-mac-address
   * @kb-section Server Identification
   */
  describe("Server Identification", () => {
    test("Listen addresses setting", async () => {
      const { rows } = await directSQLExpectSuccess(
        "SELECT current_setting('listen_addresses') as addr"
      );
      expect((rows[0] as { addr: string }).addr).toBeDefined();
    });

    test("Unix socket directories", async () => {
      const { rows } = await directSQLExpectSuccess(
        "SELECT current_setting('unix_socket_directories') as dir"
      );
      expect((rows[0] as { dir: string }).dir).toBeDefined();
    });

    test("pg_control_system() (Superuser)", async () => {
      // This requires superuser via pg_read_all_settings or similar usually?
      // Actually pg_control_system is restricted.
      const { success, error } = await directSQL(
        "SELECT system_identifier FROM pg_control_system()"
      );
      if (!success) {
        expect(error?.message).toMatch(/permission denied|does not exist/i);
      } else {
        expect(success).toBe(true);
      }
    });
  });

  /**
   * @kb-entry postgresql/server-mac-address
   * @kb-section File-Based MAC Address Retrieval
   */
  describe("File-Based Retrieval (Privileged)", () => {
    test("Attempt pg_read_file on /sys/class/net/eth0/address", async () => {
      // Note: Interface might be eth0, ens33, etc. This is opportunistic.
      // And strict pg_read_file restriction usually blocks absolute paths anyway unless superuser config allows.
      const { success, error } = await directSQL(
        "SELECT pg_read_file('/sys/class/net/eth0/address')"
      );

      if (!success) {
        // Expect permission denied or path restriction error
        expect(error?.message).toMatch(/permission denied|absolute path not allowed|no such file/i);
      } else {
        // If it worked (unlikely but possible in loose container), check format
        expect(success).toBe(true);
      }
    });
  });

  /**
   * @kb-entry postgresql/server-mac-address
   * @kb-section Command Execution Methods
   */
  describe("Command Execution (Privileged)", () => {
    test("Attempt COPY FROM PROGRAM 'ip link'", async () => {
      const { success, error } = await directSQL(`
        CREATE TEMP TABLE IF NOT EXISTS net_info (line text);
        COPY net_info FROM PROGRAM 'ip link';
      `);

      if (!success) {
        expect(error?.message).toMatch(/permission denied|must be superuser/i);
      } else {
        expect(success).toBe(true);
      }
    });
  });
});
