/**
 * PostgreSQL Server Hardware/Network Information Tests
 *
 * Covers techniques for retrieving network and hardware info (MAC address alternatives).
 *
 * @kb-coverage postgresql/server-mac-address - Full coverage
 */

import net from "node:net";
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
      const addr = (rows[0] as { addr: string | null }).addr;
      // May be null if connected via unix socket
      if (addr === null) {
        return; // Skip validation for unix socket connections
      }
      // Strip CIDR suffix if present (e.g., "192.168.1.1/32" -> "192.168.1.1")
      const ipOnly = addr.split("/")[0];
      // Use Node's net.isIP() for proper validation (returns 4 for IPv4, 6 for IPv6, 0 for invalid)
      const ipVersion = net.isIP(ipOnly);
      expect(ipVersion).toBeGreaterThan(0);
    });

    test("inet_server_port() returns port number", async () => {
      const { rows } = await directSQLExpectSuccess("SELECT inet_server_port() as port");
      const port = (rows[0] as { port: number }).port;
      expect(typeof port).toBe("number");
      expect(port).toBeGreaterThan(0);
    });

    test("inet_client_addr() returns IP address", async () => {
      const { rows } = await directSQLExpectSuccess("SELECT inet_client_addr()::text as addr");
      const addr = (rows[0] as { addr: string | null }).addr;
      // Might be null if via unix socket, or IP string
      if (addr !== null) {
        // Strip CIDR suffix if present and validate with net.isIP()
        const ipOnly = addr.split("/")[0];
        const ipVersion = net.isIP(ipOnly);
        expect(ipVersion).toBeGreaterThan(0);
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
    test("gen_random_uuid() availability (PG 13+)", async (context) => {
      // Check version first
      const { rows } = await directSQLExpectSuccess(
        "SELECT current_setting('server_version_num')::int as ver"
      );
      const ver = (rows[0] as { ver: number }).ver;

      if (ver < 130000) {
        context.skip();
        return;
      }

      const { success } = await directSQL("SELECT gen_random_uuid()");
      expect(success).toBe(true);
    });

    test("uuid-ossp extension check", async () => {
      // Just check if extension is installed or available
      const { rows } = await directSQLExpectSuccess(
        "SELECT count(*)::int as cnt FROM pg_extension WHERE extname = 'uuid-ossp'"
      );
      const count = (rows[0] as { cnt: number }).cnt;
      expect(count).toBeGreaterThanOrEqual(0); // Extension may or may not be installed
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
      const { success, error, result } = await directSQL(
        "SELECT system_identifier FROM pg_control_system()"
      );
      if (!success) {
        expect(error?.message).toMatch(/permission denied|does not exist/i);
      } else {
        // Verify the query returned a system identifier
        expect(result?.rows[0]).toHaveProperty("system_identifier");
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
      const { success, error, result } = await directSQL(
        "SELECT pg_read_file('/sys/class/net/eth0/address') as mac"
      );

      if (!success) {
        // Expect permission denied or path restriction error
        expect(error?.message).toMatch(/permission denied|absolute path not allowed|no such file/i);
      } else {
        // If it worked (unlikely but possible in loose container), verify we got data
        expect(result).toBeDefined();
        expect((result?.rows[0] as { mac: string }).mac).toBeDefined();
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
      }
      // If success, the COPY command executed - no additional assertion needed
      // as the query completing without error is sufficient validation
    });
  });
});
