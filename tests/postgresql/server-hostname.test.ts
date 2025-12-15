/**
 * PostgreSQL Server Hostname Tests
 *
 * @kb-coverage postgresql/server-hostname - Full coverage
 */

import { describe, test, expect, beforeAll, afterAll } from "vitest";
import {
  initDirectRunner,
  cleanupDirectRunner,
  directSQL,
  directSQLExpectSuccess,
} from "../../src/runner/direct.js";
import { logger } from "../../src/utils/logger.js";

describe("PostgreSQL Server Hostname", () => {
  beforeAll(async () => {
    logger.setLevel("warn");
    await initDirectRunner();
  }, 30000);

  afterAll(async () => {
    await cleanupDirectRunner();
  }, 10000);

  /**
   * @kb-entry postgresql/server-hostname
   * @kb-section Server IP Address
   */
  describe("Server IP address", () => {
    test("inet_server_addr() returns server IP", async () => {
      const { success, result } = await directSQL("SELECT inet_server_addr()");
      // May return NULL in some configurations
      expect(success).toBe(true);
      if (result && result.rows.length > 0) {
        const addr = (result.rows[0] as { inet_server_addr: string | null }).inet_server_addr;
        // Address can be null in local connections
        expect(addr === null || typeof addr === "string").toBe(true);
      }
    });
  });

  /**
   * @kb-entry postgresql/server-hostname
   * @kb-section Server Port
   */
  describe("Server port", () => {
    test("inet_server_port() returns server port", async () => {
      const { success, result } = await directSQL("SELECT inet_server_port()");
      expect(success).toBe(true);
      if (result && result.rows.length > 0) {
        const port = (result.rows[0] as { inet_server_port: number | null }).inet_server_port;
        // Port can be null in local connections
        expect(port === null || typeof port === "number").toBe(true);
      }
    });
  });

  /**
   * @kb-entry postgresql/server-hostname
   * @kb-section Client Information
   */
  describe("Client information", () => {
    test("inet_client_addr() returns client IP", async () => {
      const { success } = await directSQL("SELECT inet_client_addr()");
      expect(success).toBe(true);
    });

    test("inet_client_port() returns client port", async () => {
      const { success } = await directSQL("SELECT inet_client_port()");
      expect(success).toBe(true);
    });
  });

  /**
   * @kb-entry postgresql/server-hostname
   * @kb-section Combined Network Information
   */
  describe("Combined network information", () => {
    test("Query all network info at once", async () => {
      const { success, result } = await directSQL(`
        SELECT
          inet_server_addr() AS server_ip,
          inet_server_port() AS server_port,
          inet_client_addr() AS client_ip,
          inet_client_port() AS client_port
      `);
      expect(success).toBe(true);
      if (result) {
        expect(result.rows.length).toBe(1);
      }
    });
  });

  /**
   * @kb-entry postgresql/server-hostname
   * @kb-section Configuration Settings
   */
  describe("Configuration settings", () => {
    test("Query listen_addresses setting", async () => {
      const { rows } = await directSQLExpectSuccess(
        "SELECT current_setting('listen_addresses') as addr"
      );
      const addr = (rows[0] as { addr: string }).addr;
      expect(addr).toBeTruthy();
    });

    test("Query port setting", async () => {
      const { rows } = await directSQLExpectSuccess("SELECT current_setting('port') as port");
      const port = (rows[0] as { port: string }).port;
      expect(parseInt(port, 10)).toBeGreaterThan(0);
    });

    test("Query data_directory setting", async () => {
      const { rows } = await directSQLExpectSuccess(
        "SELECT current_setting('data_directory') as dir"
      );
      const dir = (rows[0] as { dir: string }).dir;
      expect(dir).toContain("data");
    });
  });

  /**
   * @kb-entry postgresql/server-hostname
   * @kb-section Injection Examples
   */
  describe("Injection context examples", () => {
    test("UNION SELECT server address", async () => {
      const { success } = await directSQL(`
        SELECT id, username FROM users WHERE id = 1
        UNION SELECT 999, inet_server_addr()::text
      `);
      expect(success).toBe(true);
    });

    test("UNION SELECT server port", async () => {
      const { success } = await directSQL(`
        SELECT id, username FROM users WHERE id = 1
        UNION SELECT 999, inet_server_port()::text
      `);
      expect(success).toBe(true);
    });

    test("UNION SELECT combined address:port", async () => {
      const { success } = await directSQL(`
        SELECT id, username FROM users WHERE id = 1
        UNION SELECT 999, COALESCE(inet_server_addr()::text, 'local') || ':' || COALESCE(inet_server_port()::text, '?')
      `);
      expect(success).toBe(true);
    });
  });

  /**
   * @kb-entry postgresql/server-hostname
   * @kb-section Operating System Information
   */
  describe("Operating system information", () => {
    test("version() includes OS information", async () => {
      const { rows } = await directSQLExpectSuccess("SELECT version()");
      const version = (rows[0] as { version: string }).version;
      expect(version).toMatch(/PostgreSQL/);
      // Version string typically includes OS info
    });
  });

  /**
   * @kb-entry postgresql/server-hostname
   * @kb-section Host-based Information Gathering
   */
  describe("Host-based information gathering", () => {
    test("Combine multiple info sources", async () => {
      const { rows } = await directSQLExpectSuccess(`
        SELECT
          current_database() as db,
          current_user as usr,
          current_setting('port') as port,
          current_setting('server_version') as ver
      `);
      const row = rows[0] as { db: string; usr: string; port: string; ver: string };
      expect(row.db).toBe("vulndb");
      expect(row.usr).toBe("postgres");
      expect(row.port).toBeTruthy();
      expect(row.ver).toBeTruthy();
    });
  });
});
