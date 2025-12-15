/**
 * PostgreSQL Database Names Enumeration Tests
 *
 * @kb-coverage postgresql/database-names - Full coverage
 */

import { describe, test, expect, beforeAll, afterAll } from "vitest";
import {
  initDirectRunner,
  cleanupDirectRunner,
  directSQLExpectSuccess,
} from "../../src/runner/direct.js";
import { logger } from "../../src/utils/logger.js";

describe("PostgreSQL Database Names Enumeration", () => {
  beforeAll(async () => {
    logger.setLevel("warn");
    await initDirectRunner();
  }, 30000);

  afterAll(async () => {
    await cleanupDirectRunner();
  }, 10000);

  /**
   * @kb-entry postgresql/database-names
   * @kb-section Current Database
   */
  describe("Current database", () => {
    test("current_database() returns database name", async () => {
      const { rows } = await directSQLExpectSuccess("SELECT current_database()");
      const dbName = (rows[0] as { current_database: string }).current_database;
      expect(dbName).toBe("vulndb");
    });

    test("current_catalog returns database name", async () => {
      const { rows } = await directSQLExpectSuccess("SELECT current_catalog");
      const dbName = (rows[0] as { current_catalog: string }).current_catalog;
      expect(dbName).toBe("vulndb");
    });
  });

  /**
   * @kb-entry postgresql/database-names
   * @kb-section Current Schema
   */
  describe("Current schema", () => {
    test("current_schema() returns current schema", async () => {
      const { rows } = await directSQLExpectSuccess("SELECT current_schema()");
      const schema = (rows[0] as { current_schema: string }).current_schema;
      expect(schema).toBe("public");
    });

    test("current_schemas(true) returns search path", async () => {
      const { rows } = await directSQLExpectSuccess("SELECT current_schemas(true)");
      const schemas = (rows[0] as { current_schemas: string[] }).current_schemas;
      expect(schemas).toContain("public");
    });

    test("SHOW search_path returns schema search path", async () => {
      const { rows } = await directSQLExpectSuccess("SHOW search_path");
      const searchPath = (rows[0] as { search_path: string }).search_path;
      expect(searchPath).toBeTruthy();
    });
  });

  /**
   * @kb-entry postgresql/database-names
   * @kb-section List All Databases
   */
  describe("List all databases", () => {
    test("Query pg_database for all databases", async () => {
      const { rows } = await directSQLExpectSuccess("SELECT datname FROM pg_database");
      const databases = rows.map((r) => (r as { datname: string }).datname);
      expect(databases).toContain("vulndb");
      expect(databases).toContain("postgres");
    });

    test("Filter out template databases", async () => {
      const { rows } = await directSQLExpectSuccess(
        "SELECT datname FROM pg_database WHERE datistemplate = false"
      );
      const databases = rows.map((r) => (r as { datname: string }).datname);
      expect(databases).toContain("vulndb");
    });

    test("Aggregate database names", async () => {
      const { rows } = await directSQLExpectSuccess(
        "SELECT string_agg(datname, ',') as dbs FROM pg_database"
      );
      const dbs = (rows[0] as { dbs: string }).dbs;
      expect(dbs).toContain("vulndb");
    });
  });

  /**
   * @kb-entry postgresql/database-names
   * @kb-section Database Information
   */
  describe("Database information", () => {
    test("Query database metadata", async () => {
      const { rows } = await directSQLExpectSuccess(
        "SELECT datname, encoding FROM pg_database WHERE datname = 'vulndb'"
      );
      expect(rows.length).toBe(1);
      expect((rows[0] as { datname: string }).datname).toBe("vulndb");
    });

    test("Query database with owner information", async () => {
      const { rows } = await directSQLExpectSuccess(`
        SELECT d.datname, r.rolname as owner
        FROM pg_database d
        JOIN pg_roles r ON d.datdba = r.oid
        WHERE d.datname = 'vulndb'
      `);
      expect(rows.length).toBe(1);
    });
  });

  /**
   * @kb-entry postgresql/database-names
   * @kb-section List Schemas
   */
  describe("List schemas", () => {
    test("Query schemas from information_schema", async () => {
      const { rows } = await directSQLExpectSuccess(
        "SELECT schema_name FROM information_schema.schemata"
      );
      const schemas = rows.map((r) => (r as { schema_name: string }).schema_name);
      expect(schemas).toContain("public");
    });

    test("Query schemas from pg_namespace", async () => {
      const { rows } = await directSQLExpectSuccess("SELECT nspname FROM pg_namespace");
      const schemas = rows.map((r) => (r as { nspname: string }).nspname);
      expect(schemas).toContain("public");
    });

    test("Filter user schemas only", async () => {
      const { rows } = await directSQLExpectSuccess(`
        SELECT nspname FROM pg_namespace
        WHERE nspname NOT LIKE 'pg_%' AND nspname != 'information_schema'
      `);
      const schemas = rows.map((r) => (r as { nspname: string }).nspname);
      expect(schemas).toContain("public");
    });
  });

  /**
   * @kb-entry postgresql/database-names
   * @kb-section Injection Examples
   */
  describe("Injection context examples", () => {
    test("UNION SELECT database names", async () => {
      const { rows } = await directSQLExpectSuccess(`
        SELECT id, username FROM users WHERE id = 1
        UNION SELECT 999, datname FROM pg_database
      `);
      const values = rows.map((r) => (r as { username: string }).username);
      expect(values).toContain("vulndb");
    });

    test("UNION SELECT current_database()", async () => {
      const { rows } = await directSQLExpectSuccess(`
        SELECT id, username FROM users WHERE id = 1
        UNION SELECT 999, current_database()
      `);
      const values = rows.map((r) => (r as { username: string }).username);
      expect(values).toContain("vulndb");
    });

    test("UNION SELECT schema names", async () => {
      const { rows } = await directSQLExpectSuccess(`
        SELECT id, username FROM users WHERE id = 1
        UNION SELECT 999, string_agg(schema_name,',') FROM information_schema.schemata
      `);
      expect(rows.length).toBeGreaterThan(0);
    });

    test("Boolean-based database name extraction", async () => {
      const { rows } = await directSQLExpectSuccess(`
        SELECT CASE
          WHEN SUBSTRING(current_database(),1,1)='v'
          THEN true
          ELSE false
        END as result
      `);
      expect((rows[0] as { result: boolean }).result).toBe(true);
    });
  });

  /**
   * @kb-entry postgresql/database-names
   * @kb-section Using LIMIT and OFFSET
   */
  describe("Using LIMIT and OFFSET", () => {
    test("Enumerate databases one by one", async () => {
      const { rows: first } = await directSQLExpectSuccess(
        "SELECT datname FROM pg_database LIMIT 1 OFFSET 0"
      );
      const { rows: second } = await directSQLExpectSuccess(
        "SELECT datname FROM pg_database LIMIT 1 OFFSET 1"
      );
      expect(first.length).toBe(1);
      expect(second.length).toBe(1);
      expect((first[0] as { datname: string }).datname).not.toBe(
        (second[0] as { datname: string }).datname
      );
    });
  });
});
