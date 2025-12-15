/**
 * PostgreSQL Default Databases Tests
 *
 * Tests for default databases, schemas, and system tables.
 *
 * @kb-coverage postgresql/default-databases - Full coverage
 */

import { describe, test, expect, beforeAll, afterAll } from "vitest";
import {
  initDirectRunner,
  cleanupDirectRunner,
  directSQLExpectSuccess,
} from "../../src/runner/direct.js";
import { logger } from "../../src/utils/logger.js";

describe("PostgreSQL Default Databases", () => {
  beforeAll(async () => {
    logger.setLevel("warn");
    await initDirectRunner();
  }, 30000);

  afterAll(async () => {
    await cleanupDirectRunner();
  }, 10000);

  /**
   * @kb-entry postgresql/default-databases
   * @kb-section Default Databases
   */
  describe("Default databases", () => {
    test("postgres database exists", async () => {
      const { rows } = await directSQLExpectSuccess(
        "SELECT datname FROM pg_database WHERE datname = 'postgres'"
      );
      expect(rows.length).toBe(1);
    });

    test("template0 database exists", async () => {
      const { rows } = await directSQLExpectSuccess(
        "SELECT datname FROM pg_database WHERE datname = 'template0'"
      );
      expect(rows.length).toBe(1);
    });

    test("template1 database exists", async () => {
      const { rows } = await directSQLExpectSuccess(
        "SELECT datname FROM pg_database WHERE datname = 'template1'"
      );
      expect(rows.length).toBe(1);
    });

    test("List all databases", async () => {
      const { rows } = await directSQLExpectSuccess("SELECT datname FROM pg_database");
      const dbNames = rows.map((r) => (r as { datname: string }).datname);
      expect(dbNames).toContain("postgres");
      expect(dbNames).toContain("template0");
      expect(dbNames).toContain("template1");
    });
  });

  /**
   * @kb-entry postgresql/default-databases
   * @kb-section Important Schemas
   */
  describe("Important schemas", () => {
    test("pg_catalog schema exists", async () => {
      const { rows } = await directSQLExpectSuccess(
        "SELECT nspname FROM pg_namespace WHERE nspname = 'pg_catalog'"
      );
      expect(rows.length).toBe(1);
    });

    test("information_schema exists", async () => {
      const { rows } = await directSQLExpectSuccess(
        "SELECT nspname FROM pg_namespace WHERE nspname = 'information_schema'"
      );
      expect(rows.length).toBe(1);
    });

    test("public schema exists", async () => {
      const { rows } = await directSQLExpectSuccess(
        "SELECT nspname FROM pg_namespace WHERE nspname = 'public'"
      );
      expect(rows.length).toBe(1);
    });

    test("List all schemas", async () => {
      const { rows } = await directSQLExpectSuccess(
        "SELECT nspname FROM pg_namespace WHERE nspname NOT LIKE 'pg_toast%' AND nspname NOT LIKE 'pg_temp%'"
      );
      expect(rows.length).toBeGreaterThan(0);
    });
  });

  /**
   * @kb-entry postgresql/default-databases
   * @kb-section Key System Tables - pg_catalog
   */
  describe("Key system tables (pg_catalog)", () => {
    test("pg_database table accessible", async () => {
      const { rows } = await directSQLExpectSuccess("SELECT COUNT(*) as cnt FROM pg_database");
      expect((rows[0] as { cnt: string }).cnt).toBeTruthy();
    });

    test("pg_user view accessible", async () => {
      const { rows } = await directSQLExpectSuccess("SELECT COUNT(*) as cnt FROM pg_user");
      expect((rows[0] as { cnt: string }).cnt).toBeTruthy();
    });

    test("pg_tables view accessible", async () => {
      const { rows } = await directSQLExpectSuccess("SELECT COUNT(*) as cnt FROM pg_tables");
      expect((rows[0] as { cnt: string }).cnt).toBeTruthy();
    });

    test("pg_roles table accessible", async () => {
      const { rows } = await directSQLExpectSuccess("SELECT COUNT(*) as cnt FROM pg_roles");
      expect((rows[0] as { cnt: string }).cnt).toBeTruthy();
    });

    test("pg_catalog.pg_tables accessible with schema prefix", async () => {
      const { rows } = await directSQLExpectSuccess(
        "SELECT COUNT(*) as cnt FROM pg_catalog.pg_tables"
      );
      expect((rows[0] as { cnt: string }).cnt).toBeTruthy();
    });
  });

  /**
   * @kb-entry postgresql/default-databases
   * @kb-section Key System Tables - information_schema
   */
  describe("Key system tables (information_schema)", () => {
    test("information_schema.tables accessible", async () => {
      const { rows } = await directSQLExpectSuccess(
        "SELECT COUNT(*) as cnt FROM information_schema.tables"
      );
      expect((rows[0] as { cnt: string }).cnt).toBeTruthy();
    });

    test("information_schema.columns accessible", async () => {
      const { rows } = await directSQLExpectSuccess(
        "SELECT COUNT(*) as cnt FROM information_schema.columns"
      );
      expect((rows[0] as { cnt: string }).cnt).toBeTruthy();
    });

    test("information_schema.schemata accessible", async () => {
      const { rows } = await directSQLExpectSuccess(
        "SELECT COUNT(*) as cnt FROM information_schema.schemata"
      );
      expect((rows[0] as { cnt: string }).cnt).toBeTruthy();
    });

    test("information_schema.routines accessible", async () => {
      const { rows } = await directSQLExpectSuccess(
        "SELECT COUNT(*) as cnt FROM information_schema.routines"
      );
      expect((rows[0] as { cnt: string }).cnt).toBeTruthy();
    });
  });

  /**
   * @kb-entry postgresql/default-databases
   * @kb-section Database Enumeration Queries
   */
  describe("Database enumeration queries", () => {
    test("Get current database name", async () => {
      const { rows } = await directSQLExpectSuccess("SELECT current_database() as db");
      expect((rows[0] as { db: string }).db).toBeTruthy();
    });

    test("List all user tables", async () => {
      const { rows } = await directSQLExpectSuccess(
        "SELECT tablename FROM pg_tables WHERE schemaname = 'public'"
      );
      expect(rows.length).toBeGreaterThanOrEqual(0);
    });

    test("List tables via information_schema", async () => {
      const { rows } = await directSQLExpectSuccess(
        "SELECT table_name FROM information_schema.tables WHERE table_schema = 'public'"
      );
      expect(rows.length).toBeGreaterThanOrEqual(0);
    });

    test("Get table columns via information_schema", async () => {
      const { rows } = await directSQLExpectSuccess(`
        SELECT column_name, data_type
        FROM information_schema.columns
        WHERE table_schema = 'public' AND table_name = 'users'
        LIMIT 10
      `);
      expect(rows.length).toBeGreaterThanOrEqual(0);
    });
  });

  /**
   * @kb-entry postgresql/default-databases
   * @kb-section Template Database Properties
   */
  describe("Template database properties", () => {
    test("template0 is not connectable by default", async () => {
      const { rows } = await directSQLExpectSuccess(
        "SELECT datallowconn FROM pg_database WHERE datname = 'template0'"
      );
      expect((rows[0] as { datallowconn: boolean }).datallowconn).toBe(false);
    });

    test("template1 is connectable", async () => {
      const { rows } = await directSQLExpectSuccess(
        "SELECT datallowconn FROM pg_database WHERE datname = 'template1'"
      );
      expect((rows[0] as { datallowconn: boolean }).datallowconn).toBe(true);
    });

    test("postgres database is connectable", async () => {
      const { rows } = await directSQLExpectSuccess(
        "SELECT datallowconn FROM pg_database WHERE datname = 'postgres'"
      );
      expect((rows[0] as { datallowconn: boolean }).datallowconn).toBe(true);
    });
  });

  /**
   * @kb-entry postgresql/default-databases
   * @kb-section Cross-Schema Queries
   */
  describe("Cross-schema queries", () => {
    test("Query pg_catalog and information_schema show same tables", async () => {
      const { rows: pgRows } = await directSQLExpectSuccess(
        "SELECT COUNT(*) as cnt FROM pg_catalog.pg_tables WHERE schemaname = 'public'"
      );
      const { rows: isRows } = await directSQLExpectSuccess(
        "SELECT COUNT(*) as cnt FROM information_schema.tables WHERE table_schema = 'public'"
      );
      expect((pgRows[0] as { cnt: string }).cnt).toBe((isRows[0] as { cnt: string }).cnt);
    });

    test("information_schema provides portable metadata", async () => {
      const { rows } = await directSQLExpectSuccess(`
        SELECT table_catalog, table_schema, table_name, table_type
        FROM information_schema.tables
        WHERE table_schema = 'public'
        LIMIT 5
      `);
      expect(rows.length).toBeGreaterThanOrEqual(0);
    });
  });
});
