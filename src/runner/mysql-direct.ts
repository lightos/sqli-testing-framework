/**
 * Direct SQL test runner for MySQL - executes queries directly against the database
 */

import { MySQLConnectionManager, createMySQLConnectionFromEnv } from "../db/mysql-connection.js";
import { MySQLAdapter, type MySQLExecutionResult } from "../db/mysql.js";
import { logger } from "../utils/logger.js";

let connection: MySQLConnectionManager | null = null;
let adapter: MySQLAdapter | null = null;

/**
 * Initialize the MySQL direct SQL runner
 */
export async function initMySQLDirectRunner(): Promise<void> {
  if (connection) {
    logger.warn("MySQL direct runner already initialized");
    return;
  }

  const conn = createMySQLConnectionFromEnv();
  try {
    await conn.connect();
    connection = conn;
    adapter = new MySQLAdapter(connection);
  } catch (error) {
    await conn.disconnect().catch(() => {
      // Ignore cleanup errors
    });
    throw error;
  }
}

/**
 * Cleanup the MySQL direct SQL runner
 */
export async function cleanupMySQLDirectRunner(): Promise<void> {
  if (connection) {
    let disconnectError: Error | null = null;
    try {
      await connection.disconnect();
    } catch (error) {
      disconnectError = error as Error;
      logger.error(`Failed to disconnect MySQL connection: ${disconnectError.message}`);
    } finally {
      connection = null;
      adapter = null;
    }
    if (disconnectError) {
      throw disconnectError;
    }
  }
}

/**
 * Execute SQL directly against the MySQL database
 */
export async function mysqlDirectSQL(sql: string): Promise<MySQLExecutionResult> {
  if (!adapter) {
    throw new Error("MySQL direct runner not initialized. Call initMySQLDirectRunner() first.");
  }

  return adapter.execute(sql);
}

/**
 * Execute SQL expecting it to succeed
 */
export async function mysqlDirectSQLExpectSuccess(
  sql: string
): Promise<{ rows: Record<string, unknown>[]; rowCount: number | null }> {
  if (!adapter) {
    throw new Error("MySQL direct runner not initialized. Call initMySQLDirectRunner() first.");
  }

  const result = await adapter.executeExpectingSuccess(sql);
  return { rows: result.rows, rowCount: result.rowCount };
}

/**
 * Execute SQL expecting it to fail
 */
export async function mysqlDirectSQLExpectError(sql: string): Promise<Error> {
  if (!adapter) {
    throw new Error("MySQL direct runner not initialized. Call initMySQLDirectRunner() first.");
  }

  return adapter.executeExpectingError(sql);
}

/**
 * Test timing-based injection directly.
 *
 * Validation logic:
 * - Lower bound: timing >= (expectedDelayMs - toleranceMs)
 * - Upper bound: timing <= (maxExpectedMs + toleranceMs) when maxExpectedMs is provided
 *
 * Note: toleranceMs is subtracted from the lower bound and added to the upper bound,
 * allowing for timing variance in both directions. When maxExpectedMs is omitted,
 * no upper bound check is performed.
 *
 * @param sql - SQL query to execute
 * @param expectedDelayMs - Expected delay in milliseconds (lower bound before tolerance)
 * @param toleranceMs - Tolerance in ms: subtracted from lower bound, added to upper bound (default 200ms)
 * @param maxExpectedMs - Optional upper bound (exclusive before tolerance is added)
 */
export async function mysqlDirectTimingTest(
  sql: string,
  expectedDelayMs: number,
  toleranceMs = 200,
  maxExpectedMs?: number
): Promise<boolean> {
  if (!adapter) {
    throw new Error("MySQL direct runner not initialized. Call initMySQLDirectRunner() first.");
  }

  return adapter.testTimingInjection(sql, expectedDelayMs, toleranceMs, maxExpectedMs);
}

/**
 * Get MySQL version info
 */
export async function getMySQLVersion(): Promise<{
  major: number;
  minor: number;
  full: string;
}> {
  if (!adapter) {
    throw new Error("MySQL direct runner not initialized. Call initMySQLDirectRunner() first.");
  }

  return adapter.getVersionInfo();
}

/**
 * Get the MySQL adapter for advanced operations
 */
export function getMySQLAdapter(): MySQLAdapter {
  if (!adapter) {
    throw new Error("MySQL direct runner not initialized. Call initMySQLDirectRunner() first.");
  }

  return adapter;
}
