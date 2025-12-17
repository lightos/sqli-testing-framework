/**
 * Direct SQL test runner - executes queries directly against the database
 */

import { ConnectionManager, createConnectionFromEnv } from "../db/connection.js";
import { PostgreSQLAdapter, type SQLExecutionResult } from "../db/postgresql.js";
import { logger } from "../utils/logger.js";

let connection: ConnectionManager | null = null;
let adapter: PostgreSQLAdapter | null = null;

/**
 * Initialize the direct SQL runner
 */
export async function initDirectRunner(): Promise<void> {
  if (connection) {
    logger.warn("Direct runner already initialized");
    return;
  }

  connection = createConnectionFromEnv();
  await connection.connect();
  adapter = new PostgreSQLAdapter(connection);
}

/**
 * Cleanup the direct SQL runner
 */
export async function cleanupDirectRunner(): Promise<void> {
  if (connection) {
    await connection.disconnect();
    connection = null;
    adapter = null;
  }
}

/**
 * Execute SQL directly against the database
 */
export async function directSQL(sql: string): Promise<SQLExecutionResult> {
  if (!adapter) {
    throw new Error("Direct runner not initialized. Call initDirectRunner() first.");
  }

  return adapter.execute(sql);
}

/**
 * Execute parameterized SQL directly against the database
 */
export async function directSQLParameterized(
  sql: string,
  params: unknown[]
): Promise<SQLExecutionResult> {
  if (!adapter) {
    throw new Error("Direct runner not initialized. Call initDirectRunner() first.");
  }

  return adapter.executeParameterized(sql, params);
}

/**
 * Execute SQL expecting it to succeed
 */
export async function directSQLExpectSuccess(
  sql: string
): Promise<{ rows: Record<string, unknown>[]; rowCount: number | null }> {
  if (!adapter) {
    throw new Error("Direct runner not initialized. Call initDirectRunner() first.");
  }

  const result = await adapter.executeExpectingSuccess(sql);
  return { rows: result.rows, rowCount: result.rowCount };
}

/**
 * Execute SQL expecting it to fail
 */
export async function directSQLExpectError(sql: string): Promise<Error> {
  if (!adapter) {
    throw new Error("Direct runner not initialized. Call initDirectRunner() first.");
  }

  return adapter.executeExpectingError(sql);
}

/**
 * Test timing-based injection directly.
 *
 * @param sql - SQL query to execute
 * @param expectedDelayMs - Expected delay in milliseconds
 * @param toleranceMs - Tolerance for lower bound check (default 200ms)
 * @param maxExpectedMs - Optional upper bound; if provided, validates timing <= maxExpectedMs
 */
export async function directTimingTest(
  sql: string,
  expectedDelayMs: number,
  toleranceMs = 200,
  maxExpectedMs?: number
): Promise<boolean> {
  if (!adapter) {
    throw new Error("Direct runner not initialized. Call initDirectRunner() first.");
  }

  return adapter.testTimingInjection(sql, expectedDelayMs, toleranceMs, maxExpectedMs);
}

/**
 * Get PostgreSQL version info
 */
export async function getPostgreSQLVersion(): Promise<{
  major: number;
  minor: number;
  full: string;
}> {
  if (!adapter) {
    throw new Error("Direct runner not initialized. Call initDirectRunner() first.");
  }

  return adapter.getVersionInfo();
}

/**
 * Get the adapter for advanced operations
 */
export function getAdapter(): PostgreSQLAdapter {
  if (!adapter) {
    throw new Error("Direct runner not initialized. Call initDirectRunner() first.");
  }

  return adapter;
}
