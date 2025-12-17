import { MySQLConnectionManager, type MySQLQueryResult } from "./mysql-connection.js";
import { measureTime, type TimingResult } from "../utils/timing.js";
import { logger } from "../utils/logger.js";

export interface MySQLExecutionResult {
  success: boolean;
  result?: MySQLQueryResult;
  error?: Error;
  timing: TimingResult;
}

/**
 * MySQL-specific adapter for SQL injection testing
 */
export class MySQLAdapter {
  private connection: MySQLConnectionManager;

  constructor(connection: MySQLConnectionManager) {
    this.connection = connection;
  }

  /**
   * Execute SQL and capture results, errors, and timing
   */
  async execute(sql: string): Promise<MySQLExecutionResult> {
    const { result, durationMs, startTime, endTime } = await measureTime(async () => {
      try {
        const queryResult = await this.connection.query(sql);
        return { success: true, result: queryResult };
      } catch (error) {
        return { success: false, error: error as Error };
      }
    });

    return {
      success: result.success,
      result: result.result,
      error: result.error,
      timing: { durationMs, startTime, endTime },
    };
  }

  /**
   * Execute SQL expecting success
   */
  async executeExpectingSuccess(sql: string): Promise<MySQLQueryResult> {
    const { success, result, error } = await this.execute(sql);

    if (!success || !result) {
      throw error ?? new Error("Query failed unexpectedly");
    }

    return result;
  }

  /**
   * Execute SQL expecting an error
   */
  async executeExpectingError(sql: string): Promise<Error> {
    const { success, error } = await this.execute(sql);

    if (success) {
      throw new Error("Expected query to fail but it succeeded");
    }

    if (!error) {
      throw new Error("Query failed but no error was captured");
    }

    return error;
  }

  /**
   * Test if a timing-based injection is successful.
   * Validates both lower bound (delay occurred) and optionally upper bound (not too slow).
   * Tolerance is applied symmetrically to both bounds.
   *
   * @param sql - SQL query to execute
   * @param expectedDelayMs - Expected delay in milliseconds
   * @param toleranceMs - Tolerance applied to both bounds (default 200ms)
   * @param maxExpectedMs - Optional upper bound; tolerance is added to this value
   */
  async testTimingInjection(
    sql: string,
    expectedDelayMs: number,
    toleranceMs = 200,
    maxExpectedMs?: number
  ): Promise<boolean> {
    const { timing } = await this.execute(sql);
    const minExpected = expectedDelayMs - toleranceMs;
    // Apply tolerance symmetrically: add tolerance to upper bound when provided
    const maxAllowed = maxExpectedMs !== undefined ? maxExpectedMs + toleranceMs : Infinity;

    const meetsLowerBound = timing.durationMs >= minExpected;
    const meetsUpperBound = timing.durationMs <= maxAllowed;

    const upperBoundMsg =
      maxExpectedMs !== undefined ? `, <= ${maxAllowed}ms (${maxExpectedMs}+${toleranceMs})` : "";
    logger.debug(
      `Timing test: ${timing.durationMs}ms (expected >= ${minExpected}ms${upperBoundMsg})`,
      {
        sql: sql.substring(0, 100),
        meetsLowerBound,
        meetsUpperBound,
      }
    );

    return meetsLowerBound && meetsUpperBound;
  }

  /**
   * Get database version as a parsed object
   */
  async getVersionInfo(): Promise<{ major: number; minor: number; full: string }> {
    const versionString = await this.connection.getVersion();

    // Parse "8.0.35" or "5.7.44" format
    const match = /^(\d+)\.(\d+)/.exec(versionString);

    if (!match) {
      return { major: 0, minor: 0, full: versionString };
    }

    return {
      major: parseInt(match[1], 10),
      minor: parseInt(match[2], 10),
      full: versionString,
    };
  }
}
