import { ConnectionManager, type QueryResult } from "./connection.js";
import { measureTime, type TimingResult } from "../utils/timing.js";
import { logger } from "../utils/logger.js";

export interface SQLExecutionResult {
  success: boolean;
  result?: QueryResult;
  error?: Error;
  timing: TimingResult;
}

/**
 * PostgreSQL-specific adapter for SQL injection testing
 */
export class PostgreSQLAdapter {
  private connection: ConnectionManager;

  constructor(connection: ConnectionManager) {
    this.connection = connection;
  }

  /**
   * Execute SQL and capture results, errors, and timing
   */
  async execute(sql: string): Promise<SQLExecutionResult> {
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
  async executeExpectingSuccess(sql: string): Promise<QueryResult> {
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
   * Test if a timing-based injection is successful
   */
  async testTimingInjection(
    sql: string,
    expectedDelayMs: number,
    toleranceMs = 200
  ): Promise<boolean> {
    const { timing } = await this.execute(sql);
    const minExpected = expectedDelayMs - toleranceMs;

    logger.debug(`Timing test: ${timing.durationMs}ms (expected >= ${minExpected}ms)`, {
      sql: sql.substring(0, 100),
    });

    return timing.durationMs >= minExpected;
  }

  /**
   * Test if stacked queries are supported
   */
  async testStackedQueries(): Promise<boolean> {
    try {
      // Try executing two statements
      await this.connection.query("SELECT 1; SELECT 2;");
      return true;
    } catch {
      return false;
    }
  }

  /**
   * Get database version as a parsed object
   */
  async getVersionInfo(): Promise<{ major: number; minor: number; full: string }> {
    const versionString = await this.connection.getVersion();

    // Parse "PostgreSQL 16.1 (Debian 16.1-1.pgdg120+1)" format
    const match = /PostgreSQL (\d+)\.(\d+)/.exec(versionString);

    if (!match) {
      return { major: 0, minor: 0, full: versionString };
    }

    return {
      major: parseInt(match[1], 10),
      minor: parseInt(match[2], 10),
      full: versionString,
    };
  }

  /**
   * Check if a specific feature is available based on version
   */
  async hasFeature(feature: PostgreSQLFeature): Promise<boolean> {
    const version = await this.getVersionInfo();

    switch (feature) {
      case "pg_sleep":
        return version.major >= 8 || (version.major === 8 && version.minor >= 2);
      case "pg_read_file":
        return version.major >= 8 || (version.major === 8 && version.minor >= 1);
      case "copy_to_program":
        return version.major >= 9 || (version.major === 9 && version.minor >= 3);
      case "pg_sleep_for":
        return version.major >= 9 || (version.major === 9 && version.minor >= 4);
      default:
        return false;
    }
  }
}

export type PostgreSQLFeature = "pg_sleep" | "pg_read_file" | "copy_to_program" | "pg_sleep_for";
