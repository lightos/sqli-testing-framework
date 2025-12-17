import mysql, { ResultSetHeader } from "mysql2/promise";
import { logger } from "../utils/logger.js";

export interface MySQLConnectionConfig {
  host: string;
  port: number;
  user: string;
  password: string;
  database: string;
  /** Maximum number of connections in the pool (default: 10) */
  connectionLimit?: number;
  /** Maximum number of queued connection requests (default: 50) */
  queueLimit?: number;
  /** Connection timeout in milliseconds (default: 10000) */
  connectTimeoutMs?: number;
}

export interface MySQLQueryResult<T extends Record<string, unknown> = Record<string, unknown>> {
  rows: T[];
  rowCount: number;
  affectedRows: number;
  insertId?: number;
}

/**
 * Type guard to check if result is a ResultSetHeader (non-SELECT result)
 * Checks for both affectedRows and fieldCount to robustly discriminate from row data
 */
function isResultSetHeader(result: unknown): result is ResultSetHeader {
  return (
    result !== null &&
    typeof result === "object" &&
    "affectedRows" in result &&
    typeof (result as ResultSetHeader).affectedRows === "number" &&
    "fieldCount" in result &&
    typeof (result as ResultSetHeader).fieldCount === "number"
  );
}

/**
 * MySQL connection manager with connection pooling
 */
export class MySQLConnectionManager {
  private pool: mysql.Pool | null = null;
  private config: MySQLConnectionConfig;

  constructor(config: MySQLConnectionConfig) {
    this.config = config;
  }

  /**
   * Initialize the connection pool
   */
  async connect(): Promise<void> {
    if (this.pool) {
      logger.warn("MySQL connection pool already initialized");
      return;
    }

    this.pool = mysql.createPool({
      host: this.config.host,
      port: this.config.port,
      user: this.config.user,
      password: this.config.password,
      database: this.config.database,
      waitForConnections: true,
      connectionLimit: this.config.connectionLimit ?? 10,
      queueLimit: this.config.queueLimit ?? 50,
      connectTimeout: this.config.connectTimeoutMs ?? 10000,
    });

    // Test connection
    try {
      const [rows] = await this.pool.query<mysql.RowDataPacket[]>("SELECT VERSION() as version");
      logger.info("Connected to MySQL", {
        host: this.config.host,
        port: this.config.port,
        version: rows[0]?.version,
      });
    } catch (error) {
      await this.disconnect();
      throw error;
    }
  }

  /**
   * Close all connections in the pool
   */
  async disconnect(): Promise<void> {
    if (this.pool) {
      await this.pool.end();
      this.pool = null;
      logger.info("Disconnected from MySQL");
    }
  }

  /**
   * Execute a SQL query using the connection pool
   */
  async query<T extends Record<string, unknown> = Record<string, unknown>>(
    sql: string
  ): Promise<MySQLQueryResult<T>> {
    if (!this.pool) {
      throw new Error("MySQL connection pool not initialized. Call connect() first.");
    }

    const [rows] = await this.pool.query(sql);

    // Handle SELECT queries (returns array of rows)
    if (Array.isArray(rows)) {
      return {
        rows: rows as T[],
        rowCount: rows.length,
        affectedRows: 0,
      };
    }

    // Handle INSERT/UPDATE/DELETE queries (returns ResultSetHeader)
    if (isResultSetHeader(rows)) {
      return {
        rows: [],
        rowCount: 0,
        affectedRows: rows.affectedRows,
        insertId: rows.insertId > 0 ? rows.insertId : undefined,
      };
    }

    // Fallback for unexpected result types - log for diagnostics
    let valueStr: string;
    try {
      valueStr = JSON.stringify(rows, (_key, val: unknown) =>
        typeof val === "bigint" ? val.toString() : val
      ).slice(0, 500);
    } catch {
      valueStr = "[unstringifiable]";
    }
    logger.warn("Unexpected MySQL query result type", {
      type: typeof rows,
      constructor: (rows as object).constructor.name,
      value: valueStr,
    });
    return {
      rows: [],
      rowCount: 0,
      affectedRows: 0,
    };
  }

  /**
   * Get MySQL version information
   */
  async getVersion(): Promise<string> {
    const result = await this.query<{ version: string }>("SELECT VERSION() as version");
    if (result.rows.length === 0) {
      return "unknown";
    }
    return result.rows[0].version;
  }

  /**
   * Check if connected.
   * Note: This only checks pool existence, not actual connectivity.
   * The pool can be non-null while underlying connections are dead
   * (e.g., network failure, server restart). Use query() or healthCheck()
   * to verify actual connectivity.
   */
  isConnected(): boolean {
    return this.pool !== null;
  }

  /**
   * Perform a health check query to verify actual database connectivity
   */
  async healthCheck(): Promise<boolean> {
    if (!this.pool) return false;
    try {
      await this.pool.query("SELECT 1");
      return true;
    } catch {
      return false;
    }
  }
}

/**
 * Create a MySQL connection manager from environment variables
 */
export function createMySQLConnectionFromEnv(): MySQLConnectionManager {
  const portStr = process.env.MYSQL_PORT ?? "3306";
  const port = parseInt(portStr, 10);
  if (Number.isNaN(port)) {
    throw new Error(`Invalid MYSQL_PORT: "${portStr}" is not a number`);
  }
  if (port < 1 || port > 65535) {
    throw new Error(
      `Invalid MYSQL_PORT: ${port} (from "${portStr}") is outside valid range 1-65535`
    );
  }

  const config: MySQLConnectionConfig = {
    host: process.env.MYSQL_HOST ?? "localhost",
    port,
    user: process.env.MYSQL_USER ?? "root",
    password: process.env.MYSQL_PASSWORD ?? "testpass",
    database: process.env.MYSQL_DATABASE ?? "vulndb",
  };

  return new MySQLConnectionManager(config);
}
