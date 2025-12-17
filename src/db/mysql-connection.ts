import mysql from "mysql2/promise";
import { logger } from "../utils/logger.js";

export interface MySQLConnectionConfig {
  host: string;
  port: number;
  user: string;
  password: string;
  database: string;
}

export interface MySQLQueryResult {
  rows: Record<string, unknown>[];
  rowCount: number;
  affectedRows: number;
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
      connectionLimit: 10,
      queueLimit: 0,
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
  async query(sql: string): Promise<MySQLQueryResult> {
    if (!this.pool) {
      throw new Error("MySQL connection pool not initialized. Call connect() first.");
    }

    const [rows, _fields] = await this.pool.query<mysql.RowDataPacket[]>(sql);

    // Handle different result types (SELECT vs INSERT/UPDATE/DELETE)
    if (Array.isArray(rows)) {
      return {
        rows: rows as Record<string, unknown>[],
        rowCount: rows.length,
        affectedRows: 0,
      };
    }

    // For non-SELECT queries
    const result = rows as mysql.ResultSetHeader;
    return {
      rows: [],
      rowCount: 0,
      affectedRows: result.affectedRows,
    };
  }

  /**
   * Get MySQL version information
   */
  async getVersion(): Promise<string> {
    const result = await this.query("SELECT VERSION() as version");
    const versionRow = result.rows[0] as { version: string } | undefined;
    return versionRow?.version ?? "unknown";
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
