import pg from "pg";
import { logger } from "../utils/logger.js";

const { Pool, Client } = pg;

export interface ConnectionConfig {
  host: string;
  port: number;
  user: string;
  password: string;
  database: string;
}

export interface QueryResult {
  rows: Record<string, unknown>[];
  rowCount: number | null;
  command: string;
}

/**
 * Database connection manager with connection pooling
 */
export class ConnectionManager {
  private pool: pg.Pool | null = null;
  private config: ConnectionConfig;

  constructor(config: ConnectionConfig) {
    this.config = config;
  }

  /**
   * Initialize the connection pool
   */
  async connect(): Promise<void> {
    if (this.pool) {
      logger.warn("Connection pool already initialized");
      return;
    }

    this.pool = new Pool({
      host: this.config.host,
      port: this.config.port,
      user: this.config.user,
      password: this.config.password,
      database: this.config.database,
      max: 10,
      idleTimeoutMillis: 30000,
      connectionTimeoutMillis: 5000,
    });

    // Test connection
    try {
      const client = await this.pool.connect();
      const result = await client.query<{ version: string }>("SELECT version()");
      client.release();

      logger.info("Connected to PostgreSQL", {
        host: this.config.host,
        port: this.config.port,
        version: result.rows[0]?.version.split(" ").slice(0, 2).join(" "),
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
      logger.info("Disconnected from PostgreSQL");
    }
  }

  /**
   * Execute a SQL query using the connection pool
   */
  async query(sql: string): Promise<QueryResult> {
    if (!this.pool) {
      throw new Error("Connection pool not initialized. Call connect() first.");
    }

    const result = await this.pool.query(sql);

    return {
      rows: result.rows as Record<string, unknown>[],
      rowCount: result.rowCount,
      command: result.command,
    };
  }

  /**
   * Execute a parameterized SQL query using the connection pool
   */
  async queryParameterized(sql: string, params: unknown[]): Promise<QueryResult> {
    if (!this.pool) {
      throw new Error("Connection pool not initialized. Call connect() first.");
    }

    const result = await this.pool.query(sql, params);

    return {
      rows: result.rows as Record<string, unknown>[],
      rowCount: result.rowCount,
      command: result.command,
    };
  }

  /**
   * Execute a SQL query with a fresh connection (bypasses pool)
   * Useful for testing connection-specific behaviors
   */
  async queryWithNewConnection(sql: string): Promise<QueryResult> {
    const client = new Client({
      host: this.config.host,
      port: this.config.port,
      user: this.config.user,
      password: this.config.password,
      database: this.config.database,
    });

    try {
      await client.connect();
      const result = await client.query(sql);

      return {
        rows: result.rows as Record<string, unknown>[],
        rowCount: result.rowCount,
        command: result.command,
      };
    } finally {
      await client.end();
    }
  }

  /**
   * Get PostgreSQL version information
   */
  async getVersion(): Promise<string> {
    const result = await this.query("SELECT version()");
    const versionRow = result.rows[0] as { version: string } | undefined;
    return versionRow?.version ?? "unknown";
  }

  /**
   * Check if connected
   */
  isConnected(): boolean {
    return this.pool !== null;
  }
}

/**
 * Create a connection manager from environment variables
 */
export function createConnectionFromEnv(): ConnectionManager {
  const config: ConnectionConfig = {
    host: process.env.PG_HOST ?? "localhost",
    port: parseInt(process.env.PG_PORT ?? "5433", 10),
    user: process.env.PG_USER ?? "postgres",
    password: process.env.PG_PASSWORD ?? "testpass",
    database: process.env.PG_DATABASE ?? "vulndb",
  };

  return new ConnectionManager(config);
}
