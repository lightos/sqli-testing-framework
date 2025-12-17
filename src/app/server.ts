/**
 * Intentionally Vulnerable Express Application
 *
 * WARNING: This application contains intentional SQL injection vulnerabilities
 * for testing purposes. DO NOT use in production or expose to untrusted networks.
 *
 * Supports both PostgreSQL and MySQL databases.
 */

import express, { type Request, type Response, type NextFunction } from "express";
import pg from "pg";
import mysql from "mysql2/promise";
import { logger } from "../utils/logger.js";

const { Pool: PgPool } = pg;

type DatabaseType = "postgresql" | "mysql";

interface AppConfig {
  port: number;
  dbType: DatabaseType;
  dbHost: string;
  dbPort: number;
  dbUser: string;
  dbPassword: string;
  dbName: string;
}

interface QueryResult {
  rows: Record<string, unknown>[];
  affectedRows?: number;
  insertId?: number;
}

/**
 * Database adapter interface for abstracting PostgreSQL and MySQL
 */
interface DatabaseAdapter {
  query(sql: string): Promise<QueryResult>;
  close(): Promise<void>;
}

/**
 * PostgreSQL adapter
 */
class PostgreSQLAdapter implements DatabaseAdapter {
  private pool: pg.Pool;

  constructor(config: AppConfig) {
    this.pool = new PgPool({
      host: config.dbHost,
      port: config.dbPort,
      user: config.dbUser,
      password: config.dbPassword,
      database: config.dbName,
      max: 5,
    });
  }

  async query(sql: string): Promise<QueryResult> {
    const result = await this.pool.query(sql);
    return { rows: result.rows as Record<string, unknown>[] };
  }

  async close(): Promise<void> {
    await this.pool.end();
  }
}

/**
 * MySQL adapter
 */
class MySQLAdapter implements DatabaseAdapter {
  private pool: mysql.Pool;

  constructor(config: AppConfig) {
    this.pool = mysql.createPool({
      host: config.dbHost,
      port: config.dbPort,
      user: config.dbUser,
      password: config.dbPassword,
      database: config.dbName,
      waitForConnections: true,
      connectionLimit: 5,
    });
  }

  async query(sql: string): Promise<QueryResult> {
    const [result] = await this.pool.query(sql);
    // mysql2 returns RowDataPacket[] for SELECT, ResultSetHeader for INSERT/UPDATE/DELETE
    if (Array.isArray(result)) {
      return { rows: result as Record<string, unknown>[] };
    }
    // ResultSetHeader for non-SELECT statements
    const header = result as mysql.ResultSetHeader;
    return {
      rows: [],
      affectedRows: header.affectedRows,
      insertId: header.insertId,
    };
  }

  async close(): Promise<void> {
    await this.pool.end();
  }
}

/**
 * Create database adapter based on type
 */
function createDatabaseAdapter(config: AppConfig): DatabaseAdapter {
  switch (config.dbType) {
    case "postgresql":
      return new PostgreSQLAdapter(config);
    case "mysql":
      return new MySQLAdapter(config);
    default: {
      const exhaustiveCheck: never = config.dbType;
      throw new Error(`Unsupported database type: ${exhaustiveCheck as string}`);
    }
  }
}

/**
 * Create and configure the vulnerable Express application
 */
export function createApp(config: AppConfig): express.Application {
  const app = express();

  app.use(express.json());
  app.use(express.urlencoded({ extended: true }));

  // Database adapter
  const db = createDatabaseAdapter(config);

  // Request logging middleware
  app.use((req: Request, _res: Response, next: NextFunction) => {
    logger.debug(`${req.method} ${req.path}`, { query: req.query, body: req.body });
    next();
  });

  /**
   * Health check endpoint
   */
  app.get("/health", (_req: Request, res: Response) => {
    res.json({ status: "ok", vulnerable: true, dbType: config.dbType });
  });

  /**
   * VULNERABLE ENDPOINT: SQL Injection via GET parameter
   *
   * Examples:
   *   /users?id=1                    - Normal query
   *   /users?id=1' OR '1'='1         - Authentication bypass
   *   /users?id=1'; DROP TABLE users;-- - Stacked query
   *   /users?id=1' AND pg_sleep(5)-- - Time-based blind (PostgreSQL)
   *   /users?id=1' AND SLEEP(5)--    - Time-based blind (MySQL)
   */
  app.get("/users", async (req: Request, res: Response) => {
    const id = req.query.id as string | undefined;

    if (!id) {
      res.status(400).json({ error: "Missing id parameter" });
      return;
    }

    try {
      // VULNERABLE: Direct string concatenation - no parameterization
      const sql = `SELECT id, username, email, role FROM users WHERE id = ${id}`;
      logger.debug("Executing SQL", { sql });

      const result = await db.query(sql);
      res.json({ users: result.rows });
    } catch (error) {
      const err = error as Error;
      // VULNERABLE: Exposing database errors (information disclosure)
      res.status(500).json({ error: err.message });
    }
  });

  /**
   * VULNERABLE ENDPOINT: SQL Injection via POST body
   *
   * Examples:
   *   POST /search { "query": "laptop" }
   *   POST /search { "query": "laptop' OR '1'='1" }
   */
  app.post("/search", async (req: Request, res: Response) => {
    const { query } = req.body as { query?: string };

    if (!query) {
      res.status(400).json({ error: "Missing query parameter" });
      return;
    }

    try {
      // VULNERABLE: Direct string interpolation in LIKE clause
      const sql = `SELECT * FROM products WHERE name LIKE '%${query}%' OR description LIKE '%${query}%'`;
      logger.debug("Executing SQL", { sql });

      const result = await db.query(sql);
      res.json({ products: result.rows });
    } catch (error) {
      const err = error as Error;
      res.status(500).json({ error: err.message });
    }
  });

  /**
   * VULNERABLE ENDPOINT: SQL Injection via ORDER BY clause
   *
   * Examples:
   *   /products?sort=name
   *   /products?sort=price DESC; SELECT pg_sleep(5)--
   */
  app.get("/products", async (req: Request, res: Response) => {
    const sortParam = req.query.sort;
    const sort = typeof sortParam === "string" ? sortParam : "id";

    try {
      // VULNERABLE: Unvalidated column name in ORDER BY
      const sql = `SELECT * FROM products ORDER BY ${sort}`;
      logger.debug("Executing SQL", { sql });

      const result = await db.query(sql);
      res.json({ products: result.rows });
    } catch (error) {
      const err = error as Error;
      res.status(500).json({ error: err.message });
    }
  });

  /**
   * VULNERABLE ENDPOINT: Authentication bypass
   *
   * Examples:
   *   POST /login { "username": "admin", "password": "admin123" }
   *   POST /login { "username": "admin'--", "password": "anything" }
   *   POST /login { "username": "' OR '1'='1", "password": "' OR '1'='1" }
   */
  app.post("/login", async (req: Request, res: Response) => {
    const { username, password } = req.body as { username?: string; password?: string };

    if (!username || !password) {
      res.status(400).json({ error: "Missing username or password" });
      return;
    }

    try {
      // VULNERABLE: String concatenation in authentication query
      const sql = `SELECT id, username, role FROM users WHERE username = '${username}' AND password = '${password}'`;
      logger.debug("Executing SQL", { sql });

      const result = await db.query(sql);

      if (result.rows.length > 0) {
        const user = result.rows[0];
        res.json({ success: true, user });
      } else {
        res.status(401).json({ success: false, error: "Invalid credentials" });
      }
    } catch (error) {
      const err = error as Error;
      res.status(500).json({ error: err.message });
    }
  });

  /**
   * VULNERABLE ENDPOINT: Raw SQL execution (for testing)
   *
   * POST /sql { "query": "SELECT * FROM users" }
   *
   * This endpoint allows arbitrary SQL execution for testing obfuscation
   * techniques through the HTTP layer.
   */
  app.post("/sql", async (req: Request, res: Response) => {
    const { query } = req.body as { query?: string };

    if (!query) {
      res.status(400).json({ error: "Missing query parameter" });
      return;
    }

    try {
      logger.debug("Executing raw SQL", { sql: query });
      const result = await db.query(query);
      res.json({ success: true, rows: result.rows, rowCount: result.rows.length });
    } catch (error) {
      const err = error as Error;
      res.status(500).json({ success: false, error: err.message });
    }
  });

  // Store cleanup function
  const cleanup = async (): Promise<void> => {
    await db.close();
    logger.info("Database connection closed");
  };

  (app as express.Application & { cleanup?: () => Promise<void> }).cleanup = cleanup;

  return app;
}

/**
 * Get environment variable based on database type with fallback default.
 */
function getDbEnv(
  mysqlKey: string,
  pgKey: string,
  dbType: DatabaseType,
  defaultValue: string
): string {
  const envKey = dbType === "mysql" ? mysqlKey : pgKey;
  return process.env[envKey] ?? defaultValue;
}

/**
 * Get environment variable as integer based on database type with fallback default.
 * Logs a warning if the environment variable contains an invalid integer value.
 */
function getDbEnvInt(
  mysqlKey: string,
  pgKey: string,
  dbType: DatabaseType,
  defaultValue: number
): number {
  const envKey = dbType === "mysql" ? mysqlKey : pgKey;
  const value = process.env[envKey];
  if (value === undefined) return defaultValue;
  const parsed = parseInt(value, 10);
  if (Number.isNaN(parsed)) {
    logger.warn(
      `Invalid integer value for environment variable ${envKey}: "${value}" (dbType: ${dbType}). Using default: ${defaultValue}`
    );
    return defaultValue;
  }
  return parsed;
}

/**
 * Start the vulnerable server
 */
export async function startServer(config?: Partial<AppConfig>): Promise<{
  app: express.Application;
  server: ReturnType<express.Application["listen"]>;
  cleanup: () => Promise<void>;
}> {
  // Determine database type: config takes priority, then environment, then default
  const dbTypeEnv = process.env.DB_TYPE?.toLowerCase();
  let envDbType: DatabaseType = "postgresql";

  if (dbTypeEnv === "mysql") {
    envDbType = "mysql";
  } else if (dbTypeEnv === "postgresql" || dbTypeEnv === "postgres") {
    envDbType = "postgresql";
  }

  const resolvedDbType: DatabaseType = config?.dbType ?? envDbType;

  // Use database-specific environment variables with fallbacks
  const fullConfig: AppConfig = {
    port: config?.port ?? parseInt(process.env.APP_PORT ?? "3000", 10),
    dbType: resolvedDbType,
    dbHost: config?.dbHost ?? getDbEnv("MYSQL_HOST", "PG_HOST", resolvedDbType, "localhost"),
    dbPort:
      config?.dbPort ??
      getDbEnvInt(
        "MYSQL_PORT",
        "PG_PORT",
        resolvedDbType,
        resolvedDbType === "mysql" ? 3306 : 5433
      ),
    dbUser:
      config?.dbUser ??
      getDbEnv(
        "MYSQL_USER",
        "PG_USER",
        resolvedDbType,
        resolvedDbType === "mysql" ? "root" : "postgres"
      ),
    dbPassword:
      config?.dbPassword ?? getDbEnv("MYSQL_PASSWORD", "PG_PASSWORD", resolvedDbType, "testpass"),
    dbName: config?.dbName ?? getDbEnv("MYSQL_DATABASE", "PG_DATABASE", resolvedDbType, "vulndb"),
  };

  const app = createApp(fullConfig);
  const cleanup = (app as express.Application & { cleanup?: () => Promise<void> }).cleanup;

  return new Promise((resolve) => {
    const server = app.listen(fullConfig.port, () => {
      logger.info(`Vulnerable app listening on port ${fullConfig.port}`, {
        dbType: fullConfig.dbType,
        dbHost: fullConfig.dbHost,
        dbPort: fullConfig.dbPort,
      });
      resolve({
        app,
        server,
        cleanup:
          cleanup ??
          (async (): Promise<void> => {
            /* no-op */
          }),
      });
    });
  });
}

// Run server if executed directly
const isMainModule = import.meta.url === `file://${process.argv[1]}`;
if (isMainModule) {
  startServer().catch((error: unknown) => {
    logger.error("Failed to start server", { error: String(error) });
    process.exit(1);
  });
}
