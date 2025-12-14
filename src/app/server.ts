/**
 * Intentionally Vulnerable Express Application
 *
 * WARNING: This application contains intentional SQL injection vulnerabilities
 * for testing purposes. DO NOT use in production or expose to untrusted networks.
 */

import express, { type Request, type Response, type NextFunction } from "express";
import pg from "pg";
import { logger } from "../utils/logger.js";

const { Pool } = pg;

interface AppConfig {
  port: number;
  dbHost: string;
  dbPort: number;
  dbUser: string;
  dbPassword: string;
  dbName: string;
}

/**
 * Create and configure the vulnerable Express application
 */
export function createApp(config: AppConfig): express.Application {
  const app = express();

  app.use(express.json());
  app.use(express.urlencoded({ extended: true }));

  // Database connection pool
  const pool = new Pool({
    host: config.dbHost,
    port: config.dbPort,
    user: config.dbUser,
    password: config.dbPassword,
    database: config.dbName,
    max: 5,
  });

  // Request logging middleware
  app.use((req: Request, _res: Response, next: NextFunction) => {
    logger.debug(`${req.method} ${req.path}`, { query: req.query, body: req.body });
    next();
  });

  /**
   * Health check endpoint
   */
  app.get("/health", (_req: Request, res: Response) => {
    res.json({ status: "ok", vulnerable: true });
  });

  /**
   * VULNERABLE ENDPOINT: SQL Injection via GET parameter
   *
   * Examples:
   *   /users?id=1                    - Normal query
   *   /users?id=1' OR '1'='1         - Authentication bypass
   *   /users?id=1'; DROP TABLE users;-- - Stacked query
   *   /users?id=1' AND pg_sleep(5)-- - Time-based blind
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

      const result = await pool.query(sql);
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

      const result = await pool.query(sql);
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

      const result = await pool.query(sql);
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

      const result = await pool.query(sql);

      if (result.rows.length > 0) {
        const user = result.rows[0] as Record<string, unknown>;
        res.json({ success: true, user });
      } else {
        res.status(401).json({ success: false, error: "Invalid credentials" });
      }
    } catch (error) {
      const err = error as Error;
      res.status(500).json({ error: err.message });
    }
  });

  // Cleanup on shutdown
  const cleanup = async (): Promise<void> => {
    await pool.end();
    logger.info("Database pool closed");
  };

  // Store cleanup function for testing
  (app as express.Application & { cleanup?: () => Promise<void> }).cleanup = cleanup;

  return app;
}

/**
 * Start the vulnerable server
 */
export async function startServer(config?: Partial<AppConfig>): Promise<{
  app: express.Application;
  server: ReturnType<express.Application["listen"]>;
  cleanup: () => Promise<void>;
}> {
  const fullConfig: AppConfig = {
    port: config?.port ?? parseInt(process.env.APP_PORT ?? "3000", 10),
    dbHost: config?.dbHost ?? process.env.PG_HOST ?? "localhost",
    dbPort: config?.dbPort ?? parseInt(process.env.PG_PORT ?? "5433", 10),
    dbUser: config?.dbUser ?? process.env.PG_USER ?? "postgres",
    dbPassword: config?.dbPassword ?? process.env.PG_PASSWORD ?? "testpass",
    dbName: config?.dbName ?? process.env.PG_DATABASE ?? "vulndb",
  };

  const app = createApp(fullConfig);
  const cleanup = (app as express.Application & { cleanup?: () => Promise<void> }).cleanup;

  return new Promise((resolve) => {
    const server = app.listen(fullConfig.port, () => {
      logger.info(`Vulnerable app listening on port ${fullConfig.port}`);
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
