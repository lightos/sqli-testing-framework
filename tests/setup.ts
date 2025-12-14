/**
 * Test setup and teardown utilities
 */

import { beforeAll, afterAll } from "vitest";
import { initDirectRunner, cleanupDirectRunner } from "../src/runner/direct.js";
import { initHTTPRunner } from "../src/runner/http.js";
import { startServer } from "../src/app/server.js";
import { logger } from "../src/utils/logger.js";

let serverCleanup: (() => Promise<void>) | null = null;

/**
 * Setup all test infrastructure
 */
export function setupTestInfrastructure(): void {
  beforeAll(async () => {
    logger.setLevel("warn"); // Reduce noise during tests

    // Initialize direct SQL runner
    await initDirectRunner();

    // Start vulnerable app and initialize HTTP runner
    const { cleanup } = await startServer({ port: 3001 });
    serverCleanup = cleanup;

    initHTTPRunner({ baseUrl: "http://localhost:3001" });
  }, 30000); // 30 second timeout for setup

  afterAll(async () => {
    // Cleanup in reverse order
    if (serverCleanup) {
      await serverCleanup();
    }
    await cleanupDirectRunner();
  }, 10000);
}

/**
 * Setup only direct SQL runner (no HTTP server)
 */
export function setupDirectOnly(): void {
  beforeAll(async () => {
    logger.setLevel("warn");
    await initDirectRunner();
  }, 30000);

  afterAll(async () => {
    await cleanupDirectRunner();
  }, 10000);
}
