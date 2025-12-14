/**
 * HTTP test runner - executes payloads via the vulnerable web application
 */

import { measureTime, type TimingResult } from "../utils/timing.js";
import { logger } from "../utils/logger.js";

export interface HTTPConfig {
  baseUrl: string;
  timeout?: number;
}

export interface HTTPResponse {
  status: number;
  body: unknown;
  headers: Headers;
  timing: TimingResult;
}

let config: HTTPConfig | null = null;

/**
 * Initialize the HTTP runner
 */
export function initHTTPRunner(httpConfig: HTTPConfig): void {
  config = {
    baseUrl: httpConfig.baseUrl.replace(/\/$/, ""), // Remove trailing slash
    timeout: httpConfig.timeout ?? 30000,
  };
  logger.info("HTTP runner initialized", { baseUrl: config.baseUrl });
}

/**
 * Get the current configuration
 */
export function getHTTPConfig(): HTTPConfig {
  if (!config) {
    throw new Error("HTTP runner not initialized. Call initHTTPRunner() first.");
  }
  return config;
}

/**
 * Make an HTTP GET request to the vulnerable app
 */
export async function httpGet(path: string, query?: Record<string, string>): Promise<HTTPResponse> {
  if (!config) {
    throw new Error("HTTP runner not initialized. Call initHTTPRunner() first.");
  }

  let url = `${config.baseUrl}${path}`;

  if (query) {
    const params = new URLSearchParams(query);
    url += `?${params.toString()}`;
  }

  logger.debug(`GET ${url}`);

  const timeout = config.timeout ?? 30000;

  const { result, durationMs, startTime, endTime } = await measureTime(async () => {
    const response = await fetch(url, {
      method: "GET",
      signal: AbortSignal.timeout(timeout),
    });

    const body: unknown = await response.json().catch(() => null);

    return {
      status: response.status,
      body,
      headers: response.headers,
    };
  });

  return {
    ...result,
    timing: { durationMs, startTime, endTime },
  };
}

/**
 * Make an HTTP POST request to the vulnerable app
 */
export async function httpPost(path: string, body: Record<string, unknown>): Promise<HTTPResponse> {
  if (!config) {
    throw new Error("HTTP runner not initialized. Call initHTTPRunner() first.");
  }

  const url = `${config.baseUrl}${path}`;

  logger.debug(`POST ${url}`, { body });

  const timeout = config.timeout ?? 30000;

  const { result, durationMs, startTime, endTime } = await measureTime(async () => {
    const response = await fetch(url, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
      },
      body: JSON.stringify(body),
      signal: AbortSignal.timeout(timeout),
    });

    const responseBody: unknown = await response.json().catch(() => null);

    return {
      status: response.status,
      body: responseBody,
      headers: response.headers,
    };
  });

  return {
    ...result,
    timing: { durationMs, startTime, endTime },
  };
}

/**
 * Test a timing-based injection via HTTP
 */
export async function httpTimingTest(
  method: "GET" | "POST",
  path: string,
  payload: Record<string, unknown>,
  expectedDelayMs: number,
  toleranceMs = 200
): Promise<boolean> {
  const response =
    method === "GET"
      ? await httpGet(path, payload as Record<string, string>)
      : await httpPost(path, payload);

  const minExpected = expectedDelayMs - toleranceMs;

  logger.debug(`HTTP timing test: ${response.timing.durationMs}ms (expected >= ${minExpected}ms)`);

  return response.timing.durationMs >= minExpected;
}

/**
 * Test if a payload causes an error response
 */
export async function httpErrorTest(
  method: "GET" | "POST",
  path: string,
  payload: Record<string, unknown>
): Promise<boolean> {
  const response =
    method === "GET"
      ? await httpGet(path, payload as Record<string, string>)
      : await httpPost(path, payload);

  return response.status >= 400;
}

/**
 * Extract error message from response
 */
export function extractError(response: HTTPResponse): string | null {
  if (typeof response.body === "object" && response.body !== null) {
    const body = response.body as Record<string, unknown>;
    if (typeof body.error === "string") {
      return body.error;
    }
  }
  return null;
}
