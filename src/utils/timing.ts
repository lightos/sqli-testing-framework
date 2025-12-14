/**
 * Timing utilities for measuring query execution and detecting time-based injections
 */

export interface TimingResult {
  durationMs: number;
  startTime: number;
  endTime: number;
}

/**
 * Measure the execution time of an async function
 */
export async function measureTime<T>(fn: () => Promise<T>): Promise<{ result: T } & TimingResult> {
  const startTime = performance.now();
  const result = await fn();
  const endTime = performance.now();

  return {
    result,
    durationMs: Math.round(endTime - startTime),
    startTime,
    endTime,
  };
}

/**
 * Check if execution time indicates a successful time-based injection
 * @param durationMs - Actual execution time in milliseconds
 * @param expectedDelayMs - Expected delay from the injection (e.g., pg_sleep(2) = 2000ms)
 * @param toleranceMs - Acceptable variance (default 200ms)
 */
export function isDelayDetected(
  durationMs: number,
  expectedDelayMs: number,
  toleranceMs = 200
): boolean {
  const minExpected = expectedDelayMs - toleranceMs;
  const maxExpected = expectedDelayMs + toleranceMs * 2; // Allow more tolerance on upper bound

  return durationMs >= minExpected && durationMs <= maxExpected;
}

/**
 * Calculate if timing difference suggests a boolean condition was true
 * Used for blind boolean-based timing attacks
 */
export function isConditionTrue(
  trueDurationMs: number,
  falseDurationMs: number,
  thresholdMs = 500
): boolean {
  return trueDurationMs - falseDurationMs > thresholdMs;
}

/**
 * Sleep for a specified number of milliseconds
 */
export function sleep(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

/**
 * Get current timestamp in milliseconds
 */
export function now(): number {
  return performance.now();
}
