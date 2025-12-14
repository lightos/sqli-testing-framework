import chalk from "chalk";

export type LogLevel = "debug" | "info" | "warn" | "error";

interface LogEntry {
  level: LogLevel;
  message: string;
  timestamp: string;
  context?: Record<string, unknown>;
}

const LOG_LEVEL_PRIORITY: Record<LogLevel, number> = {
  debug: 0,
  info: 1,
  warn: 2,
  error: 3,
};

const LOG_LEVEL_COLORS: Record<LogLevel, (text: string) => string> = {
  debug: chalk.gray,
  info: chalk.blue,
  warn: chalk.yellow,
  error: chalk.red,
};

const LOG_LEVEL_LABELS: Record<LogLevel, string> = {
  debug: "DEBUG",
  info: "INFO ",
  warn: "WARN ",
  error: "ERROR",
};

class Logger {
  private minLevel: LogLevel = "info";

  /**
   * Set the minimum log level to display
   */
  setLevel(level: LogLevel): void {
    this.minLevel = level;
  }

  /**
   * Check if a log level should be displayed
   */
  private shouldLog(level: LogLevel): boolean {
    return LOG_LEVEL_PRIORITY[level] >= LOG_LEVEL_PRIORITY[this.minLevel];
  }

  /**
   * Format and output a log entry
   */
  private log(entry: LogEntry): void {
    if (!this.shouldLog(entry.level)) return;

    const colorFn = LOG_LEVEL_COLORS[entry.level];
    const label = LOG_LEVEL_LABELS[entry.level];
    const timestamp = chalk.dim(entry.timestamp);
    const levelStr = colorFn(`[${label}]`);

    let output = `${timestamp} ${levelStr} ${entry.message}`;

    if (entry.context && Object.keys(entry.context).length > 0) {
      output += ` ${chalk.dim(JSON.stringify(entry.context))}`;
    }

    console.log(output);
  }

  /**
   * Create a log entry with current timestamp
   */
  private createEntry(
    level: LogLevel,
    message: string,
    context?: Record<string, unknown>
  ): LogEntry {
    return {
      level,
      message,
      timestamp: new Date().toISOString(),
      context,
    };
  }

  debug(message: string, context?: Record<string, unknown>): void {
    this.log(this.createEntry("debug", message, context));
  }

  info(message: string, context?: Record<string, unknown>): void {
    this.log(this.createEntry("info", message, context));
  }

  warn(message: string, context?: Record<string, unknown>): void {
    this.log(this.createEntry("warn", message, context));
  }

  error(message: string, context?: Record<string, unknown>): void {
    this.log(this.createEntry("error", message, context));
  }

  /**
   * Log a test result with appropriate formatting
   */
  testResult(name: string, passed: boolean, durationMs: number, error?: string): void {
    const status = passed ? chalk.green("✓ PASS") : chalk.red("✗ FAIL");
    const duration = chalk.dim(`(${durationMs}ms)`);

    console.log(`  ${status} ${name} ${duration}`);

    if (error) {
      console.log(chalk.dim(`    └─ ${error}`));
    }
  }

  /**
   * Log a section header
   */
  section(title: string): void {
    console.log("");
    console.log(chalk.bold.cyan(`▸ ${title}`));
    console.log(chalk.dim("─".repeat(50)));
  }
}

export const logger = new Logger();
