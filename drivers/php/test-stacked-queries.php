<?php
/**
 * PostgreSQL Multi-Statement Test for PHP pg_* functions
 *
 * Tests multi-statement support in:
 * - pg_query() - should support multi-statements
 * - pg_query_params() - should NOT support multi-statements
 *
 * Run: php test-stacked-queries.php
 */

$host = getenv('PG_HOST') ?: 'postgres-16';
$port = getenv('PG_PORT') ?: '5432';
$dbname = getenv('PG_DATABASE') ?: 'vulndb';
$user = getenv('PG_USER') ?: 'postgres';
$password = getenv('PG_PASSWORD') ?: 'testpass';

$connString = "host=$host port=$port dbname=$dbname user=$user password=$password";

echo "=== PHP PostgreSQL Multi-Statement Tests ===\n\n";

// Connect
$conn = pg_connect($connString);
if (!$conn) {
    echo "FAIL: Could not connect to PostgreSQL\n";
    exit(1);
}
echo "Connected to PostgreSQL\n\n";

$passed = 0;
$failed = 0;

// Test 1: pg_query() with multiple statements
echo "Test 1: pg_query() with multiple SELECT statements\n";
$result = @pg_query($conn, "SELECT 1 as a; SELECT 2 as b;");
if ($result) {
    echo "  PASS: pg_query() supports multi-statements\n";
    // Check first result
    $row = pg_fetch_assoc($result);
    echo "  First result: a = " . ($row['a'] ?? 'null') . "\n";
    $passed++;
} else {
    echo "  FAIL: pg_query() rejected multi-statements\n";
    echo "  Error: " . pg_last_error($conn) . "\n";
    $failed++;
}
echo "\n";

// Test 2: pg_query() with SELECT + INSERT
echo "Test 2: pg_query() with SELECT + INSERT (stacked modification)\n";
$testAction = "php_test_" . time();
$result = @pg_query($conn, "SELECT 1; INSERT INTO logs (action, ip_address) VALUES ('$testAction', '127.0.0.1');");
if ($result) {
    // Verify insert worked
    $verify = pg_query($conn, "SELECT * FROM logs WHERE action = '$testAction'");
    $count = pg_num_rows($verify);
    if ($count > 0) {
        echo "  PASS: pg_query() executed stacked INSERT ($count rows inserted)\n";
        $passed++;
    } else {
        echo "  FAIL: INSERT did not persist\n";
        $failed++;
    }
    // Cleanup
    pg_query($conn, "DELETE FROM logs WHERE action = '$testAction'");
} else {
    echo "  FAIL: pg_query() rejected stacked modification\n";
    echo "  Error: " . pg_last_error($conn) . "\n";
    $failed++;
}
echo "\n";

// Test 3: pg_query_params() with single statement (should work)
echo "Test 3: pg_query_params() with single statement\n";
$result = @pg_query_params($conn, "SELECT $1::int + $2::int as sum", [5, 3]);
if ($result) {
    $row = pg_fetch_assoc($result);
    if ($row['sum'] == 8) {
        echo "  PASS: pg_query_params() works with single statement (sum = 8)\n";
        $passed++;
    } else {
        echo "  FAIL: Unexpected result: " . $row['sum'] . "\n";
        $failed++;
    }
} else {
    echo "  FAIL: pg_query_params() failed on single statement\n";
    echo "  Error: " . pg_last_error($conn) . "\n";
    $failed++;
}
echo "\n";

// Test 4: pg_query_params() with multiple statements (should FAIL)
echo "Test 4: pg_query_params() with multiple statements (expected to FAIL)\n";
$result = @pg_query_params($conn, "SELECT $1; SELECT $2;", [1, 2]);
if ($result === false) {
    $error = pg_last_error($conn);
    if (stripos($error, 'cannot insert multiple commands') !== false) {
        echo "  PASS: pg_query_params() correctly rejects multi-statements\n";
        echo "  Error: $error\n";
        $passed++;
    } else {
        echo "  PASS: pg_query_params() rejected multi-statements (different error)\n";
        echo "  Error: $error\n";
        $passed++;
    }
} else {
    echo "  FAIL: pg_query_params() unexpectedly allowed multi-statements!\n";
    $failed++;
}
echo "\n";

// Summary
pg_close($conn);
echo "=== Summary ===\n";
echo "Passed: $passed\n";
echo "Failed: $failed\n";
exit($failed > 0 ? 1 : 0);
