#!/usr/bin/env python3
"""
PostgreSQL Multi-Statement Test for psycopg2

Tests multi-statement support in:
- cursor.execute() without params - should support multi-statements
- cursor.execute() with params - should NOT support multi-statements

Run: python test-stacked-queries.py
"""

import os
import sys
import time

try:
    import psycopg2
except ImportError:
    print("ERROR: psycopg2 not installed.", file=sys.stderr)
    print("Install with: pip install psycopg2-binary", file=sys.stderr)
    print("Or run via docker-compose which handles dependencies.", file=sys.stderr)
    sys.exit(1)

# Connection parameters
host = os.getenv('PG_HOST', 'postgres-16')
port = os.getenv('PG_PORT', '5432')
dbname = os.getenv('PG_DATABASE', 'vulndb')
user = os.getenv('PG_USER', 'postgres')
password = os.getenv('PG_PASSWORD', 'testpass')

print("=== Python psycopg2 Multi-Statement Tests ===\n")

# Connect
try:
    conn = psycopg2.connect(
        host=host,
        port=port,
        dbname=dbname,
        user=user,
        password=password
    )
    conn.autocommit = True
    print(f"Connected to PostgreSQL at {host}:{port}\n")
except Exception as e:
    print(f"FAIL: Could not connect to PostgreSQL: {e}")
    sys.exit(1)

passed = 0
failed = 0
cursor = conn.cursor()

# Test 1: execute() with multiple statements (no params)
print("Test 1: execute() with multiple SELECT statements (no params)")
try:
    cursor.execute("SELECT 1 as a; SELECT 2 as b;")
    # psycopg2 returns the LAST result set
    row = cursor.fetchone()
    print("  PASS: execute() supports multi-statements (no params)")
    print(f"  Result from last statement: b = {row[0]}")
    passed += 1
except Exception as e:
    print("  FAIL: execute() rejected multi-statements")
    print(f"  Error: {e}")
    failed += 1
print()

# Test 2: execute() with SELECT + INSERT (no params)
print("Test 2: execute() with SELECT + INSERT (stacked modification, no params)")
test_action = f"python_test_{int(time.time())}"
try:
    cursor.execute(f"SELECT 1; INSERT INTO logs (action, ip_address) VALUES ('{test_action}', '127.0.0.1');")
    # Verify insert worked
    cursor.execute(f"SELECT * FROM logs WHERE action = '{test_action}'")
    rows = cursor.fetchall()
    if len(rows) > 0:
        print(f"  PASS: execute() executed stacked INSERT ({len(rows)} rows inserted)")
        passed += 1
    else:
        print("  FAIL: INSERT did not persist")
        failed += 1
except Exception as e:
    print("  FAIL: execute() rejected stacked modification")
    print(f"  Error: {e}")
    failed += 1
finally:
    # Cleanup - always attempt to delete test rows
    try:
        cursor.execute(f"DELETE FROM logs WHERE action = '{test_action}'")
    except Exception as cleanup_error:
        print(f"  Warning: Cleanup failed: {cleanup_error}", file=sys.stderr)
print()

# Test 3: execute() with single statement + params (should work)
print("Test 3: execute() with single statement + params")
try:
    cursor.execute("SELECT %s::int + %s::int as sum", (5, 3))
    row = cursor.fetchone()
    if row[0] == 8:
        print("  PASS: execute() works with single parameterized statement (sum = 8)")
        passed += 1
    else:
        print(f"  FAIL: Unexpected result: {row[0]}")
        failed += 1
except Exception as e:
    print("  FAIL: execute() failed on single parameterized statement")
    print(f"  Error: {e}")
    failed += 1
print()

# Test 4: execute() with multiple statements + params (psycopg2 uses client-side substitution, so this works)
print("Test 4: execute() with multiple statements + params")
print("  Note: psycopg2 uses client-side parameter substitution, NOT server-side prepared statements")
try:
    cursor.execute("SELECT %s; SELECT %s;", (1, 2))
    row = cursor.fetchone()
    # psycopg2 returns the LAST result set
    if row[0] == 2:
        print(f"  PASS: execute() supports multi-statements with params (returns last result: {row[0]})")
        passed += 1
    else:
        print(f"  FAIL: Unexpected result: {row}")
        failed += 1
except Exception as e:
    print("  FAIL: execute() rejected multi-statements with params")
    print(f"  Error: {type(e).__name__}: {e}")
    failed += 1
print()

# Cleanup
cursor.close()
conn.close()

print("=== Summary ===")
print(f"Passed: {passed}")
print(f"Failed: {failed}")
sys.exit(1 if failed > 0 else 0)
