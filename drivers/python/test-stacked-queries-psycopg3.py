#!/usr/bin/env python3
"""
PostgreSQL Multi-Statement Test for psycopg3

Tests multi-statement support in psycopg3 which uses server-side
parameter binding (extended query protocol via PQexecParams).

Expected behavior:
- Without params: multi-statements should work (simple query protocol)
- With params: multi-statements should FAIL (extended query protocol limitation)

Run: python test-stacked-queries-psycopg3.py
"""

import os
import sys
import time

try:
    import psycopg
except ImportError:
    print("Installing psycopg[binary]...")
    import subprocess
    subprocess.check_call([sys.executable, "-m", "pip", "install", "psycopg[binary]", "-q"])
    import psycopg

# Connection parameters
host = os.getenv('PG_HOST', 'postgres-16')
port = os.getenv('PG_PORT', '5432')
dbname = os.getenv('PG_DATABASE', 'vulndb')
user = os.getenv('PG_USER', 'postgres')
password = os.getenv('PG_PASSWORD', 'testpass')

print("=== Python psycopg3 Multi-Statement Tests ===\n")

# Connect
try:
    conn = psycopg.connect(
        host=host,
        port=port,
        dbname=dbname,
        user=user,
        password=password,
        autocommit=True
    )
    print(f"Connected to PostgreSQL at {host}:{port}\n")
except Exception as e:
    print(f"FAIL: Could not connect to PostgreSQL: {e}")
    sys.exit(1)

passed = 0
failed = 0
cursor = conn.cursor()

# Test 1: execute() with multiple statements (no params) - should work
print("Test 1: execute() with multiple SELECT statements (no params)")
try:
    cursor.execute("SELECT 1 as a; SELECT 2 as b;")
    row = cursor.fetchone()
    # psycopg3 returns the FIRST result set (unlike psycopg2 which returns last)
    print(f"  PASS: execute() supports multi-statements (no params)")
    print(f"  Result from first statement: a = {row[0]}")
    passed += 1
except Exception as e:
    print(f"  FAIL: execute() rejected multi-statements (no params)")
    print(f"  Error: {type(e).__name__}: {e}")
    failed += 1
print()

# Test 2: execute() with SELECT + INSERT (no params) - should work
print("Test 2: execute() with SELECT + INSERT (stacked modification, no params)")
test_action = f"psycopg3_test_{int(time.time())}"
try:
    cursor.execute(f"SELECT 1; INSERT INTO logs (action, ip_address) VALUES ('{test_action}', '127.0.0.1');")
    # Verify insert worked
    cursor.execute(f"SELECT * FROM logs WHERE action = '{test_action}'")
    rows = cursor.fetchall()
    if len(rows) > 0:
        print(f"  PASS: execute() executed stacked INSERT ({len(rows)} rows inserted)")
        passed += 1
    else:
        print(f"  FAIL: INSERT did not persist")
        failed += 1
    # Cleanup
    cursor.execute(f"DELETE FROM logs WHERE action = '{test_action}'")
except Exception as e:
    print(f"  FAIL: execute() rejected stacked modification (no params)")
    print(f"  Error: {type(e).__name__}: {e}")
    failed += 1
print()

# Test 3: execute() with single statement + params (should work)
print("Test 3: execute() with single statement + params")
try:
    cursor.execute("SELECT %s::int + %s::int as sum", (5, 3))
    row = cursor.fetchone()
    if row[0] == 8:
        print(f"  PASS: execute() works with single parameterized statement (sum = 8)")
        passed += 1
    else:
        print(f"  FAIL: Unexpected result: {row[0]}")
        failed += 1
except Exception as e:
    print(f"  FAIL: execute() failed on single parameterized statement")
    print(f"  Error: {type(e).__name__}: {e}")
    failed += 1
print()

# Test 4: execute() with multiple statements + params (should FAIL - extended query protocol)
print("Test 4: execute() with multiple statements + params")
print("  Note: psycopg3 uses server-side parameter binding (PQexecParams), which rejects multi-statements")
try:
    cursor.execute("SELECT %s; SELECT %s;", (1, 2))
    row = cursor.fetchone()
    print(f"  FAIL: execute() unexpectedly allowed multi-statements with params (result: {row})")
    failed += 1
except Exception as e:
    print(f"  PASS: execute() correctly rejected multi-statements with params")
    print(f"  Error (expected): {type(e).__name__}")
    passed += 1
print()

# Test 5: ClientCursor with multiple statements + params (should work - client-side binding)
print("Test 5: ClientCursor with multiple statements + params")
print("  Note: ClientCursor uses client-side binding like psycopg2")
try:
    from psycopg import ClientCursor
    # In psycopg3, create ClientCursor by passing connection directly
    ccur = ClientCursor(conn)
    ccur.execute("SELECT %s; SELECT %s;", (1, 2))
    row = ccur.fetchone()
    # psycopg3 returns the FIRST result set
    if row[0] == 1:
        print(f"  PASS: ClientCursor supports multi-statements with params (returns first result: {row[0]})")
        passed += 1
    else:
        print(f"  FAIL: Unexpected result: {row}")
        failed += 1
    ccur.close()
except Exception as e:
    print(f"  FAIL: ClientCursor rejected multi-statements with params")
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
