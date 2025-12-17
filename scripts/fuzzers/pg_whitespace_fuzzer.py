#!/usr/bin/env python3
"""
PostgreSQL Whitespace Character Fuzzer
Tests Unicode range 0x0000-0xFFFF to find valid whitespace substitutes.

Usage: python pg_whitespace_fuzzer.py [port] [--verbose]
"""

import sys

import psycopg2

from fuzzer_utils import (
    get_pg_connection,
    get_char_description,
    url_encode_char,
    log_debug,
)


def main():
    # Parse arguments
    args = [a for a in sys.argv[1:] if not a.startswith("--")]
    verbose = "--verbose" in sys.argv or "-v" in sys.argv

    if args:
        try:
            port = int(args[0])
        except ValueError:
            print(
                f"Error: Invalid port '{args[0]}' - must be an integer", file=sys.stderr
            )
            sys.exit(1)
    else:
        port = 5432

    conn = None
    cur = None
    valid_whitespace = []
    valid_after_select = []  # Characters that work after SELECT before column (includes operators)

    try:
        conn = get_pg_connection(port)
        cur = conn.cursor()

        cur.execute("SELECT version()")
        row = cur.fetchone()
        version = row[0].split(",")[0] if row else "unknown"
        print(f"PostgreSQL: {version}")
        if verbose:
            print("Verbose mode enabled - exceptions will be logged")
        print("Testing 0x0000-0xFFFF as whitespace...\n")

        for i in range(0x10000):
            char = chr(i)

            # Test 1: TRUE whitespace - works between any keywords (UNION{char}SELECT)
            try:
                query = f"SELECT 1 UNION{char}SELECT 2"
                cur.execute(query)
                result = cur.fetchall()
                if len(result) == 2:
                    valid_whitespace.append(i)
            except KeyboardInterrupt:
                raise
            except psycopg2.Error as e:
                log_debug(verbose, f"0x{i:04X} UNION test: {type(e).__name__}: {e}")

            # Test 2: Works after SELECT before column (includes unary operators)
            try:
                query = f"SELECT{char}1"
                cur.execute(query)
                result = cur.fetchone()
                if result and result[0] == 1:
                    if i not in valid_whitespace:
                        valid_after_select.append(i)
            except KeyboardInterrupt:
                raise
            except psycopg2.Error as e:
                log_debug(verbose, f"0x{i:04X} SELECT test: {type(e).__name__}: {e}")

            if i % 5000 == 0 and i > 0:
                print(f"  ...tested {i} characters", file=sys.stderr)
    finally:
        if cur:
            cur.close()
        if conn:
            conn.close()

    print("\n" + "=" * 60)
    print(f"TRUE WHITESPACE CHARACTERS: {len(valid_whitespace)}")
    print("(Can replace space between ANY keywords)")
    print("=" * 60 + "\n")

    print("| Hex    | Dec   | URL Encoded | Description |")
    print("| ------ | ----- | ----------- | ----------- |")
    for i in valid_whitespace:
        print(
            f"| 0x{i:04X} | {i:5} | {url_encode_char(i):11} | {get_char_description(i)} |"
        )

    if valid_after_select:
        print("\n" + "=" * 60)
        print(
            f"UNARY OPERATORS (work after SELECT before value): {len(valid_after_select)}"
        )
        print("(NOT true whitespace - only work in specific contexts)")
        print("=" * 60 + "\n")

        print("| Hex    | Dec   | Character   | Description |")
        print("| ------ | ----- | ----------- | ----------- |")
        for i in valid_after_select:
            char_repr = repr(chr(i)) if 0x20 <= i < 0x7F else ""
            print(f"| 0x{i:04X} | {i:5} | {char_repr:11} | {get_char_description(i)} |")


if __name__ == "__main__":
    main()
