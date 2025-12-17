#!/usr/bin/env python3
"""
PostgreSQL Whitespace Character Fuzzer
Tests Unicode range 0x0000-0xFFFF to find valid whitespace substitutes.
"""

import argparse
import sys

import psycopg2

from fuzzer_utils import (
    get_pg_connection,
    get_char_description,
    url_encode_char,
    log_debug,
)


def parse_args() -> argparse.Namespace:
    """Parse command line arguments."""
    parser = argparse.ArgumentParser(
        description="PostgreSQL Whitespace Fuzzer - Tests Unicode range 0x0000-0xFFFF for valid whitespace substitutes."
    )
    parser.add_argument(
        "port",
        nargs="?",
        type=int,
        default=5432,
        help="PostgreSQL port (default: 5432)",
    )
    parser.add_argument(
        "-v",
        "--verbose",
        action="store_true",
        help="Enable verbose output - log exceptions to stderr",
    )
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    port = args.port
    verbose = args.verbose

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

    return 0


if __name__ == "__main__":
    sys.exit(main())
