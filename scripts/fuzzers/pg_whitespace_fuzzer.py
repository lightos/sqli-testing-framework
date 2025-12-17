#!/usr/bin/env python3
"""
PostgreSQL Whitespace Character Fuzzer
Tests Unicode range 0x0000-0xFFFF to find valid whitespace substitutes.
"""

import sys
from fuzzer_utils import get_pg_connection, get_char_description, url_encode_char


def main():
    port = int(sys.argv[1]) if len(sys.argv) > 1 else 5432

    conn = get_pg_connection(port)
    cur = conn.cursor()

    cur.execute("SELECT version()")
    version = cur.fetchone()[0].split(',')[0]
    print(f"PostgreSQL: {version}")
    print(f"Testing 0x0000-0xFFFF as whitespace...\n")

    valid_whitespace = []
    valid_after_select = []  # Characters that work after SELECT before column (includes operators)

    for i in range(0x10000):
        char = chr(i)

        # Test 1: TRUE whitespace - works between any keywords (UNION{char}SELECT)
        try:
            query = f"SELECT 1 UNION{char}SELECT 2"
            cur.execute(query)
            result = cur.fetchall()
            if len(result) == 2:
                valid_whitespace.append(i)
        except Exception:
            pass

        # Test 2: Works after SELECT before column (includes unary operators)
        try:
            query = f"SELECT{char}1"
            cur.execute(query)
            result = cur.fetchone()
            if result and result[0] == 1:
                if i not in valid_whitespace:
                    valid_after_select.append(i)
        except Exception:
            pass

        if i % 5000 == 0 and i > 0:
            print(f"  ...tested {i} characters", file=sys.stderr)

    cur.close()
    conn.close()

    print(f"\n{'='*60}")
    print(f"TRUE WHITESPACE CHARACTERS: {len(valid_whitespace)}")
    print(f"(Can replace space between ANY keywords)")
    print(f"{'='*60}\n")

    print("| Hex    | Dec   | URL Encoded | Description |")
    print("| ------ | ----- | ----------- | ----------- |")
    for i in valid_whitespace:
        print(f"| 0x{i:04X} | {i:5} | {url_encode_char(i):11} | {get_char_description(i)} |")

    if valid_after_select:
        print(f"\n{'='*60}")
        print(f"UNARY OPERATORS (work after SELECT before value): {len(valid_after_select)}")
        print(f"(NOT true whitespace - only work in specific contexts)")
        print(f"{'='*60}\n")

        print("| Hex    | Dec   | Character   | Description |")
        print("| ------ | ----- | ----------- | ----------- |")
        for i in valid_after_select:
            char_repr = repr(chr(i)) if i >= 0x20 and i < 0x7F else ""
            print(f"| 0x{i:04X} | {i:5} | {char_repr:11} | {get_char_description(i)} |")

if __name__ == "__main__":
    main()
