#!/usr/bin/env python3
"""
PostgreSQL Double Whitespace Character Fuzzer
Tests all combinations of two bytes (0x00-0xFF) as whitespace.
"""

import sys
from fuzzer_utils import get_pg_connection


def main():
    port = int(sys.argv[1]) if len(sys.argv) > 1 else 5432

    conn = get_pg_connection(port)
    cur = conn.cursor()

    cur.execute("SELECT version()")
    version = cur.fetchone()[0].split(',')[0]
    print(f"PostgreSQL: {version}")
    print(f"Testing all 2-byte combinations (0x00-0xFF x 0x00-0xFF = 65536 combos)...\n")

    # Known single whitespace chars for comparison
    single_ws = {0x09, 0x0A, 0x0C, 0x0D, 0x20}

    valid = []

    for i in range(256):
        for j in range(256):
            try:
                chars = chr(i) + chr(j)
                query = f"SELECT 1 UNION{chars}SELECT 2"
                cur.execute(query)
                result = cur.fetchall()
                if len(result) == 2:
                    # Check if this is just two known whitespace chars
                    both_known = i in single_ws and j in single_ws
                    valid.append((i, j, both_known))
            except Exception:
                pass

        if i % 16 == 0:
            print(f"  ...tested {i * 256} combinations, found {len(valid)} valid", file=sys.stderr)

    cur.close()
    conn.close()

    # Separate into expected (both chars are known ws) and unexpected
    expected = [(i, j) for i, j, both in valid if both]
    unexpected = [(i, j) for i, j, both in valid if not both]

    print(f"\n{'='*60}")
    print(f"RESULTS: {len(valid)} valid 2-char whitespace combinations")
    print(f"{'='*60}\n")

    if unexpected:
        print(f"UNEXPECTED COMBINATIONS ({len(unexpected)}):")
        print(f"(At least one char is NOT a known single whitespace)\n")
        print("| Byte 1 | Byte 2 | URL Encoded |")
        print("| ------ | ------ | ----------- |")
        for i, j in unexpected:
            print(f"| 0x{i:02X}   | 0x{j:02X}   | %{i:02X}%{j:02X}       |")

    print(f"\nExpected combinations (both chars are known whitespace): {len(expected)}")

    # Show which single chars appear in valid combos
    chars_in_valid = set()
    for i, j, _ in valid:
        chars_in_valid.add(i)
        chars_in_valid.add(j)

    print(f"\nUnique bytes that appear in valid combinations: {sorted(chars_in_valid)}")

if __name__ == "__main__":
    main()
