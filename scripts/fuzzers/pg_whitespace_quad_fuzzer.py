#!/usr/bin/env python3
"""
PostgreSQL 4-byte Whitespace Fuzzer
Tests 4-byte combinations (0x00-0x7F charset)
"""

import sys
from itertools import product
from fuzzer_utils import get_pg_connection


def main():
    port = int(sys.argv[1]) if len(sys.argv) > 1 else 5432
    outfile = sys.argv[2] if len(sys.argv) > 2 else "pg_quad_results.txt"

    conn = None
    cur = None
    unexpected = set()
    known_valid = 0
    results = []

    try:
        conn = get_pg_connection(port)
        cur = conn.cursor()

        cur.execute("SELECT version()")
        version = cur.fetchone()[0].split(',')[0]

        single_ws = {0x09, 0x0A, 0x0C, 0x0D, 0x20}
        non_ws = [b for b in range(128) if b not in single_ws]  # 123 bytes

        results.append(f"PostgreSQL: {version}")
        results.append("Testing 4-byte combinations (0x00-0x7F)")
        results.append("")

        print(f"PostgreSQL: {version}")
        print(f"Output: {outfile}")

        # Phase 1: All known ws (5^4 = 625)
        print("\nPhase 1: Known whitespace combos (5⁴ = 625)...")
        for combo in product(single_ws, repeat=4):
            try:
                chars = ''.join(chr(c) for c in combo)
                cur.execute(f"SELECT 1 UNION{chars}SELECT 2")
                if len(cur.fetchall()) == 2:
                    known_valid += 1
            except Exception:
                pass
        print(f"  Valid: {known_valid}/625")
        results.append(f"Known whitespace 4-byte combos: {known_valid}/625")

        # Phase 2: [x][ws][ws][ws] - 123 * 125 = 15,375
        print("\nPhase 2: [x][ws][ws][ws]...")
        count = 0
        for b in non_ws:
            for combo in product(single_ws, repeat=3):
                count += 1
                try:
                    chars = chr(b) + ''.join(chr(c) for c in combo)
                    cur.execute(f"SELECT 1 UNION{chars}SELECT 2")
                    if len(cur.fetchall()) == 2:
                        unexpected.add((b,) + combo)
                except Exception:
                    pass
        print(f"  Tested: {count}")

        # Phase 3: [ws][x][ws][ws]
        print("\nPhase 3: [ws][x][ws][ws]...")
        count = 0
        for w1 in single_ws:
            for b in non_ws:
                for combo in product(single_ws, repeat=2):
                    count += 1
                    try:
                        chars = chr(w1) + chr(b) + ''.join(chr(c) for c in combo)
                        cur.execute(f"SELECT 1 UNION{chars}SELECT 2")
                        if len(cur.fetchall()) == 2:
                            unexpected.add((w1, b) + combo)
                    except Exception:
                        pass
        print(f"  Tested: {count}")

        # Phase 4: [ws][ws][x][ws]
        print("\nPhase 4: [ws][ws][x][ws]...")
        count = 0
        for combo in product(single_ws, repeat=2):
            for b in non_ws:
                for w in single_ws:
                    count += 1
                    try:
                        chars = ''.join(chr(c) for c in combo) + chr(b) + chr(w)
                        cur.execute(f"SELECT 1 UNION{chars}SELECT 2")
                        if len(cur.fetchall()) == 2:
                            unexpected.add(combo + (b, w))
                    except Exception:
                        pass
        print(f"  Tested: {count}")

        # Phase 5: [ws][ws][ws][x]
        print("\nPhase 5: [ws][ws][ws][x]...")
        count = 0
        for combo in product(single_ws, repeat=3):
            for b in non_ws:
                count += 1
                try:
                    chars = ''.join(chr(c) for c in combo) + chr(b)
                    cur.execute(f"SELECT 1 UNION{chars}SELECT 2")
                    if len(cur.fetchall()) == 2:
                        unexpected.add(combo + (b,))
                except Exception:
                    pass
        print(f"  Tested: {count}")

        # Phase 6: [x][x][ws][ws] - two non-ws
        print("\nPhase 6: [x][x][ws][ws]...")
        count = 0
        for b1 in non_ws:
            for b2 in non_ws:
                for combo in product(single_ws, repeat=2):
                    count += 1
                    try:
                        chars = chr(b1) + chr(b2) + ''.join(chr(c) for c in combo)
                        cur.execute(f"SELECT 1 UNION{chars}SELECT 2")
                        if len(cur.fetchall()) == 2:
                            unexpected.add((b1, b2) + combo)
                    except Exception:
                        pass
            if b1 % 20 == 0:
                print(f"    ...{count} tested", file=sys.stderr)
        print(f"  Tested: {count}")

        # Phase 7: [ws][ws][x][x]
        print("\nPhase 7: [ws][ws][x][x]...")
        count = 0
        for combo in product(single_ws, repeat=2):
            for b1 in non_ws:
                for b2 in non_ws:
                    count += 1
                    try:
                        chars = ''.join(chr(c) for c in combo) + chr(b1) + chr(b2)
                        cur.execute(f"SELECT 1 UNION{chars}SELECT 2")
                        if len(cur.fetchall()) == 2:
                            unexpected.add(combo + (b1, b2))
                    except Exception:
                        pass
        print(f"  Tested: {count}")

        # Phase 8: [x][ws][x][ws] and [ws][x][ws][x] - alternating
        print("\nPhase 8: Alternating patterns...")
        count = 0
        for b1 in non_ws:
            for w1 in single_ws:
                for b2 in non_ws:
                    for w2 in single_ws:
                        count += 1
                        try:
                            chars = chr(b1) + chr(w1) + chr(b2) + chr(w2)
                            cur.execute(f"SELECT 1 UNION{chars}SELECT 2")
                            if len(cur.fetchall()) == 2:
                                unexpected.add((b1, w1, b2, w2))
                        except Exception:
                            pass
                        try:
                            chars = chr(w1) + chr(b1) + chr(w2) + chr(b2)
                            cur.execute(f"SELECT 1 UNION{chars}SELECT 2")
                            if len(cur.fetchall()) == 2:
                                unexpected.add((w1, b1, w2, b2))
                        except Exception:
                            pass
        print(f"  Tested: {count * 2}")
    finally:
        if cur:
            cur.close()
        if conn:
            conn.close()

    # Sort for stable output
    unexpected_sorted = sorted(unexpected)

    results.append("")
    results.append("=" * 60)
    results.append(f"UNEXPECTED COMBINATIONS: {len(unexpected)}")
    results.append("=" * 60)

    if unexpected:
        results.append("")
        results.append("| Byte 1 | Byte 2 | Byte 3 | Byte 4 | URL Encoded      |")
        results.append("| ------ | ------ | ------ | ------ | ---------------- |")
        for combo in unexpected_sorted:
            b1, b2, b3, b4 = combo
            results.append(f"| 0x{b1:02X}   | 0x{b2:02X}   | 0x{b3:02X}   | 0x{b4:02X}   | %{b1:02X}%{b2:02X}%{b3:02X}%{b4:02X}           |")
    else:
        results.append("")
        results.append("No unexpected combinations found!")
        results.append("Only known whitespace characters work in 4-byte sequences.")

    # Write to file
    with open(outfile, 'w') as f:
        f.write('\n'.join(results))

    print("\n" + "=" * 60)
    print(f"RESULTS: {len(unexpected)} unexpected combinations")
    print(f"Written to: {outfile}")
    print("=" * 60)


if __name__ == "__main__":
    main()
