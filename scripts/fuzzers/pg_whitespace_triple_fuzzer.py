#!/usr/bin/env python3
"""
PostgreSQL Triple Whitespace Character Fuzzer
Tests 3-byte combinations. Optimized to find unexpected results.
"""

import sys
from itertools import product
from fuzzer_utils import get_pg_connection


def main():
    port = int(sys.argv[1]) if len(sys.argv) > 1 else 5432

    conn = None
    cur = None
    try:
        conn = get_pg_connection(port)
        cur = conn.cursor()

        cur.execute("SELECT version()")
        version = cur.fetchone()[0].split(',')[0]
        print(f"PostgreSQL: {version}")

        # Known single whitespace chars
        single_ws = {0x09, 0x0A, 0x0C, 0x0D, 0x20}

        # First, verify all-known-ws combinations work (5^3 = 125)
        print("\nPhase 1: Testing all known whitespace combos (5³ = 125)...")
        known_valid = 0
        for combo in product(single_ws, repeat=3):
            try:
                chars = ''.join(chr(c) for c in combo)
                query = f"SELECT 1 UNION{chars}SELECT 2"
                cur.execute(query)
                if len(cur.fetchall()) == 2:
                    known_valid += 1
            except Exception:
                pass
        print(f"  Known whitespace combos that work: {known_valid}/125")

        # Phase 2: Test combos with at least one non-whitespace byte
        # Focus on control chars and near-whitespace bytes
        print("\nPhase 2: Testing combos with non-whitespace bytes...")
        print("  (Testing bytes 0x00-0x20 + some special chars)")

        # Test bytes: 0x00-0x20 range plus some interesting ones
        test_bytes = [*range(0x21), 0x7F, 0xA0, 0x85]  # control chars + DEL + NBSP + NEL

        unexpected = set()
        tested = 0

        for combo in product(test_bytes, repeat=3):
            # Skip if all are known whitespace (already tested)
            if all(c in single_ws for c in combo):
                continue

            tested += 1
            try:
                chars = ''.join(chr(c) for c in combo)
                query = f"SELECT 1 UNION{chars}SELECT 2"
                cur.execute(query)
                if len(cur.fetchall()) == 2:
                    unexpected.add(combo)
            except Exception:
                pass

            if tested % 10000 == 0:
                print(f"    ...tested {tested}, found {len(unexpected)} unexpected", file=sys.stderr)

        # Phase 3: Quick scan of full range with one wildcard
        print("\nPhase 3: Testing [known_ws][known_ws][0x00-0xFF]...")
        for ws1 in single_ws:
            for ws2 in single_ws:
                for b in range(256):
                    if b in single_ws:
                        continue
                    try:
                        chars = chr(ws1) + chr(ws2) + chr(b)
                        query = f"SELECT 1 UNION{chars}SELECT 2"
                        cur.execute(query)
                        if len(cur.fetchall()) == 2:
                            unexpected.add((ws1, ws2, b))
                    except Exception:
                        pass

        print("\nPhase 4: Testing [known_ws][0x00-0xFF][known_ws]...")
        for ws1 in single_ws:
            for b in range(256):
                if b in single_ws:
                    continue
                for ws2 in single_ws:
                    try:
                        chars = chr(ws1) + chr(b) + chr(ws2)
                        query = f"SELECT 1 UNION{chars}SELECT 2"
                        cur.execute(query)
                        if len(cur.fetchall()) == 2:
                            unexpected.add((ws1, b, ws2))
                    except Exception:
                        pass

        print("\nPhase 5: Testing [0x00-0xFF][known_ws][known_ws]...")
        for b in range(256):
            if b in single_ws:
                continue
            for ws1 in single_ws:
                for ws2 in single_ws:
                    try:
                        chars = chr(b) + chr(ws1) + chr(ws2)
                        query = f"SELECT 1 UNION{chars}SELECT 2"
                        cur.execute(query)
                        if len(cur.fetchall()) == 2:
                            unexpected.add((b, ws1, ws2))
                    except Exception:
                        pass
    finally:
        if cur:
            cur.close()
        if conn:
            conn.close()

    print("\n" + "=" * 60)
    print("RESULTS")
    print("=" * 60)
    print(f"Known whitespace combos (all 3 bytes from known set): {known_valid}")

    if unexpected:
        print(f"\nUNEXPECTED COMBINATIONS: {len(unexpected)}")
        print("| Byte 1 | Byte 2 | Byte 3 | URL Encoded    |")
        print("| ------ | ------ | ------ | -------------- |")
        for i, j, k in sorted(unexpected)[:50]:  # Show first 50
            print(f"| 0x{i:02X}   | 0x{j:02X}   | 0x{k:02X}   | %{i:02X}%{j:02X}%{k:02X}         |")
        if len(unexpected) > 50:
            print(f"... and {len(unexpected) - 50} more")
    else:
        print("\nNo unexpected combinations found!")
        print("Only known whitespace characters work, even in 3-byte sequences.")

if __name__ == "__main__":
    main()
