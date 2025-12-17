#!/usr/bin/env python3
"""
PostgreSQL 4-byte Whitespace Fuzzer
Tests 4-byte combinations (0x00-0x7F charset)
"""

import argparse
import os
import sys
from itertools import product

import psycopg2

from fuzzer_utils import get_pg_connection, log_debug


def parse_args() -> argparse.Namespace:
    """Parse command line arguments."""
    parser = argparse.ArgumentParser(
        description="PostgreSQL 4-byte Whitespace Fuzzer - Tests 4-byte combinations (0x00-0x7F charset)"
    )
    parser.add_argument(
        "port",
        nargs="?",
        type=int,
        default=5432,
        help="PostgreSQL port (default: 5432)",
    )
    parser.add_argument(
        "outfile",
        nargs="?",
        default="pg_quad_results.txt",
        help="Output file for results (default: pg_quad_results.txt)",
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
    outfile = args.outfile
    verbose = args.verbose

    conn = None
    cur = None
    unexpected = set()
    known_valid = 0
    results = []

    try:
        conn = get_pg_connection(port)
        cur = conn.cursor()

        cur.execute("SELECT version()")
        row = cur.fetchone()
        version = row[0].split(",")[0] if row else "unknown"

        single_ws = {0x09, 0x0A, 0x0C, 0x0D, 0x20}
        non_ws = [b for b in range(128) if b not in single_ws]  # 123 bytes

        results.append(f"PostgreSQL: {version}")
        results.append("Testing 4-byte combinations (0x00-0x7F)")
        results.append("")

        print(f"PostgreSQL: {version}")
        if verbose:
            print("Verbose mode enabled - exceptions will be logged")
        print(f"Output: {outfile}")

        # Phase 1: All known ws (5^4 = 625)
        print("\nPhase 1: Known whitespace combos (5⁴ = 625)...")
        for combo in product(single_ws, repeat=4):
            try:
                chars = "".join(chr(c) for c in combo)
                cur.execute(f"SELECT 1 UNION{chars}SELECT 2")
                if len(cur.fetchall()) == 2:
                    known_valid += 1
            except KeyboardInterrupt:
                raise
            except psycopg2.Error as e:
                log_debug(verbose, f"Phase1 {combo}: {type(e).__name__}: {e}")
        print(f"  Valid: {known_valid}/625")
        results.append(f"Known whitespace 4-byte combos: {known_valid}/625")

        # Phase 2: [x][ws][ws][ws] - 123 * 125 = 15,375
        print("\nPhase 2: [x][ws][ws][ws]...")
        count = 0
        for b in non_ws:
            for combo in product(single_ws, repeat=3):
                count += 1
                try:
                    chars = chr(b) + "".join(chr(c) for c in combo)
                    cur.execute(f"SELECT 1 UNION{chars}SELECT 2")
                    if len(cur.fetchall()) == 2:
                        unexpected.add((b, *combo))
                except KeyboardInterrupt:
                    raise
                except psycopg2.Error as e:
                    log_debug(
                        verbose, f"Phase2 ({b:02X},ws,ws,ws): {type(e).__name__}: {e}"
                    )
        print(f"  Tested: {count}")

        # Phase 3: [ws][x][ws][ws]
        print("\nPhase 3: [ws][x][ws][ws]...")
        count = 0
        for w1 in single_ws:
            for b in non_ws:
                for combo in product(single_ws, repeat=2):
                    count += 1
                    try:
                        chars = chr(w1) + chr(b) + "".join(chr(c) for c in combo)
                        cur.execute(f"SELECT 1 UNION{chars}SELECT 2")
                        if len(cur.fetchall()) == 2:
                            unexpected.add((w1, b, *combo))
                    except KeyboardInterrupt:
                        raise
                    except psycopg2.Error as e:
                        log_debug(
                            verbose,
                            f"Phase3 ({w1:02X},{b:02X},ws,ws): {type(e).__name__}: {e}",
                        )
        print(f"  Tested: {count}")

        # Phase 4: [ws][ws][x][ws]
        print("\nPhase 4: [ws][ws][x][ws]...")
        count = 0
        for combo in product(single_ws, repeat=2):
            for b in non_ws:
                for w in single_ws:
                    count += 1
                    try:
                        chars = "".join(chr(c) for c in combo) + chr(b) + chr(w)
                        cur.execute(f"SELECT 1 UNION{chars}SELECT 2")
                        if len(cur.fetchall()) == 2:
                            unexpected.add((*combo, b, w))
                    except KeyboardInterrupt:
                        raise
                    except psycopg2.Error as e:
                        log_debug(
                            verbose,
                            f"Phase4 (ws,ws,{b:02X},{w:02X}): {type(e).__name__}: {e}",
                        )
        print(f"  Tested: {count}")

        # Phase 5: [ws][ws][ws][x]
        print("\nPhase 5: [ws][ws][ws][x]...")
        count = 0
        for combo in product(single_ws, repeat=3):
            for b in non_ws:
                count += 1
                try:
                    chars = "".join(chr(c) for c in combo) + chr(b)
                    cur.execute(f"SELECT 1 UNION{chars}SELECT 2")
                    if len(cur.fetchall()) == 2:
                        unexpected.add((*combo, b))
                except KeyboardInterrupt:
                    raise
                except psycopg2.Error as e:
                    log_debug(
                        verbose, f"Phase5 (ws,ws,ws,{b:02X}): {type(e).__name__}: {e}"
                    )
        print(f"  Tested: {count}")

        # Phase 6: [x][x][ws][ws] - two non-ws
        print("\nPhase 6: [x][x][ws][ws]...")
        count = 0
        for b1 in non_ws:
            for b2 in non_ws:
                for combo in product(single_ws, repeat=2):
                    count += 1
                    try:
                        chars = chr(b1) + chr(b2) + "".join(chr(c) for c in combo)
                        cur.execute(f"SELECT 1 UNION{chars}SELECT 2")
                        if len(cur.fetchall()) == 2:
                            unexpected.add((b1, b2, *combo))
                    except KeyboardInterrupt:
                        raise
                    except psycopg2.Error as e:
                        log_debug(
                            verbose,
                            f"Phase6 ({b1:02X},{b2:02X},ws,ws): {type(e).__name__}: {e}",
                        )
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
                        chars = "".join(chr(c) for c in combo) + chr(b1) + chr(b2)
                        cur.execute(f"SELECT 1 UNION{chars}SELECT 2")
                        if len(cur.fetchall()) == 2:
                            unexpected.add((*combo, b1, b2))
                    except KeyboardInterrupt:
                        raise
                    except psycopg2.Error as e:
                        log_debug(
                            verbose,
                            f"Phase7 (ws,ws,{b1:02X},{b2:02X}): {type(e).__name__}: {e}",
                        )
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
                        except KeyboardInterrupt:
                            raise
                        except psycopg2.Error as e:
                            log_debug(
                                verbose,
                                f"Phase8a ({b1:02X},{w1:02X},{b2:02X},{w2:02X}): {type(e).__name__}: {e}",
                            )
                        try:
                            chars = chr(w1) + chr(b1) + chr(w2) + chr(b2)
                            cur.execute(f"SELECT 1 UNION{chars}SELECT 2")
                            if len(cur.fetchall()) == 2:
                                unexpected.add((w1, b1, w2, b2))
                        except KeyboardInterrupt:
                            raise
                        except psycopg2.Error as e:
                            log_debug(
                                verbose,
                                f"Phase8b ({w1:02X},{b1:02X},{w2:02X},{b2:02X}): {type(e).__name__}: {e}",
                            )
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
            results.append(
                f"| 0x{b1:02X}   | 0x{b2:02X}   | 0x{b3:02X}   | 0x{b4:02X}   | %{b1:02X}%{b2:02X}%{b3:02X}%{b4:02X}           |"
            )
    else:
        results.append("")
        results.append("No unexpected combinations found!")
        results.append("Only known whitespace characters work in 4-byte sequences.")

    # Write to file
    content = "\n".join(results)
    write_ok = False
    try:
        with open(outfile, "w", encoding="utf-8") as f:
            f.write(content)
            f.flush()
            os.fsync(f.fileno())
        write_ok = True
        print("\n" + "=" * 60)
        print(f"RESULTS: {len(unexpected)} unexpected combinations")
        print(f"Written to: {outfile}")
        print("=" * 60)
    except OSError as e:
        print(f"\nERROR: Failed to write results to {outfile}: {e}", file=sys.stderr)
        # Attempt to save partial results to a fallback file
        partial_file = f"{outfile}.partial"
        try:
            with open(partial_file, "w", encoding="utf-8") as f:
                f.write(content)
                f.flush()
                os.fsync(f.fileno())
            print(f"Partial results saved to: {partial_file}", file=sys.stderr)
            write_ok = True
        except OSError as e2:
            print(f"Failed to save partial results: {e2}", file=sys.stderr)

    return 0 if write_ok else 1


if __name__ == "__main__":
    sys.exit(main())
