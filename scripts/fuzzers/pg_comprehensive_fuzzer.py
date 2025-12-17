#!/usr/bin/env python3
"""
PostgreSQL Comprehensive WAF Evasion Fuzzer
Tests various encoding/obfuscation techniques for SQL injection.
"""

import os
import psycopg2
import sys
import tempfile
import traceback
from datetime import datetime, timezone

class PgFuzzer:
    def __init__(self, port=5432):
        host = os.environ.get("PGHOST", "localhost")
        port = int(os.environ.get("PGPORT", port))
        user = os.environ.get("PGUSER", "postgres")
        password = os.environ.get("PGPASSWORD")
        database = os.environ.get("PGDATABASE", "postgres")

        if not password:
            raise ValueError("PGPASSWORD environment variable is required")

        self.conn = psycopg2.connect(
            host=host, port=port, user=user,
            password=password, database=database
        )
        self.conn.autocommit = True
        self.cur = self.conn.cursor()
        self.cur.execute("SELECT version()")
        self.version = self.cur.fetchone()[0].split(',')[0]
        self.results = {"version": self.version, "tests": {}}

    def test(self, name, query, expected=None):
        """Run a test query and record result."""
        try:
            self.cur.execute(query)
            if self.cur.description:  # Query returns rows
                result = self.cur.fetchone()
            else:
                result = None
            success = True
            value = result[0] if result else None
            if expected is not None:
                success = (str(value) == str(expected))
            return {"success": success, "value": value, "query": query[:100], "name": name}
        except Exception as e:
            return {"success": False, "error": str(e)[:100], "query": query[:100], "name": name}

    def close(self):
        self.cur.close()
        self.conn.close()


def fuzz_dollar_quotes(fuzzer):
    """Test dollar quote tag variations."""
    print("\n" + "="*60)
    print("1. DOLLAR QUOTE TAG FUZZING")
    print("="*60)

    results = []

    # Basic dollar quotes
    basic_tests = [
        ("$$test$$", "empty tag"),
        ("$a$test$a$", "single char"),
        ("$tag$test$tag$", "word tag"),
        ("$TAG$test$TAG$", "uppercase tag"),
        ("$TaG$test$TaG$", "mixed case"),
        ("$_$test$_$", "underscore"),
        ("$__$test$__$", "double underscore"),
        ("$a1$test$a1$", "alphanumeric"),
        ("$1$test$1$", "starts with number"),
        ("$123$test$123$", "all numbers"),
    ]

    for tag, desc in basic_tests:
        r = fuzzer.test(desc, f"SELECT {tag}")
        results.append((desc, r["success"], tag))
        status = "✓" if r["success"] else "✗"
        print(f"  {status} {desc}: {tag}")

    # Special character tags
    print("\n  Testing special chars in tags...")
    special_chars = "!@#%^&*()-+=[]{}|;:',.<>?/`~"
    for char in special_chars:
        tag = f"${char}$test${char}$"
        r = fuzzer.test(f"char {repr(char)}", f"SELECT {tag}")
        if r["success"]:
            results.append((f"special:{char}", True, tag))
            print(f"    ✓ ${char}$ works!")

    # Unicode in tags
    print("\n  Testing unicode in tags...")
    unicode_tests = [
        ("$α$test$α$", "greek alpha"),
        ("$日$test$日$", "CJK char"),
        ("$💀$test$💀$", "emoji"),
        ("$ñ$test$ñ$", "latin extended"),
    ]
    for tag, desc in unicode_tests:
        r = fuzzer.test(desc, f"SELECT {tag}")
        status = "✓" if r["success"] else "✗"
        print(f"    {status} {desc}")
        results.append((desc, r["success"], tag))

    return results


def fuzz_string_encoding(fuzzer):
    """Test string encoding variations."""
    print("\n" + "="*60)
    print("2. STRING ENCODING FUZZING")
    print("="*60)

    results = []
    target = "admin"  # String we're trying to represent

    # CHR() variations
    print("\n  CHR() encoding...")
    chr_tests = [
        ("CHR(97)||CHR(100)||CHR(109)||CHR(105)||CHR(110)", "basic CHR concat"),
        ("CHR(97)|| CHR(100)|| CHR(109)|| CHR(105)|| CHR(110)", "CHR with spaces"),
        ("chr(97)||chr(100)||chr(109)||chr(105)||chr(110)", "lowercase chr"),
        ("CONCAT(CHR(97),CHR(100),CHR(109),CHR(105),CHR(110))", "CONCAT with CHR"),
    ]
    for expr, desc in chr_tests:
        r = fuzzer.test(desc, f"SELECT {expr}")
        status = "✓" if r["success"] and r.get("value") == target else "✗"
        print(f"    {status} {desc}")
        results.append((desc, r["success"], expr))

    # Escape strings E''
    print("\n  Escape strings (E'')...")
    escape_tests = [
        (r"E'\x61\x64\x6d\x69\x6e'", "hex escape"),
        (r"E'\141\144\155\151\156'", "octal escape"),
        (r"E'ad\x6din'", "mixed hex"),
        (r"e'\x61dmin'", "lowercase e"),
        (r"E'admin'", "no escapes"),
        (r"E'\u0061dmin'", "unicode escape in E string"),
    ]
    for expr, desc in escape_tests:
        r = fuzzer.test(desc, f"SELECT {expr}")
        status = "✓" if r["success"] else "✗"
        val = r.get("value", r.get("error", "")[:30])
        print(f"    {status} {desc}: {val}")
        results.append((desc, r["success"], expr))

    # Unicode strings U&''
    print("\n  Unicode strings (U&'')...")
    unicode_tests = [
        (r"U&'\0061\0064\006d\0069\006e'", "4-digit unicode"),
        (r"U&'\+000061dmin'", "6-digit unicode"),
        (r"U&'admin'", "no escapes"),
        (r"U&'\0061'||'dmin'", "mixed concat"),
    ]
    for expr, desc in unicode_tests:
        r = fuzzer.test(desc, f"SELECT {expr}")
        status = "✓" if r["success"] else "✗"
        val = r.get("value", r.get("error", "")[:30])
        print(f"    {status} {desc}: {val}")
        results.append((desc, r["success"], expr))

    # UESCAPE variations
    print("\n  UESCAPE variations...")
    uescape_tests = [
        (r"U&'!0061dmin' UESCAPE '!'", "custom escape char !"),
        (r"U&'#0061dmin' UESCAPE '#'", "custom escape char #"),
        (r"U&'@0061dmin' UESCAPE '@'", "custom escape char @"),
    ]
    for expr, desc in uescape_tests:
        r = fuzzer.test(desc, f"SELECT {expr}")
        status = "✓" if r["success"] else "✗"
        val = r.get("value", r.get("error", "")[:30])
        print(f"    {status} {desc}: {val}")
        results.append((desc, r["success"], expr))

    return results


def fuzz_numeric(fuzzer):
    """Test numeric representation variations."""
    print("\n" + "="*60)
    print("3. NUMERIC REPRESENTATION FUZZING")
    print("="*60)

    results = []

    # Scientific notation
    print("\n  Scientific notation...")
    sci_tests = [
        ("1e0", 1), ("1E0", 1), ("1e+0", 1), ("1e-0", 1),
        ("10e-1", 1), ("0.1e1", 1), ("0.1e+1", 1),
        (".1e1", 1), ("1.", 1), (".5", 0.5),
        ("1e1", 10), ("1E1", 10), ("1e+1", 10),
    ]
    for expr, expected in sci_tests:
        r = fuzzer.test(f"sci:{expr}", f"SELECT {expr}")
        val = r.get("value")
        status = "✓" if r["success"] and (val is None or float(val) == expected) else "✗"
        print(f"    {status} {expr} = {r.get('value', 'ERR')}")
        results.append((f"sci:{expr}", r["success"], expr))

    # Hex literals
    print("\n  Hex/Binary literals...")
    hex_tests = [
        ("x'41'", "hex string x''"),
        ("X'41'", "hex string X''"),
        ("0x41", "C-style hex"),
        ("B'0001'", "binary B''"),
        ("b'0001'", "binary b''"),
    ]
    for expr, desc in hex_tests:
        r = fuzzer.test(desc, f"SELECT {expr}")
        status = "✓" if r["success"] else "✗"
        val = r.get("value", r.get("error", "")[:30])
        print(f"    {status} {desc}: {val}")
        results.append((desc, r["success"], expr))

    # Numeric expressions that equal 1
    print("\n  Expressions equal to 1...")
    expr_tests = [
        ("1+0", "addition"), ("2-1", "subtraction"),
        ("1*1", "multiplication"), ("1/1", "division"),
        ("1%2", "modulo"), ("2>>1", "right shift"),
        ("1<<0", "left shift"), ("1&1", "bitwise and"),
        ("1|0", "bitwise or"), ("1^0", "bitwise xor"),
        ("~~1", "double negation"), ("--1", "double minus"),
        ("ABS(-1)", "abs"), ("CEIL(0.1)", "ceil"),
        ("FLOOR(1.9)", "floor"), ("ROUND(1.4)", "round"),
        ("SIGN(100)", "sign"), ("LENGTH('x')", "length"),
        ("ASCII('1')-48", "ascii math"),
    ]
    for expr, desc in expr_tests:
        r = fuzzer.test(desc, f"SELECT {expr}")
        val = r.get("value")
        status = "✓" if r["success"] and str(val) == "1" else "✗"
        print(f"    {status} {expr} = {val}")
        results.append((desc, r["success"], expr))

    # Numeric separators (PG14+)
    print("\n  Numeric separators (PG14+)...")
    sep_tests = [
        ("1_000", "underscore thousands"),
        ("1_0_0_0", "multiple underscores"),
        ("1_000.00", "with decimal"),
        ("1_000e0", "with exponent"),
    ]
    for expr, desc in sep_tests:
        r = fuzzer.test(desc, f"SELECT {expr}")
        status = "✓" if r["success"] else "✗"
        val = r.get("value", r.get("error", "")[:30])
        print(f"    {status} {desc}: {val}")
        results.append((desc, r["success"], expr))

    return results


def fuzz_operators(fuzzer):
    """Test operator and function alternatives."""
    print("\n" + "="*60)
    print("4. OPERATOR/FUNCTION ALTERNATIVES FUZZING")
    print("="*60)

    results = []

    # String concatenation
    print("\n  String concatenation...")
    concat_tests = [
        ("'a'||'b'", "pipe concat"),
        ("CONCAT('a','b')", "CONCAT function"),
        ("CONCAT_WS('','a','b')", "CONCAT_WS empty"),
        ("'a' || 'b'", "pipe with spaces"),
        ("FORMAT('%s%s','a','b')", "FORMAT function"),
        ("ARRAY_TO_STRING(ARRAY['a','b'],'')", "array to string"),
    ]
    for expr, desc in concat_tests:
        r = fuzzer.test(desc, f"SELECT {expr}")
        status = "✓" if r["success"] and r.get("value") == "ab" else "✗"
        print(f"    {status} {desc}: {r.get('value', 'ERR')}")
        results.append((desc, r["success"], expr))

    # LIKE alternatives
    print("\n  Pattern matching alternatives...")
    pattern_tests = [
        ("'admin' LIKE 'adm%'", "LIKE"),
        ("'admin' ILIKE 'ADM%'", "ILIKE case-insensitive"),
        ("'admin' SIMILAR TO 'adm%'", "SIMILAR TO"),
        ("'admin' ~ '^adm'", "regex ~"),
        ("'admin' ~* '^ADM'", "regex ~* case-insensitive"),
        ("'admin' !~ '^xyz'", "negated regex"),
        ("'admin' !~* '^XYZ'", "negated regex case-insensitive"),
        ("POSITION('adm' IN 'admin') > 0", "POSITION"),
        ("STRPOS('admin','adm') > 0", "STRPOS"),
        ("'admin' ^@ 'adm'", "starts with ^@ (PG11+)"),
    ]
    for expr, desc in pattern_tests:
        r = fuzzer.test(desc, f"SELECT {expr}")
        status = "✓" if r["success"] else "✗"
        print(f"    {status} {desc}: {r.get('value', r.get('error','')[:20])}")
        results.append((desc, r["success"], expr))

    # Comparison alternatives
    print("\n  Comparison alternatives...")
    cmp_tests = [
        ("1 = 1", "equals"),
        ("1 != 2", "not equals !="),
        ("1 <> 2", "not equals <>"),
        ("NOT 1 = 2", "NOT equals"),
        ("1 BETWEEN 0 AND 2", "BETWEEN"),
        ("1 IN (1,2,3)", "IN list"),
        ("1 = ANY(ARRAY[1,2,3])", "= ANY array"),
        ("1 = ANY('{1,2,3}'::int[])", "= ANY text array"),
        ("1 = SOME(ARRAY[1,2,3])", "= SOME"),
        ("GREATEST(1,0) = 1", "GREATEST"),
        ("LEAST(1,2) = 1", "LEAST"),
        ("NULLIF(1,2) = 1", "NULLIF"),
        ("COALESCE(1,2) = 1", "COALESCE"),
    ]
    for expr, desc in cmp_tests:
        r = fuzzer.test(desc, f"SELECT {expr}")
        status = "✓" if r["success"] else "✗"
        print(f"    {status} {desc}: {r.get('value', r.get('error','')[:20])}")
        results.append((desc, r["success"], expr))

    # OR/AND alternatives
    print("\n  Boolean operator alternatives...")
    bool_op_tests = [
        ("true OR false", "OR keyword"),
        ("true AND true", "AND keyword"),
        ("NOT false", "NOT keyword"),
        ("1=1 OR 1=2", "OR with comparisons"),
        ("(SELECT BOOL_OR(v) FROM (VALUES (true),(false)) AS t(v))", "BOOL_OR aggregate"),
        ("(SELECT BOOL_AND(v) FROM (VALUES (true),(true)) AS t(v))", "BOOL_AND aggregate"),
    ]
    for expr, desc in bool_op_tests:
        r = fuzzer.test(desc, f"SELECT {expr}")
        status = "✓" if r["success"] else "✗"
        print(f"    {status} {desc}: {r.get('value', r.get('error','')[:20])}")
        results.append((desc, r["success"], expr))

    return results


def fuzz_type_casting(fuzzer):
    """Test type casting variations."""
    print("\n" + "="*60)
    print("5. TYPE CASTING VARIATIONS FUZZING")
    print("="*60)

    results = []

    # Integer casting
    print("\n  Integer casting...")
    int_tests = [
        ("'1'::int", "::int"),
        ("'1'::integer", "::integer"),
        ("'1'::int4", "::int4"),
        ("'1'::int8", "::int8"),
        ("'1'::bigint", "::bigint"),
        ("'1'::smallint", "::smallint"),
        ("CAST('1' AS int)", "CAST AS int"),
        ("CAST('1' AS integer)", "CAST AS integer"),
        ("int4('1')", "int4() function"),
        ("int8('1')", "int8() function"),
        ("'1'::numeric::int", "chain cast"),
        ("'1'::text::int", "text to int"),
    ]
    for expr, desc in int_tests:
        r = fuzzer.test(desc, f"SELECT {expr}")
        status = "✓" if r["success"] else "✗"
        print(f"    {status} {desc}: {r.get('value', r.get('error','')[:20])}")
        results.append((desc, r["success"], expr))

    # String casting
    print("\n  String casting...")
    str_tests = [
        ("1::text", "::text"),
        ("1::varchar", "::varchar"),
        ("1::char", "::char"),
        ("CAST(1 AS text)", "CAST AS text"),
        ("TEXT(1)", "TEXT() function"),
        ("1::varchar(10)", "::varchar(n)"),
        ("1 || ''", "concat empty string"),
        ("TO_CHAR(1,'9')", "TO_CHAR"),
    ]
    for expr, desc in str_tests:
        r = fuzzer.test(desc, f"SELECT {expr}")
        status = "✓" if r["success"] else "✗"
        print(f"    {status} {desc}: {r.get('value', r.get('error','')[:20])}")
        results.append((desc, r["success"], expr))

    # Boolean casting
    print("\n  Boolean casting...")
    bool_tests = [
        ("'t'::boolean", "'t'::boolean"),
        ("'true'::boolean", "'true'::boolean"),
        ("'1'::boolean", "'1'::boolean"),
        ("'yes'::boolean", "'yes'::boolean"),
        ("'on'::boolean", "'on'::boolean"),
        ("'y'::boolean", "'y'::boolean"),
        ("1::boolean", "1::boolean"),
        ("0::boolean", "0::boolean"),
        ("CAST('true' AS boolean)", "CAST AS boolean"),
        ("bool('t')", "bool() function"),
    ]
    for expr, desc in bool_tests:
        r = fuzzer.test(desc, f"SELECT {expr}")
        status = "✓" if r["success"] else "✗"
        print(f"    {status} {desc}: {r.get('value', r.get('error','')[:20])}")
        results.append((desc, r["success"], expr))

    return results


def fuzz_null_bytes(fuzzer):
    """Test NULL byte handling."""
    print("\n" + "="*60)
    print("6. NULL BYTE HANDLING FUZZING")
    print("="*60)

    results = []

    null_tests = [
        ("E'test\\x00end'", "null in E string"),
        ("'test' || CHR(0) || 'end'", "CHR(0) concat"),
        ("CONCAT('test', CHR(0), 'end')", "CONCAT with CHR(0)"),
        ("LENGTH(E'test\\x00end')", "LENGTH with null"),
        ("POSITION(CHR(0) IN E'a\\x00b')", "POSITION of null"),
        ("REPLACE(E'a\\x00b', CHR(0), 'X')", "REPLACE null"),
        ("REGEXP_REPLACE(E'a\\x00b', CHR(0), 'X')", "REGEXP_REPLACE null"),
        ("ENCODE(E'a\\x00b'::bytea, 'hex')", "ENCODE bytea with null"),
    ]

    for expr, desc in null_tests:
        r = fuzzer.test(desc, f"SELECT {expr}")
        status = "✓" if r["success"] else "✗"
        val = repr(r.get("value", r.get("error", "")[:30]))
        print(f"    {status} {desc}: {val[:40]}")
        results.append((desc, r["success"], expr))

    return results


def fuzz_booleans(fuzzer):
    """Test boolean representation variations."""
    print("\n" + "="*60)
    print("7. BOOLEAN REPRESENTATION FUZZING")
    print("="*60)

    results = []

    # TRUE representations
    print("\n  TRUE representations...")
    true_tests = [
        "true", "TRUE", "True", "'t'::boolean", "'T'::boolean",
        "'true'::boolean", "'TRUE'::boolean", "'True'::boolean",
        "'1'::boolean", "'y'::boolean", "'Y'::boolean",
        "'yes'::boolean", "'YES'::boolean", "'Yes'::boolean",
        "'on'::boolean", "'ON'::boolean", "'On'::boolean",
        "1::boolean", "1=1", "NOT false", "NOT NOT true",
        "true AND true", "true OR false",
        "BOOL 't'", "BOOL 'true'",
    ]
    for expr in true_tests:
        r = fuzzer.test(f"true:{expr}", f"SELECT {expr}")
        is_true = r["success"] and r.get("value") in [True, 't', 'true', 1, '1']
        status = "✓" if is_true else "✗"
        print(f"    {status} {expr}: {r.get('value', r.get('error','')[:20])}")
        results.append((f"true:{expr}", r["success"], expr))

    # FALSE representations
    print("\n  FALSE representations...")
    false_tests = [
        "false", "FALSE", "False", "'f'::boolean", "'F'::boolean",
        "'false'::boolean", "'FALSE'::boolean", "'0'::boolean",
        "'n'::boolean", "'N'::boolean", "'no'::boolean",
        "'off'::boolean", "0::boolean", "1=2", "NOT true",
    ]
    for expr in false_tests:
        r = fuzzer.test(f"false:{expr}", f"SELECT {expr}")
        is_false = r["success"] and r.get("value") in [False, 'f', 'false', 0, '0']
        status = "✓" if is_false else "✗"
        print(f"    {status} {expr}: {r.get('value', r.get('error','')[:20])}")
        results.append((f"false:{expr}", r["success"], expr))

    return results


def fuzz_identifiers(fuzzer):
    """Test keyword/identifier obfuscation."""
    print("\n" + "="*60)
    print("8. KEYWORD/IDENTIFIER OBFUSCATION FUZZING")
    print("="*60)

    results = []

    # Schema-qualified function names
    print("\n  Schema-qualified functions...")
    schema_tests = [
        ("pg_catalog.upper('a')", "pg_catalog.upper"),
        ("pg_catalog.lower('A')", "pg_catalog.lower"),
        ("pg_catalog.length('test')", "pg_catalog.length"),
        ("pg_catalog.substr('test',1,2)", "pg_catalog.substr"),
        ("public.upper('a')", "public.upper (should fail)"),
        ('pg_catalog."upper"($$a$$)', "quoted function name"),
    ]
    for expr, desc in schema_tests:
        r = fuzzer.test(desc, f"SELECT {expr}")
        status = "✓" if r["success"] else "✗"
        print(f"    {status} {desc}: {r.get('value', r.get('error','')[:20])}")
        results.append((desc, r["success"], expr))

    # Quoted identifiers
    print("\n  Quoted identifiers...")
    quoted_tests = [
        ('SELECT 1 as "select"', "reserved word as alias"),
        ('SELECT 1 as "SELECT"', "uppercase reserved"),
        ('SELECT 1 as "from"', "FROM as alias"),
        ('SELECT 1 as "union"', "UNION as alias"),
        ('SELECT 1 as ""', "empty identifier"),
        ('SELECT 1 as " "', "space identifier"),
        ('SELECT 1 as "123"', "numeric identifier"),
        ('SELECT 1 as "a""b"', "quote in identifier"),
    ]
    for query, desc in quoted_tests:
        r = fuzzer.test(desc, query)
        status = "✓" if r["success"] else "✗"
        print(f"    {status} {desc}")
        results.append((desc, r["success"], query))

    # Unicode identifiers
    print("\n  Unicode identifiers...")
    unicode_id_tests = [
        ('SELECT 1 as "tëst"', "latin extended"),
        ('SELECT 1 as "テスト"', "japanese"),
        ('SELECT 1 as "тест"', "cyrillic"),
        ('SELECT 1 as U&"t\\0065st"', "unicode escape in identifier"),
    ]
    for query, desc in unicode_id_tests:
        r = fuzzer.test(desc, query)
        status = "✓" if r["success"] else "✗"
        print(f"    {status} {desc}")
        results.append((desc, r["success"], query))

    # Mixed case keywords (should all work)
    print("\n  Mixed case keywords...")
    case_tests = [
        "SeLeCt 1", "SELECT 1", "select 1", "sELECT 1",
    ]
    for query in case_tests:
        r = fuzzer.test(f"case:{query}", query)
        status = "✓" if r["success"] else "✗"
        print(f"    {status} {query}")
        results.append((f"case:{query}", r["success"], query))

    return results


def main():
    port = int(sys.argv[1]) if len(sys.argv) > 1 else 5432
    outfile = sys.argv[2] if len(sys.argv) > 2 else f"pg_comprehensive_results_{port}.txt"

    print("PostgreSQL Comprehensive WAF Evasion Fuzzer")
    print(f"Port: {port}")
    print(f"Output: {outfile}")

    try:
        fuzzer = PgFuzzer(port)
    except Exception as e:
        print(f"Error: Failed to connect to PostgreSQL: {e}", file=sys.stderr)
        sys.exit(1)

    print(f"Connected to: {fuzzer.version}")

    all_results = {
        "version": fuzzer.version,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "sections": {}
    }

    # Run all fuzzers
    all_results["sections"]["dollar_quotes"] = fuzz_dollar_quotes(fuzzer)
    all_results["sections"]["string_encoding"] = fuzz_string_encoding(fuzzer)
    all_results["sections"]["numeric"] = fuzz_numeric(fuzzer)
    all_results["sections"]["operators"] = fuzz_operators(fuzzer)
    all_results["sections"]["type_casting"] = fuzz_type_casting(fuzzer)
    all_results["sections"]["null_bytes"] = fuzz_null_bytes(fuzzer)
    all_results["sections"]["booleans"] = fuzz_booleans(fuzzer)
    all_results["sections"]["identifiers"] = fuzz_identifiers(fuzzer)

    fuzzer.close()

    # Write results with atomic write
    try:
        # Ensure output directory exists
        outdir = os.path.dirname(outfile)
        if outdir:
            os.makedirs(outdir, exist_ok=True)

        # Write to temp file first for atomic operation
        fd, tmpfile = tempfile.mkstemp(dir=outdir or '.', suffix='.tmp')
        try:
            with os.fdopen(fd, 'w', encoding='utf-8') as f:
                f.write("# PostgreSQL Comprehensive Fuzzing Results\n")
                f.write(f"Version: {all_results.get('version', 'unknown')}\n")
                f.write(f"Timestamp: {all_results.get('timestamp', 'unknown')}\n\n")

                for section, results in all_results.get("sections", {}).items():
                    f.write(f"\n## {section.upper()}\n\n")
                    successful = [r for r in results if r[1]]
                    failed = [r for r in results if not r[1]]
                    f.write(f"Successful: {len(successful)}/{len(results)}\n\n")

                    if successful:
                        f.write("### Working:\n")
                        for desc, _, expr in successful:
                            f.write(f"- {desc}: `{expr[:60]}`\n")

                    if failed:
                        f.write("\n### Failed:\n")
                        for desc, _, expr in failed:
                            f.write(f"- {desc}: `{expr[:60]}`\n")

                f.flush()
                os.fsync(f.fileno())

            # Atomic replace
            os.replace(tmpfile, outfile)
        except Exception:
            # Clean up temp file on failure
            if os.path.exists(tmpfile):
                os.unlink(tmpfile)
            raise
    except Exception as e:
        print(f"Error: Failed to write results to {outfile}: {e}\n{traceback.format_exc()}", file=sys.stderr)
        sys.exit(1)

    print(f"\n{'='*60}")
    print(f"Results written to: {outfile}")
    print(f"{'='*60}")

    # Summary
    print("\nSUMMARY:")
    for section, results in all_results["sections"].items():
        successful = len([r for r in results if r[1]])
        print(f"  {section}: {successful}/{len(results)} passed")


if __name__ == "__main__":
    main()
