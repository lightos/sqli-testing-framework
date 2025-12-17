#!/usr/bin/env python3
"""
Shared utilities for PostgreSQL fuzzers.
"""

import os
import psycopg2


def get_pg_connection(port=None):
    """
    Create a PostgreSQL connection using environment variables.

    Environment variables:
        PGHOST: Database host (default: localhost)
        PGPORT: Database port (default: 5432, or port parameter)
        PGUSER: Database user (default: postgres)
        PGPASSWORD: Database password (required)
        PGDATABASE: Database name (default: postgres)

    Args:
        port: Optional port override (for CLI argument compatibility)

    Returns:
        psycopg2 connection with autocommit=True

    Raises:
        ValueError: If PGPASSWORD is not set
    """
    host = os.environ.get("PGHOST", "localhost")
    db_port = int(os.environ.get("PGPORT", port or 5432))
    user = os.environ.get("PGUSER", "postgres")
    password = os.environ.get("PGPASSWORD")
    database = os.environ.get("PGDATABASE", "postgres")

    if not password:
        raise ValueError(
            "PGPASSWORD environment variable is required. "
            "Set it with: export PGPASSWORD=yourpassword"
        )

    conn = psycopg2.connect(
        host=host, port=db_port, user=user,
        password=password, database=database
    )
    conn.autocommit = True
    return conn


def get_char_description(code_point):
    """
    Get human-readable description for common whitespace/control characters.

    Args:
        code_point: Unicode code point (integer)

    Returns:
        Description string or empty string if not a known character
    """
    descriptions = {
        0x09: "Horizontal Tab",
        0x0A: "Line Feed (LF)",
        0x0B: "Vertical Tab",
        0x0C: "Form Feed",
        0x0D: "Carriage Return (CR)",
        0x20: "Space",
        0x2B: "Plus (+)",
        0x2D: "Minus (-)",
        0x40: "At (@)",
        0x7E: "Tilde (~)",
        0x21: "Exclamation (!)",
        0x85: "Next Line (NEL)",
        0xA0: "Non-breaking Space",
        0x1680: "Ogham Space Mark",
        0x2000: "En Quad",
        0x2001: "Em Quad",
        0x2002: "En Space",
        0x2003: "Em Space",
        0x2004: "Three-Per-Em Space",
        0x2005: "Four-Per-Em Space",
        0x2006: "Six-Per-Em Space",
        0x2007: "Figure Space",
        0x2008: "Punctuation Space",
        0x2009: "Thin Space",
        0x200A: "Hair Space",
        0x2028: "Line Separator",
        0x2029: "Paragraph Separator",
        0x202F: "Narrow No-Break Space",
        0x205F: "Medium Mathematical Space",
        0x3000: "Ideographic Space",
    }
    return descriptions.get(code_point, "")


def url_encode_char(code_point):
    """
    URL-encode a Unicode code point.

    Args:
        code_point: Unicode code point (integer)

    Returns:
        URL-encoded string (%XX for ASCII, %uXXXX for higher)
    """
    if code_point < 0x100:
        return f"%{code_point:02X}"
    else:
        return f"%u{code_point:04X}"
