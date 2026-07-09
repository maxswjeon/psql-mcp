"""Tests for driver-only query-param stripping (Prisma/JDBC URLs → libpq)."""

import pytest

from psql_mcp.runner import strip_driver_params


@pytest.mark.parametrize("dsn, expected", [
    # no query string — unchanged
    ("postgresql://ro:pw@h:5432/db", "postgresql://ro:pw@h:5432/db"),
    # driver-only param on a URL with no port
    ("postgresql://ro:pw@h/db?readOnly=true", "postgresql://ro:pw@h/db"),
    # keep libpq-valid params regardless of order
    ("postgresql://ro:pw@h/db?readOnly=true&sslmode=require",
     "postgresql://ro:pw@h/db?sslmode=require"),
    ("postgresql://ro:pw@h/db?sslmode=require&readOnly=true",
     "postgresql://ro:pw@h/db?sslmode=require"),
    # multiple driver params interleaved with a kept one
    ("postgresql://ro:pw@h/db?schema=public&sslmode=require&connection_limit=5",
     "postgresql://ro:pw@h/db?sslmode=require"),
    # only driver params → drop the '?' entirely
    ("postgresql://ro:pw@h/db?schema=public", "postgresql://ro:pw@h/db"),
    # nothing to strip
    ("postgresql://ro:pw@h/db?sslmode=require&connect_timeout=10",
     "postgresql://ro:pw@h/db?sslmode=require&connect_timeout=10"),
    # key/value DSN form (no URI query) — unchanged
    ("host=h dbname=db user=ro", "host=h dbname=db user=ro"),
    # case-insensitive key match
    ("postgresql://ro:pw@h/db?ReadOnly=true", "postgresql://ro:pw@h/db"),
])
def test_strip_driver_params(dsn, expected):
    assert strip_driver_params(dsn) == expected
