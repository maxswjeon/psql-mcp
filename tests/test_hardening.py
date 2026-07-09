"""Unit tests for the SQL hardening layer — the security core.

Run with: ``pytest`` (or ``uv run --with pytest pytest``).
"""

import pytest

from psql_mcp.hardening import validate_readonly, wrap_readonly


# --- statements that must be allowed ------------------------------------------

@pytest.mark.parametrize("sql", [
    "SELECT 1",
    "select id, name from users where id = 5",
    "SELECT CASE WHEN x > 0 THEN 'a' ELSE 'b' END FROM t",  # END is not blocked
    "SELECT * FROM t -- a trailing comment\n",
    "SELECT '\\n not a meta command' AS s",                 # backslash inside a string
    "SELECT $$literal with a \\ backslash$$ AS s",          # dollar-quoted
    "COPY (SELECT * FROM t) TO STDOUT",                     # pure read COPY
    "WITH c AS (SELECT 1) SELECT * FROM c",
])
def test_allows_read_queries(sql):
    assert validate_readonly(sql) == sql.strip()


# --- statements that must be rejected -----------------------------------------

@pytest.mark.parametrize("sql", [
    "",
    "   ",
    r"SELECT 1; \! cat /etc/passwd",                         # meta-command mid-line
    r"\copy t to 'x.csv'",                                   # meta-command at start
    "SELECT 1; RESET ALL",
    "DISCARD ALL",
    "BEGIN; SELECT 1",
    "COMMIT",
    "START TRANSACTION",
    "SET SESSION CHARACTERISTICS AS TRANSACTION READ WRITE",
    "SET default_transaction_read_only = off",
    "SET SESSION AUTHORIZATION postgres",
    "SELECT pg_read_file('/etc/passwd')",
    "SELECT pg_ls_logdir()",
    "COPY t FROM PROGRAM 'curl evil'",
    "COPY (SELECT 1) TO '/tmp/x.csv'",                       # non-STDOUT COPY
    "SELECT lo_export(1, '/tmp/x')",
    "SELECT dblink('', 'select 1')",
    "SELECT query_to_xml('select 1', true, true, '')",
    "SELECT U&'\\0070g' ",                                   # unicode-escape introducer
])
def test_rejects_dangerous(sql):
    with pytest.raises(ValueError):
        validate_readonly(sql)


def test_estring_terminator_not_fooled():
    # An E-string honours \' as a literal quote; the \! afterwards is still inside
    # the string and must NOT be treated as the start of a meta-command... but the
    # string is never actually closed here, so the scanner simply consumes to EOF
    # without seeing an unquoted backslash. The point: no false "meta-command"
    # rejection, and no leak.
    validate_readonly(r"SELECT E'it\'s fine' AS s")


def test_wrap_readonly_envelope():
    wrapped = wrap_readonly("SELECT 1")
    assert wrapped.startswith("SET default_transaction_read_only = on;")
    assert "BEGIN READ ONLY;" in wrapped
    assert wrapped.rstrip().endswith("ROLLBACK;")
    assert "SELECT 1" in wrapped
