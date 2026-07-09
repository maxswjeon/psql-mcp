"""SQL hardening: reject anything that could write, escape the read-only guard,
touch the filesystem, or shell out to exfiltrate credentials.

This module is the security core of psql-mcp and is deliberately kept free of any
I/O or configuration so it can be unit-tested in isolation. The runtime wraps the
(validated) user SQL in ``READONLY_PRELUDE`` / ``READONLY_SUFFIX`` before handing
it to psql.

Two layers force the Postgres engine — not this Python — to be the authority on
"no writes":

  1. a session ``default_transaction_read_only = on`` default (catches anything
     that escapes the managed transaction), and
  2. an explicit ``BEGIN READ ONLY`` wrapping the user's statements — read-only is
     a property of the transaction itself, which ``RESET`` / ``DISCARD`` cannot
     clear (those only reset GUCs).

Pre-flight validation additionally rejects the statements that could lift either
guard, plus the psql/Postgres features that could read the credential-bearing
wrapper or otherwise reach the filesystem / a shell.
"""

from __future__ import annotations

import re

# Wrap user statements so the engine enforces read-only two independent ways.
READONLY_PRELUDE = (
    "SET default_transaction_read_only = on;\n"
    "BEGIN READ ONLY;\n"
)
# Trailing `;` guarantees the user's last statement is terminated before ROLLBACK
# even when they omit it. ROLLBACK is belt-and-suspenders; the session ends anyway.
READONLY_SUFFIX = "\n;\nROLLBACK;\n"

# Patterns that could exfiltrate credentials, touch the filesystem, or undo the
# read-only guard. Matched case-insensitively against the user SQL only (never
# against our own prelude/suffix).
_FORBIDDEN = [
    (re.compile(r"\bPROGRAM\b", re.I), "COPY ... PROGRAM (shell execution) is not allowed"),
    (re.compile(r"\blo_(import|export)\b", re.I), "large-object file I/O is not allowed"),
    # Covers pg_read_file/pg_read_binary_file/pg_stat_file/pg_ls_dir, the obsolete
    # pg_logdir_ls, and the whole modern pg_ls_*dir family (pg_ls_logdir/waldir/
    # tmpdir/archive_statusdir/replslotdir, ...) via `ls_\w*dir`.
    (re.compile(r"\bpg_(read_file|read_binary_file|stat_file|logdir_ls|ls_\w*dir)\b", re.I),
     "server-side file access functions are not allowed"),
    # Unicode-escaped string/identifier introducers (U&'...' / U&"...") let an
    # attacker spell a blocked name so the literal never appears for the regexes
    # above to match — e.g. U&"pg\005Fls\005Flogdir" decodes to pg_ls_logdir only
    # inside the server, and _reject_meta_commands deliberately skips double-quoted
    # identifiers. Reject the U& introducer outright; legit reads never need it.
    (re.compile(r"(?<![A-Za-z0-9_])[uU]&\s*[\"']"),
     "Unicode-escaped literals/identifiers (U&'...' / U&\"...\") are not allowed"),
    # Dynamic-SQL executors run a text argument as SQL under the wrapper role, so a
    # forbidden name assembled from pieces — e.g. query_to_xml('select pg_ls_' ||
    # 'logdir()', ...) or dblink(..., 'select pg_read_file(...)') — never appears as
    # a literal for the guards above to match yet still executes. Block them.
    (re.compile(r"\b(query_to_xml\w*|dblink\w*)\b", re.I),
     "dynamic-SQL execution functions (query_to_xml*/dblink*) are not allowed"),
    (re.compile(r"\bREAD\s+WRITE\b", re.I), "re-enabling read-write is not allowed"),
    (re.compile(r"\b(default_)?transaction_read_only\b", re.I),
     "changing the read-only guard is not allowed"),
    (re.compile(r"\bSESSION\s+CHARACTERISTICS\b", re.I),
     "changing session characteristics is not allowed"),
    # Reset/discard would clear the session read-only GUC; transaction control would
    # let a statement escape the managed BEGIN READ ONLY into a writable autocommit
    # context. Block both (the wrapper's own BEGIN/ROLLBACK live in the prelude/
    # suffix and are never scanned).
    (re.compile(r"\bRESET\b", re.I), "RESET of session state is not allowed"),
    (re.compile(r"\bDISCARD\b", re.I), "DISCARD is not allowed"),
    (re.compile(r"\bSET\s+SESSION\s+AUTHORIZATION\b", re.I),
     "SET SESSION AUTHORIZATION is not allowed"),
    # NB: not `END` — it collides with CASE ... END in legitimate read queries. An
    # END that commits the wrapper transaction is harmless: the session GUC keeps
    # autocommit read-only, and every way to clear that GUC is blocked above.
    (re.compile(r"\b(COMMIT|ROLLBACK|ABORT|SAVEPOINT)\b", re.I),
     "transaction-control statements are not allowed"),
    (re.compile(r"\bBEGIN\b", re.I),
     "BEGIN is not allowed (statements run in a managed read-only transaction)"),
    (re.compile(r"\bSTART\s+TRANSACTION\b", re.I), "START TRANSACTION is not allowed"),
]


def _reject_meta_commands(sql: str) -> None:
    """Reject psql backslash meta-commands appearing anywhere outside a quoted
    literal/identifier or comment.

    psql treats an unquoted backslash as the start of a client-side meta-command
    even mid-line *after* SQL on the same line — e.g.
    ``SELECT 1; \\! cat secret`` — which would reopen the shell-escape exfil path
    this server exists to close. A line-start-only check misses that, so scan the
    whole string, skipping single-quoted strings, double-quoted identifiers,
    dollar-quoted strings, and SQL comments (where a backslash is literal, not a
    meta-command), and reject a backslash found anywhere else. With the Postgres
    default ``standard_conforming_strings=on`` a backslash is literal inside a
    regular ``'...'`` string (only ``''`` escapes), but an escape-string
    ``E'...'`` treats ``\\`` as an escape (so ``\\'`` is a literal quote, not the
    terminator); we detect the ``E``/``e`` prefix at a token boundary and honour
    backslash escapes there so a ``\\'`` can't smuggle the rest of a line out of
    the string and hide a trailing meta-command.
    """
    i, n = 0, len(sql)
    while i < n:
        c = sql[i]
        if c == "'" or c == '"':  # quoted string / identifier; "" or '' escapes
            # An E-string (E'...' at a token boundary) honours backslash escapes,
            # so \' is a literal quote — track that or the real terminator is
            # mis-placed and a following \! leaks out as a meta-command.
            estring = False
            if c == "'" and i > 0 and sql[i - 1] in "Ee":
                before = sql[i - 2] if i >= 2 else ""
                if not (before and (before.isalnum() or before in "_$")):
                    estring = True
            i += 1
            while i < n:
                ch = sql[i]
                if estring and ch == "\\":  # backslash escapes the next char
                    i += 2
                    continue
                if ch == c:
                    if i + 1 < n and sql[i + 1] == c:
                        i += 2
                        continue
                    i += 1
                    break
                i += 1
            continue
        if c == "$":  # possible dollar-quoted string: $tag$ ... $tag$
            # A dollar-quote delimiter only opens a string at a token boundary. If
            # the `$` directly follows an identifier char (letter/digit/_/$),
            # Postgres treats it as part of that identifier — NOT a dollar quote —
            # so skipping here would hide a following `\` meta-command (e.g.
            # `foo$tag$ \! cat secret $tag$`). Only treat it as an opener when not
            # preceded by an identifier character.
            prev = sql[i - 1] if i > 0 else ""
            if not (prev and (prev.isalnum() or prev in "_$")):
                m = re.match(r"\$([A-Za-z_]\w*)?\$", sql[i:])
                if m:
                    tag = m.group(0)
                    end = sql.find(tag, i + len(tag))
                    i = n if end == -1 else end + len(tag)
                    continue
            i += 1
            continue
        if c == "-" and i + 1 < n and sql[i + 1] == "-":  # line comment
            # psql's lexer ends a line comment at \n OR \r (newline [\n\r]); only
            # stopping at \n would let `-- x\r\! ...` hide a meta-command after a
            # bare carriage return.
            nl = sql.find("\n", i)
            cr = sql.find("\r", i)
            ends = [x for x in (nl, cr) if x != -1]
            i = n if not ends else min(ends) + 1
            continue
        if c == "/" and i + 1 < n and sql[i + 1] == "*":  # block comment (nests)
            depth, i = 1, i + 2
            while i < n and depth:
                if sql[i] == "/" and i + 1 < n and sql[i + 1] == "*":
                    depth, i = depth + 1, i + 2
                elif sql[i] == "*" and i + 1 < n and sql[i + 1] == "/":
                    depth, i = depth - 1, i + 2
                else:
                    i += 1
            continue
        if c == "\\":
            raise ValueError(
                "psql meta-commands are not allowed "
                f"(unquoted '\\' at offset {i})"
            )
        i += 1


def validate_readonly(sql: str) -> str:
    """Return cleaned SQL, or raise ``ValueError`` describing the rejection."""
    if not sql or not sql.strip():
        raise ValueError("empty SQL")
    # Reject psql backslash meta-commands (\!, \copy, \o, \g, \gexec, ...) — the
    # client-side shell/exfil path — anywhere they would be interpreted, not just
    # at line start. See _reject_meta_commands for why mid-line matters.
    _reject_meta_commands(sql)
    for pat, msg in _FORBIDDEN:
        if pat.search(sql):
            raise ValueError(msg)
    # COPY is allowed only as `COPY (...) TO STDOUT` (pure read). Anything else
    # (file path target/source, FROM ingest) is rejected.
    for m in re.finditer(r"\bCOPY\b", sql, re.I):
        tail = sql[m.start():m.start() + 400].upper()
        if "TO STDOUT" not in tail:
            raise ValueError("COPY is only allowed as `COPY (...) TO STDOUT`")
    return sql.strip()


def wrap_readonly(sql: str) -> str:
    """Validate ``sql`` and return the full read-only-wrapped payload for psql."""
    return READONLY_PRELUDE + validate_readonly(sql) + READONLY_SUFFIX
