#!/usr/bin/env bash
# psql-mcp wrapper template (credential-isolated mode).
#
# The MCP server executes this script but never reads its contents, and your
# harness should DENY the model from reading it directly (e.g. Claude Code:
#   "permissions": { "deny": ["Read(.claude/scripts/**)"] }
# ). That keeps the connection string invisible to the model while queries run.
#
# Contract expected by psql-mcp (wrapper mode):
#   * SQL arrives on STDIN.
#   * psql output/format flags arrive as "$@" and must be forwarded verbatim
#     (the server passes -v ON_ERROR_STOP=1 and the -q/-tA/--csv mode flags).
#
# Pick ONE way to supply the read-only connection string below, then delete the
# others. Prefer a role that only has SELECT privileges as defence in depth on
# top of the server's read-only enforcement.
set -euo pipefail

# --- Option A: source an existing gitignored env file (no duplication) ---------
# Uncomment and point at the file that already holds your read-only DSN.
#   set -a; . "$(dirname "$0")/../../.env.development.local"; set +a
#   DSN="$READONLY_URL"

# --- Option B: inline the DSN here (this file must stay gitignored) -------------
#   DSN="postgresql://readonly_user:PASSWORD@host:5432/dbname"

# --- Option C: read from this script's own environment -------------------------
#   DSN="${READONLY_URL:?READONLY_URL not set}"

: "${DSN:?edit this wrapper and set DSN (see options above)}"

exec psql "$DSN" "$@"
