# psql-mcp

A hardened, **read-only** Postgres [MCP](https://modelcontextprotocol.io) server.
Give an LLM (Claude Code, etc.) safe query access to one or more databases —
without giving it the ability to write, run DDL, shell out, read server files, or
see your connection credentials.

Extracted and generalized from a per-repo server used in production. The security
core (`psql_mcp/hardening.py`) is unit-tested and unchanged from that origin.

## What it guarantees

Every query is validated and then wrapped so the **Postgres engine itself** — not
this Python — enforces read-only:

```sql
SET default_transaction_read_only = on;
BEGIN READ ONLY;
  <your SQL>
;
ROLLBACK;
```

On top of that, pre-flight validation rejects:

- **psql meta-commands** (`\!`, `\copy`, `\g`, `\gexec`, …) anywhere they'd be
  interpreted — including mid-line after SQL — closing the `\!` shell-escape.
- **Read-only escapes**: `RESET`, `DISCARD`, `SET SESSION AUTHORIZATION`,
  `SET ... READ WRITE`, `transaction_read_only`, `SESSION CHARACTERISTICS`, and
  transaction control (`BEGIN`/`COMMIT`/`ROLLBACK`/`SAVEPOINT`/`START TRANSACTION`).
  `CASE … END` is unaffected.
- **Filesystem / shell reach**: `COPY … PROGRAM`, non-`STDOUT` `COPY`,
  `pg_read_file` and the `pg_ls_*dir` family, `lo_import`/`lo_export`.
- **Obfuscation**: `U&'…'` unicode-escape introducers and dynamic-SQL executors
  (`dblink*`, `query_to_xml*`) that could assemble a blocked name at runtime.

Output is streamed under a 60 KB cap and a 60s timeout, killing the whole psql
process group (not just a wrapping `bash`) so a runaway `SELECT` can't exhaust
memory or hang the server. stderr is always surfaced so a blocked write never
looks like a silent no-op.

> These are defence-in-depth guardrails, not a substitute for least privilege.
> Point each environment at a **role that only has `SELECT`**; the server then
> just keeps the model from fighting that role.

## Install

Requires `psql` on `PATH`. Then either:

```bash
# one-off, no install (recommended for MCP configs)
uvx --from psql-mcp psql-mcp        # once published
uvx --from /path/to/psql-mcp psql-mcp   # from a local checkout

# or install into an environment
pip install psql-mcp
```

## Configure

A config declares named **environments**; the server exposes one `query_<name>`
tool per environment. Provide it via `PSQL_MCP_CONFIG` (a JSON file path) or
`PSQL_MCP_ENVIRONMENTS` (inline JSON). See [`templates/config.example.json`](templates/config.example.json).

```json
{
  "server_name": "my-psql",
  "environments": {
    "dev": { "wrapper": ".claude/scripts/psql-dev.sh" },
    "prd": { "wrapper": ".claude/scripts/psql-prd.sh", "production": true }
  }
}
```

Each environment picks **exactly one** credential source:

| Key | Secrecy | Where the DSN lives |
|-----|---------|---------------------|
| `wrapper` | **highest** | inside a shell script the model can't read (see below) |
| `url_env` | medium | an env var read at query time — not in the config file |
| `dsn` | lowest | inline in the config — anything that reads the config sees it |

Add `"production": true` to mark an environment; its tool's description warns the
model to prefer dev.

In `url_env` / `dsn` mode the DSN is passed straight to `psql`, so Prisma/JDBC-only
query params that libpq rejects (`?readOnly=true`, `?schema=…`, `connection_limit`,
…) are stripped automatically; libpq-valid params (`sslmode`, `connect_timeout`, …)
are preserved. In `wrapper` mode the shell script is responsible for the DSN, so
do the same stripping there if your connection string carries such params (the
[wrapper template](templates/psql-wrapper.sh) notes this).

### Credential isolation (`wrapper` mode)

The point of `wrapper` mode: the connection string never appears in the config,
this process's environment, or any tool output. The server *executes* the script
but never reads it, and you configure your harness to **deny the model from
reading it**. Copy [`templates/psql-wrapper.sh`](templates/psql-wrapper.sh),
point it at your read-only DSN (inline, or by sourcing an existing gitignored env
file), and `chmod +x` it. Contract: SQL arrives on **stdin**, psql flags arrive
as `"$@"` and must be forwarded verbatim.

## Wire into Claude Code

`.mcp.json`:

```json
{
  "mcpServers": {
    "my-psql": {
      "command": "uvx",
      "args": ["--from", "/path/to/psql-mcp", "psql-mcp"],
      "env": { "PSQL_MCP_CONFIG": "${workspaceFolder}/.claude/psql-mcp.json" }
    }
  }
}
```

`.claude/settings.json` — enable the server, allow its tools, and (for `wrapper`
mode) deny the escape routes so the isolation actually holds:

```json
{
  "enabledMcpjsonServers": ["my-psql"],
  "permissions": {
    "allow": ["mcp__my-psql__query_dev", "mcp__my-psql__query_prd"],
    "deny": [
      "Read(.claude/scripts/**)",
      "Bash(bash .claude/scripts/psql-dev.sh:*)",
      "Bash(bash .claude/scripts/psql-prd.sh:*)"
    ]
  }
}
```

Changes to `.mcp.json` take effect on the next session (or after re-approving the
server).

## Verifying a release

Every release is built by a [pinned GitHub Actions workflow](.github/workflows/publish.yml)
and published to PyPI with [Trusted Publishing](https://docs.pypi.org/trusted-publishers/) —
no long-lived API token exists to be stolen. Four independent artifacts back that claim:

| What | Where | Proves |
|------|-------|--------|
| **PEP 740 attestation** | PyPI, per file | PyPI itself verified the upload came from this repo's `publish.yml` via OIDC |
| **SLSA build provenance** | GitHub attestation store | these exact bytes were built by this workflow, at a named commit |
| **CycloneDX SBOM** | release asset + attestation | the full runtime dependency set, signed |
| **Sigstore bundle** | release asset (`.sigstore.json`) | keyless signature over each artifact |

Verify provenance and SBOM of a downloaded artifact with the GitHub CLI:

```bash
gh attestation verify psql_mcp-0.1.0-py3-none-any.whl --repo maxswjeon/psql-mcp
gh attestation verify psql_mcp-0.1.0-py3-none-any.whl --repo maxswjeon/psql-mcp \
  --predicate-type https://cyclonedx.org/bom
```

The PyPI attestation is shown per-file under the release's *"Download files"* → *Provenance*
on [pypi.org/project/psql-mcp](https://pypi.org/project/psql-mcp/), and is checked by PyPI at
upload time — a package uploaded from anywhere else would be rejected.

The release pipeline verifies its own provenance **before** publishing, and the upload to PyPI
requires a human approval on a protected environment.

## Develop

```bash
uv run --with pytest pytest        # run the hardening test suite
uv run --with mcp psql-mcp         # run the server against your config
```

## Caveat

The Bash deny stops casual direct invocation of a wrapper, but a determined caller
could spawn it from a `python -c` / `node -e` subprocess (the harness only gates
the top-level command). That path still leaks nothing: a well-written wrapper only
returns query rows and never echoes its DSN. The real guarantees are the
`Read(...)` deny on the script plus the shell-escape filter.

## License

MIT
