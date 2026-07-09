"""psql-mcp server: exposes one read-only ``query_<env>`` tool per configured
environment over stdio."""

from __future__ import annotations

import sys

from .config import Config, Environment, load_config
from .runner import run_psql


def _make_tool(env: Environment):
    """Build the tool callable for one environment, closing over ``env``."""

    def query(sql: str, mode: str = "table") -> str:
        return run_psql(env, sql, mode)

    prod_note = (
        "PRODUCTION data — prefer a dev environment unless you specifically need "
        "prod. "
        if env.production
        else ""
    )
    query.__name__ = f"query_{env.name}"
    query.__doc__ = (
        f"Run a READ-ONLY SQL query against the {env.name} database.\n\n"
        f"{prod_note}Writes, DDL, psql meta-commands (\\!, \\copy ...), "
        f"COPY ... PROGRAM and server-side file functions are rejected; the "
        f"session is forced read-only.\n\n"
        f"Args:\n"
        f"    sql: a SELECT / read-only statement (or several, ';'-separated).\n"
        f"    mode: 'table' (default, aligned grid), 'tuples' (unaligned, "
        f"pipe-separated), or 'csv' (header + CSV)."
    )
    return query


def build_server(config: Config):
    from mcp.server.fastmcp import FastMCP

    mcp = FastMCP(config.server_name)
    for env in config.environments.values():
        tool = _make_tool(env)
        mcp.add_tool(tool, name=tool.__name__, description=tool.__doc__)
    return mcp


def main() -> None:
    try:
        config = load_config()
    except ValueError as exc:
        print(f"psql-mcp: configuration error: {exc}", file=sys.stderr)
        raise SystemExit(2)
    build_server(config).run()


if __name__ == "__main__":
    main()
