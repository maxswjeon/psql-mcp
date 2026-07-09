"""psql-mcp — a hardened, read-only Postgres MCP server.

Public surface: :func:`psql_mcp.server.main` (console entrypoint) and the
:mod:`psql_mcp.hardening` primitives for reuse/testing.
"""

from .hardening import validate_readonly, wrap_readonly

__all__ = ["validate_readonly", "wrap_readonly", "__version__"]
__version__ = "0.1.0"
