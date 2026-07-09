"""Configuration loading for psql-mcp.

A config declares one or more named *environments* (e.g. ``dev``, ``prd``). Each
environment names exactly one credential source, in decreasing order of secrecy:

  * ``wrapper``  — path to a shell script that holds/loads the connection details
                   and runs ``psql "$DSN" "$@"`` with SQL on stdin. This is the
                   credential-isolated mode: the DSN never appears in the config,
                   the MCP process, or any tool output, so a model that can read
                   the config still cannot read the credentials (pair with a
                   harness rule that denies reading the script).
  * ``url_env``  — name of an environment variable holding the DSN, read at query
                   time. The DSN is not in the config file, but is visible to any
                   process that can read the MCP's environment.
  * ``dsn``      — inline connection string. Simplest, least secure: anything that
                   can read the config sees the credentials. Use only for local
                   throwaway databases.

Config is provided one of two ways (checked in order):

  1. ``PSQL_MCP_CONFIG``       — path to a JSON file (see templates/config.example.json)
  2. ``PSQL_MCP_ENVIRONMENTS`` — the same JSON object, inline

JSON shape::

    {
      "server_name": "my-psql",              // optional, defaults to "psql-mcp"
      "environments": {
        "dev": { "wrapper": ".claude/scripts/psql-dev.sh" },
        "prd": { "wrapper": ".claude/scripts/psql-prd.sh", "production": true }
      }
    }

Relative ``wrapper`` paths resolve against the config file's directory (or, for
inline config, the current working directory).
"""

from __future__ import annotations

import json
import os
from dataclasses import dataclass
from pathlib import Path

DEFAULT_SERVER_NAME = "psql-mcp"


@dataclass(frozen=True)
class Environment:
    """One queryable database target."""

    name: str
    production: bool = False
    wrapper: Path | None = None
    url_env: str | None = None
    dsn: str | None = None

    def resolve_dsn(self) -> str | None:
        """Return the connection string for direct (non-wrapper) modes, or None
        when this environment runs through a wrapper script."""
        if self.dsn is not None:
            return self.dsn
        if self.url_env is not None:
            val = os.environ.get(self.url_env)
            if not val:
                raise ValueError(
                    f"environment {self.name!r}: env var {self.url_env!r} "
                    f"(url_env) is not set"
                )
            return val
        return None


@dataclass(frozen=True)
class Config:
    server_name: str
    environments: dict[str, Environment]


def _build_environment(name: str, spec: dict, base_dir: Path) -> Environment:
    if not isinstance(spec, dict):
        raise ValueError(f"environment {name!r}: expected an object, got {type(spec).__name__}")

    sources = [k for k in ("wrapper", "url_env", "dsn") if spec.get(k)]
    if len(sources) == 0:
        raise ValueError(
            f"environment {name!r}: must set exactly one of 'wrapper', 'url_env', "
            f"or 'dsn'"
        )
    if len(sources) > 1:
        raise ValueError(
            f"environment {name!r}: set only one credential source, got {sources}"
        )

    wrapper = None
    if spec.get("wrapper"):
        wrapper = Path(spec["wrapper"])
        if not wrapper.is_absolute():
            wrapper = (base_dir / wrapper).resolve()

    return Environment(
        name=name,
        production=bool(spec.get("production", False)),
        wrapper=wrapper,
        url_env=spec.get("url_env"),
        dsn=spec.get("dsn"),
    )


def _parse(raw: dict, base_dir: Path) -> Config:
    if not isinstance(raw, dict):
        raise ValueError("config root must be a JSON object")
    envs_spec = raw.get("environments")
    if not isinstance(envs_spec, dict) or not envs_spec:
        raise ValueError("config must define a non-empty 'environments' object")

    environments = {
        name: _build_environment(name, spec, base_dir)
        for name, spec in envs_spec.items()
    }
    # Tool names are derived as query_<name>; keep them to a safe identifier shape
    # so the generated tool names are valid.
    for name in environments:
        if not name.isidentifier():
            raise ValueError(
                f"environment name {name!r} must be a valid identifier "
                f"(letters, digits, underscore; not starting with a digit)"
            )

    server_name = raw.get("server_name") or DEFAULT_SERVER_NAME
    return Config(server_name=server_name, environments=environments)


def load_config() -> Config:
    """Load config from ``PSQL_MCP_CONFIG`` (file) or ``PSQL_MCP_ENVIRONMENTS``
    (inline JSON). Raises ``ValueError`` with actionable guidance if neither is
    set or the content is invalid."""
    path = os.environ.get("PSQL_MCP_CONFIG")
    if path:
        cfg_path = Path(path).expanduser().resolve()
        if not cfg_path.is_file():
            raise ValueError(f"PSQL_MCP_CONFIG points to a missing file: {cfg_path}")
        try:
            raw = json.loads(cfg_path.read_text(encoding="utf-8"))
        except json.JSONDecodeError as exc:
            raise ValueError(f"PSQL_MCP_CONFIG is not valid JSON: {exc}") from exc
        return _parse(raw, base_dir=cfg_path.parent)

    inline = os.environ.get("PSQL_MCP_ENVIRONMENTS")
    if inline:
        try:
            raw = json.loads(inline)
        except json.JSONDecodeError as exc:
            raise ValueError(f"PSQL_MCP_ENVIRONMENTS is not valid JSON: {exc}") from exc
        return _parse(raw, base_dir=Path.cwd())

    raise ValueError(
        "no configuration found: set PSQL_MCP_CONFIG to a JSON file path, or "
        "PSQL_MCP_ENVIRONMENTS to an inline JSON object "
        "(see templates/config.example.json)"
    )
