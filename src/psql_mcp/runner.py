"""Execute validated read-only SQL against a configured environment.

The SQL is fed to psql over **stdin** (so it never appears in argv / process
listings) and the child runs in its own process group so a timeout or output-cap
kill reaches ``psql`` itself, not just a wrapping ``bash``. Output from both
stdout and stderr is streamed and charged against a single byte budget, so a
runaway ``SELECT`` (or a NOTICE torrent on stderr) is killed promptly instead of
buffering unbounded into this process's memory.
"""

from __future__ import annotations

import os
import signal
import subprocess
import threading

from .config import Environment
from .hardening import wrap_readonly

_MAX_OUTPUT = 60_000  # chars; keep tool results from blowing up model context
_TIMEOUT_S = 60

# psql output-format flags per mode. -v ON_ERROR_STOP=1 makes a failing statement
# (e.g. a write rejected by the read-only guard) halt and exit non-zero instead of
# silently continuing.
_MODE_FLAGS = {
    "table": ["-q"],            # human-readable aligned grid
    "tuples": ["-qtA"],         # tuples-only, unaligned (pipe-separated)
    "csv": ["-q", "--csv"],     # CSV with header
}
_COMMON_FLAGS = ["-v", "ON_ERROR_STOP=1"]

# Query params understood by app drivers (Prisma/JDBC) but rejected by libpq with
# "invalid URI query parameter" — stripped from a DSN before it reaches psql in
# direct (url_env/dsn) mode. libpq-valid params (sslmode, connect_timeout, ...)
# are preserved. Wrapper mode does its own stripping in the shell script.
_DRIVER_ONLY_PARAMS = frozenset({
    "readonly", "schema", "connection_limit", "pool_timeout", "pgbouncer",
    "socket_timeout", "statement_cache_size", "sslaccept",
})


def strip_driver_params(dsn: str) -> str:
    """Remove Prisma/JDBC-only query params from a postgres URI so libpq accepts it.

    Only touches ``key=value&...`` after the first ``?`` and only for known
    driver-only keys; everything else (including params libpq understands) is left
    untouched. A DSN in key/value form (``host=... dbname=...``) has no ``?`` and
    is returned unchanged.
    """
    base, sep, query = dsn.partition("?")
    if not sep:
        return dsn
    kept = [
        part for part in query.split("&")
        if part and part.split("=", 1)[0].lower() not in _DRIVER_ONLY_PARAMS
    ]
    return f"{base}?{'&'.join(kept)}" if kept else base


def _kill_tree(proc: subprocess.Popen) -> None:
    """Kill the child *and* its children (the real ``psql``).

    A wrapper is a ``bash`` script that spawns ``psql`` as a child, so
    ``proc.kill()`` would only reap ``bash`` and leave ``psql`` running, still
    holding the stdout pipe open — the reader would then block past the timeout.
    The process is started in its own session (``start_new_session=True``), so its
    PID is the process-group leader; signal the whole group so ``psql`` dies and
    the pipe closes.
    """
    try:
        os.killpg(os.getpgid(proc.pid), signal.SIGKILL)
    except (ProcessLookupError, PermissionError):
        proc.kill()  # already gone, or can't signal the group — best effort


def _run_capped(cmd: list[str], stdin_payload: str) -> tuple[str, str, int | None, bool, bool]:
    """Run ``cmd`` feeding ``stdin_payload`` on stdin; stream output under a cap.

    Returns ``(stdout, stderr, returncode, truncated, timed_out)``.
    """
    proc = subprocess.Popen(
        cmd,
        stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        start_new_session=True,  # own process group, so _kill_tree reaches psql
    )

    timed_out = False

    def _kill_on_timeout() -> None:
        nonlocal timed_out
        timed_out = True
        _kill_tree(proc)

    watchdog = threading.Timer(_TIMEOUT_S, _kill_on_timeout)
    watchdog.start()

    def _feed_stdin() -> None:
        # A cap-kill or early psql exit closes the pipe mid-write; that
        # BrokenPipe/closed-file is expected, not an error.
        try:
            assert proc.stdin is not None
            proc.stdin.write(stdin_payload.encode("utf-8"))
            proc.stdin.close()
        except (BrokenPipeError, ValueError, OSError):
            pass

    in_thread = threading.Thread(target=_feed_stdin, daemon=True)
    in_thread.start()

    # Shared cap across both streams: stdout and stderr drain concurrently but
    # spend one combined _MAX_OUTPUT budget. _account returns True once exceeded.
    cap_lock = threading.Lock()
    cap_state = {"size": 0, "truncated": False}

    def _account(added: int) -> bool:
        with cap_lock:
            cap_state["size"] += added
            if cap_state["size"] > _MAX_OUTPUT:
                cap_state["truncated"] = True
                return True
            return False

    def _drain(stream, sink: list[bytes]) -> None:
        while True:
            chunk = stream.read1(65536)
            if not chunk:
                break
            sink.append(chunk)
            if _account(len(chunk)):
                _kill_tree(proc)  # stop psql instead of buffering the rest
                break

    stderr_parts: list[bytes] = []
    err_thread = threading.Thread(
        target=_drain, args=(proc.stderr, stderr_parts), daemon=True)
    err_thread.start()

    out_parts: list[bytes] = []
    try:
        assert proc.stdout is not None
        _drain(proc.stdout, out_parts)
    finally:
        # Keep the watchdog armed until the child actually exits. If it closes
        # stdout/stderr but lingers (e.g. a detached grandchild), proc.wait() would
        # otherwise block past the timeout — the timer kills the group so wait()
        # returns. Cancel only once it's reaped.
        proc.wait()
        watchdog.cancel()
        in_thread.join(timeout=1)
        err_thread.join(timeout=1)

    stdout = b"".join(out_parts).decode("utf-8", "replace")
    stderr = b"".join(stderr_parts).decode("utf-8", "replace")
    return stdout, stderr, proc.returncode, cap_state["truncated"], timed_out


def _build_cmd(env: Environment, mode: str) -> list[str]:
    """Assemble the argv for ``env``. Wrapper mode passes flags to the script
    (which forwards them to psql); direct mode invokes psql with the DSN."""
    flags = _COMMON_FLAGS + _MODE_FLAGS[mode]
    if env.wrapper is not None:
        return ["bash", str(env.wrapper), *flags]
    dsn = strip_driver_params(env.resolve_dsn())
    return ["psql", dsn, *flags]


def run_psql(env: Environment, sql: str, mode: str = "table") -> str:
    """Validate, wrap, and execute ``sql`` against ``env``; return a text result."""
    if mode not in _MODE_FLAGS:
        return f"ERROR: unknown mode {mode!r} (expected one of {', '.join(_MODE_FLAGS)})"
    if env.wrapper is not None and not env.wrapper.exists():
        return f"ERROR ({env.name}): db wrapper not found: {env.wrapper}"

    try:
        payload = wrap_readonly(sql)
    except ValueError as exc:
        return f"REJECTED ({env.name}): {exc}"

    try:
        cmd = _build_cmd(env, mode)
    except ValueError as exc:
        return f"ERROR ({env.name}): {exc}"
    except FileNotFoundError:
        return "ERROR: psql executable not found on PATH"

    try:
        stdout, stderr, returncode, truncated, timed_out = _run_capped(cmd, payload)
    except FileNotFoundError:
        # psql (direct mode) or bash (wrapper mode) missing.
        return f"ERROR ({env.name}): {cmd[0]!r} not found on PATH"

    if timed_out:
        return f"ERROR ({env.name}): query exceeded {_TIMEOUT_S}s timeout"

    # psql writes ERROR / NOTICE / WARNING to stderr and can exit 0 even on error,
    # so always surface stderr — otherwise a blocked write looks like a silent no-op.
    parts = []
    if stdout and stdout.strip():
        parts.append(stdout.rstrip())
    err = stderr.strip()
    if err:
        parts.append(err)
    # A non-zero code from our own cap-kill is expected noise; only surface real
    # psql failures.
    if returncode not in (0, None) and not truncated:
        parts.append(f"[psql exit {returncode}]")
    out = "\n".join(parts) if parts else "(no rows)"
    if truncated or len(out) > _MAX_OUTPUT:
        out = out[:_MAX_OUTPUT] + f"\n... [truncated at {_MAX_OUTPUT} chars]"
    return out
