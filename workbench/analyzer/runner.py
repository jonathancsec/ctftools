"""Execution helpers shared by every tool module."""

import shutil
import subprocess
import time
from dataclasses import dataclass

from .base import ToolResult, ToolSpec


class ToolUnavailable(RuntimeError):
    """Raised when a tool binary is not installed in this environment."""


class ToolTimeout(RuntimeError):
    """Raised when a tool exceeds its execution budget."""


@dataclass
class CommandResult:
    returncode: int
    output: str
    duration_ms: int


_version_cache = {}


def find_binary(name):
    return shutil.which(name) if name else None


def available(spec):
    return find_binary(spec.binary) is not None


def version(spec):
    if not spec.binary:
        return ""
    key = f"{spec.binary}:{' '.join(spec.version_args)}"
    if key in _version_cache:
        return _version_cache[key]

    executable = find_binary(spec.binary)
    if executable is None:
        _version_cache[key] = ""
        return ""

    try:
        completed = subprocess.run(
            [executable, *spec.version_args],
            capture_output=True,
            text=True,
            errors="replace",
            timeout=10,
        )
        lines = (completed.stdout or completed.stderr or "").strip().splitlines()
        value = lines[0].strip()[:120] if lines else ""
    except (OSError, subprocess.SubprocessError):
        value = ""

    _version_cache[key] = value
    return value


def truncate(text, limit):
    if text and len(text) > limit:
        return text[:limit].rstrip() + f"\n... output truncated ({len(text)} characters)"
    return text


def run(spec, args, timeout=None, cwd=None, env=None, stdin_text=None):
    executable = find_binary(spec.binary)
    if executable is None:
        raise ToolUnavailable(f"{spec.display_name} is not installed in this environment.")

    budget = timeout or spec.timeout
    started = time.perf_counter()
    try:
        completed = subprocess.run(
            [executable, *args],
            cwd=str(cwd) if cwd else None,
            capture_output=True,
            text=True,
            errors="replace",
            timeout=budget,
            env=env,
            input=stdin_text,
        )
    except subprocess.TimeoutExpired:
        raise ToolTimeout(f"{spec.display_name} exceeded its {budget}s execution limit.") from None
    except OSError as error:
        raise ToolUnavailable(f"{spec.display_name} could not be started: {error}") from None

    duration_ms = int((time.perf_counter() - started) * 1000)
    stdout = completed.stdout or ""
    stderr = completed.stderr or ""
    output = stdout.strip()
    if stderr.strip():
        output = f"{output}\n[stderr]\n{stderr.strip()}".strip()
    if not output:
        output = ""

    return CommandResult(completed.returncode, output, duration_ms)


def unavailable(spec, note=None):
    message = note or f"{spec.display_name} is not installed in this environment."
    if spec.install_hint:
        message = f"{message} Install hint: {spec.install_hint}"
    return ToolResult(status="unavailable", error=message, version="")


def from_command(spec, result, limit, summary="", artifacts=None):
    output = truncate(result.output, limit)
    if result.returncode != 0 and not output:
        return ToolResult(
            status="failed",
            error=f"{spec.display_name} exited with code {result.returncode} and produced no output.",
            duration_ms=result.duration_ms,
        )
    if result.returncode != 0:
        return ToolResult(
            status="failed",
            summary=summary,
            output=output,
            error=f"{spec.display_name} exited with code {result.returncode}.",
            duration_ms=result.duration_ms,
        )
    if not output:
        return ToolResult(
            status="empty",
            summary=summary,
            output="",
            duration_ms=result.duration_ms,
        )
    return ToolResult(
        status="completed",
        summary=summary,
        output=output,
        duration_ms=result.duration_ms,
        artifacts=artifacts or [],
    )
