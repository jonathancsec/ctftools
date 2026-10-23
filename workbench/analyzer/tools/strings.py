import re

from .. import runner
from ..base import ToolResult, ToolSpec


SPEC = ToolSpec(
    key="strings",
    display_name="strings",
    binary="strings",
    version_args=("--version",),
    timeout=30,
    install_hint="apt install binutils",
)

TITLE = "Printable strings"

STRING_PATTERN = re.compile(rb"[\x20-\x7e]{6,}")
INTERESTING = re.compile(r"flag|ctf|pass|secret|key|token|http|ssh|begin", re.IGNORECASE)
MAX_SCAN_BYTES = 64 * 1024 * 1024


def applies_to(file_info):
    return True


def _python_extract(context):
    data = context.file_info.path.read_bytes()[:MAX_SCAN_BYTES]
    matches = STRING_PATTERN.findall(data)

    lines = []
    for raw in matches:
        text = raw.decode("latin-1")
        if len(text) > 160:
            text = f"{text[:160]}..."
        lines.append(text)

    interesting = sum(1 for line in lines if INTERESTING.search(line))
    shown = lines[: context.max_string_lines]
    truncated = len(lines) > len(shown)

    if not lines:
        return ToolResult(
            status="empty",
            summary="No printable strings found.",
            output="The built-in extractor found no printable ASCII runs of 6 or more characters.",
        )

    header = "Extracted by the built-in Python scanner (the strings binary is not installed)."
    body = "\n".join(shown)
    if truncated:
        body += f"\n... showing {len(shown)} of {len(lines)} strings."

    return ToolResult(
        status="completed",
        summary=f"{len(lines)} strings, {interesting} look interesting",
        output=f"{header}\n\n{body}",
        version="python fallback",
    )


def analyze(context):
    if not runner.available(SPEC):
        return _python_extract(context)

    try:
        result = runner.run(
            SPEC,
            ["-n", "6", "-a", str(context.file_info.path)],
            timeout=context.timeout,
        )
    except runner.ToolTimeout as error:
        return ToolResult(status="failed", error=str(error))
    except runner.ToolUnavailable:
        return _python_extract(context)

    lines = [line for line in result.output.splitlines() if line.strip()]
    if not lines:
        return ToolResult(
            status="empty",
            summary="No printable strings found.",
            duration_ms=result.duration_ms,
        )

    interesting = sum(1 for line in lines if INTERESTING.search(line))
    shown = lines[: context.max_string_lines]
    body = "\n".join(shown)
    if len(lines) > len(shown):
        body += f"\n... showing {len(shown)} of {len(lines)} strings."

    if result.returncode != 0:
        return ToolResult(
            status="failed",
            summary=f"{len(lines)} strings, {interesting} look interesting",
            output=body,
            error=f"strings exited with code {result.returncode}.",
            duration_ms=result.duration_ms,
        )

    return ToolResult(
        status="completed",
        summary=f"{len(lines)} strings, {interesting} look interesting",
        output=runner.truncate(body, context.output_limit),
        duration_ms=result.duration_ms,
    )
