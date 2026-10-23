from .. import file_detection, runner
from ..base import ToolResult, ToolSpec


SPEC = ToolSpec(
    key="binwalk",
    display_name="binwalk",
    binary="binwalk",
    version_args=("-h",),
    timeout=90,
    install_hint="pip install binwalk (or apt install binwalk)",
)

TITLE = "Embedded signatures"


def applies_to(file_info):
    return True


def _signature_scan(context):
    hits, truncated = file_detection.scan_signatures(context.file_info.path)
    if not hits:
        return ToolResult(
            status="empty",
            summary="No embedded signatures found.",
            output=(
                "The built-in scanner found no known file signatures.\n"
                "This is a heuristic: encrypted, compressed or unknown formats will not appear here."
            ),
            version="python fallback",
        )

    lines = [f"0x{offset:08x}  {label}" for offset, label in hits[:100]]
    if len(hits) > 100:
        lines.append(f"... and {len(hits) - 100} more.")
    if truncated:
        lines.append("Scan was limited to the first 64 MB of the file.")

    header = "Built-in signature scan (binwalk is not installed)."
    return ToolResult(
        status="completed",
        summary=f"{len(hits)} embedded signature(s) (built-in scan)",
        output=f"{header}\n\n" + "\n".join(lines),
        version="python fallback",
    )


def analyze(context):
    if not runner.available(SPEC):
        return _signature_scan(context)

    try:
        result = runner.run(SPEC, [str(context.file_info.path)], timeout=SPEC.timeout)
    except runner.ToolTimeout as error:
        return ToolResult(status="failed", error=str(error))
    except runner.ToolUnavailable:
        return _signature_scan(context)

    output = runner.truncate(result.output, context.output_limit)
    if not output:
        return ToolResult(
            status="empty",
            summary="binwalk reported no structures.",
            duration_ms=result.duration_ms,
        )

    return ToolResult(
        status="completed" if result.returncode == 0 else "failed",
        summary="binwalk scan complete",
        output=output,
        error="" if result.returncode == 0 else f"binwalk exited with code {result.returncode}.",
        duration_ms=result.duration_ms,
    )
