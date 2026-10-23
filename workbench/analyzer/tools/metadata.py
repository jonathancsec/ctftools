from .. import runner
from ..base import ToolResult, ToolSpec


SPEC = ToolSpec(
    key="exiftool",
    display_name="ExifTool",
    binary="exiftool",
    version_args=("-ver",),
    timeout=30,
    install_hint="apt install libimage-exiftool-perl",
)

TITLE = "Metadata"


def applies_to(file_info):
    return True


def analyze(context):
    if not runner.available(SPEC):
        return runner.unavailable(SPEC)

    try:
        result = runner.run(SPEC, ["-G1", "-s", "-a", str(context.file_info.path)])
    except runner.ToolTimeout as error:
        return ToolResult(status="failed", error=str(error))
    except runner.ToolUnavailable as error:
        return ToolResult(status="unavailable", error=str(error))

    output = runner.truncate(result.output, context.output_limit)
    if not output:
        return ToolResult(
            status="empty",
            summary="No metadata tags were reported.",
            duration_ms=result.duration_ms,
        )

    line_count = len(output.splitlines())
    return ToolResult(
        status="completed" if result.returncode == 0 else "failed",
        summary=f"{line_count} metadata lines",
        output=output,
        error="" if result.returncode == 0 else f"ExifTool exited with code {result.returncode}.",
        duration_ms=result.duration_ms,
    )
