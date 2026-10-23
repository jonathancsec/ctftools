from .. import runner
from ..base import ToolResult, ToolSpec


SPEC = ToolSpec(
    key="file",
    display_name="file",
    binary="file",
    version_args=("--version",),
    timeout=15,
    install_hint="apt install file",
)

TITLE = "File type"


def applies_to(file_info):
    return True


def analyze(context):
    if not runner.available(SPEC):
        return runner.unavailable(SPEC)

    try:
        result = runner.run(SPEC, ["-b", str(context.file_info.path)])
    except runner.ToolTimeout as error:
        return ToolResult(status="failed", error=str(error))
    except runner.ToolUnavailable as error:
        return ToolResult(status="unavailable", error=str(error))

    output = runner.truncate(result.output, context.output_limit)
    if not output:
        return ToolResult(status="empty", summary="file(1) returned no description.", duration_ms=result.duration_ms)

    return ToolResult(
        status="completed",
        summary=output.splitlines()[0][:160],
        output=output,
        duration_ms=result.duration_ms,
    )
