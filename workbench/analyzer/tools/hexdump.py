from .. import runner
from ..base import ToolResult, ToolSpec


SPEC = ToolSpec(
    key="hexdump",
    display_name="xxd",
    binary="xxd",
    version_args=("-v",),
    timeout=15,
    install_hint="apt install xxd (vim-common)",
)

TITLE = "Hexadecimal preview"
PREVIEW_BYTES = 512


def applies_to(file_info):
    return True


def _python_hexdump(path, length=PREVIEW_BYTES):
    data = path.read_bytes()[:length]
    lines = []
    for offset in range(0, len(data), 16):
        block = data[offset:offset + 16]
        hex_part = " ".join(f"{byte:02x}" for byte in block)
        text_part = "".join(chr(byte) if 32 <= byte < 127 else "." for byte in block)
        lines.append(f"{offset:08x}  {hex_part:<47}  {text_part}")
    return "\n".join(lines)


def analyze(context):
    path = context.file_info.path

    if not runner.available(SPEC):
        output = _python_hexdump(path)
        if not output:
            return ToolResult(status="empty", summary="The file is empty.")
        return ToolResult(
            status="completed",
            summary=f"First {min(PREVIEW_BYTES, context.file_info.size)} bytes (built-in hexdump)",
            output=output,
            version="python fallback",
        )

    try:
        result = runner.run(SPEC, ["-l", str(PREVIEW_BYTES), str(path)])
    except runner.ToolTimeout as error:
        return ToolResult(status="failed", error=str(error))
    except runner.ToolUnavailable:
        output = _python_hexdump(path)
        return ToolResult(status="completed", summary="Built-in hexdump", output=output, version="python fallback")

    output = runner.truncate(result.output, context.output_limit)
    if not output:
        return ToolResult(status="empty", summary="The file is empty.", duration_ms=result.duration_ms)

    return ToolResult(
        status="completed",
        summary=f"First {min(PREVIEW_BYTES, context.file_info.size)} bytes",
        output=output,
        duration_ms=result.duration_ms,
    )
