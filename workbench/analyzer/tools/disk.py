from .. import runner
from ..base import ToolResult, ToolSpec


MMLS = ToolSpec(
    key="mmls",
    display_name="mmls",
    binary="mmls",
    version_args=("-V",),
    timeout=60,
    install_hint="apt install sleuthkit",
)

FLS = ToolSpec(
    key="fls",
    display_name="fls",
    binary="fls",
    version_args=("-V",),
    timeout=90,
    install_hint="apt install sleuthkit",
)

SPEC = ToolSpec(
    key="disk",
    display_name="Disk analysis",
    binary=None,
    timeout=90,
    install_hint="apt install sleuthkit",
)

TITLE = "Disk image"


def applies_to(file_info):
    return file_info.is_disk_image


def _section(title, tool, args, timeout):
    try:
        result = runner.run(tool, args, timeout=timeout)
    except runner.ToolTimeout as error:
        return f"== {title} ==\n{error}", True
    except runner.ToolUnavailable as error:
        return f"== {title} ==\n{error}", True

    body = result.output.strip() or "(no output)"
    return f"== {title} ==\n{body}", result.returncode != 0


def analyze(context):
    if not runner.available(MMLS) and not runner.available(FLS):
        return runner.unavailable(SPEC)

    path = context.file_info.path
    sections = []
    failures = 0

    if runner.available(MMLS):
        text, failed = _section("Partition layout", MMLS, ["-r", str(path)], 60)
        sections.append(text)
        failures += 1 if failed else 0

    if runner.available(FLS):
        text, failed = _section("File listing (recursive)", FLS, ["-r", "-p", str(path)], 90)
        sections.append(text)
        failures += 1 if failed else 0

    output = "\n\n".join(sections)
    if not output.strip():
        return ToolResult(status="empty", summary="No partitions or files listed.")

    entry_count = sum(1 for line in output.splitlines() if line.startswith("+")) or sum(
        1 for line in output.splitlines() if ":" in line
    )

    return ToolResult(
        status="failed" if failures == len(sections) else "completed",
        summary=f"{entry_count} listed entries",
        output=runner.truncate(output, context.output_limit),
        error="Some Sleuth Kit commands failed." if failures else "",
        version=runner.version(MMLS) or runner.version(FLS),
    )
