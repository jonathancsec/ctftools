from pathlib import Path

from .. import runner
from ..base import ToolResult, ToolSpec


SPEC = ToolSpec(
    key="tshark",
    display_name="tshark",
    binary="tshark",
    version_args=("-v",),
    timeout=90,
    install_hint="apt install tshark",
)

TITLE = "Network analysis"
MAX_HTTP_ROWS = 100


def applies_to(file_info):
    return file_info.is_pcap


def _run_section(context, title, args, timeout):
    try:
        result = runner.run(SPEC, args, timeout=timeout)
    except runner.ToolTimeout as error:
        return f"== {title} ==\n{error}", True
    except runner.ToolUnavailable as error:
        return f"== {title} ==\n{error}", True

    body = result.output.strip() or "(no output)"
    failed = result.returncode != 0
    return f"== {title} ==\n{body}", failed


def analyze(context):
    if not runner.available(SPEC):
        return runner.unavailable(SPEC)

    path = context.file_info.path
    sections = []
    failures = 0
    budget = max(SPEC.timeout, context.timeout)

    for title, args in [
        ("Protocol hierarchy", ["-r", str(path), "-q", "-z", "io,phs"]),
        ("TCP conversations", ["-r", str(path), "-q", "-z", "conv,tcp"]),
        (
            "HTTP requests",
            [
                "-r", str(path),
                "-Y", "http.request",
                "-T", "fields",
                "-e", "frame.number",
                "-e", "http.host",
                "-e", "http.request.uri",
                "-c", str(MAX_HTTP_ROWS),
            ],
        ),
    ]:
        text, failed = _run_section(context, title, args, budget)
        sections.append(text)
        failures += 1 if failed else 0

    artifacts = []
    export_dir = context.artifact_dir("network") / "http"
    export_dir.mkdir(parents=True, exist_ok=True)
    export_text, export_failed = _run_section(
        context,
        "Exported HTTP objects",
        ["-r", str(path), "-q", "--export-objects", f"http,{export_dir}"],
        30,
    )
    sections.append(export_text)
    failures += 1 if export_failed else 0

    if export_dir.exists():
        artifacts = [item for item in Path(export_dir).rglob("*") if item.is_file()]

    output = "\n\n".join(sections)
    http_count = output.count("http")
    summary_parts = [f"{len(artifacts)} HTTP object(s) exported"]
    if http_count:
        summary_parts.append("HTTP traffic present")

    status = "completed"
    if failures == 4:
        status = "failed"
    elif not output.strip():
        status = "empty"

    return ToolResult(
        status=status,
        summary=", ".join(summary_parts),
        output=runner.truncate(output, context.output_limit),
        error=f"{failures} tshark command(s) failed." if failures else "",
        artifacts=artifacts,
        duration_ms=0,
    )
