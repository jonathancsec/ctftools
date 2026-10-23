"""Select and run the appropriate tools for a file."""

import time

from . import runner
from .base import ToolResult
from .tools import (
    binwalk,
    disk,
    extraction,
    filetype,
    hexdump,
    metadata,
    network,
    steganography,
    strings,
)


TOOLS = [
    filetype,
    metadata,
    strings,
    hexdump,
    binwalk,
    extraction,
    steganography,
    network,
    disk,
]


def _skipped(module, file_info):
    return ToolResult(
        status="skipped",
        summary="Not applicable",
        error=(
            f"{module.SPEC.display_name} does not apply to {file_info.type_label}."
        ),
    )


def run_analysis(context, on_start=None, on_finish=None):
    """Run every tool, reporting progress through optional callbacks.

    A failure in one tool never prevents the rest from running.
    """
    outcomes = []

    for position, module in enumerate(TOOLS):
        if on_start:
            on_start(module, position)

        if not module.applies_to(context.file_info):
            result = _skipped(module, context.file_info)
            if on_finish:
                on_finish(module, result, position)
            outcomes.append((module, result))
            continue

        started = time.perf_counter()
        try:
            result = module.analyze(context)
        except Exception as error:  # defensive: tools should handle their own errors
            result = ToolResult(
                status="failed",
                error=f"{module.SPEC.display_name} crashed: {error}",
            )
        result.duration_ms = result.duration_ms or int((time.perf_counter() - started) * 1000)

        if not result.version:
            result.version = runner.version(module.SPEC)

        if on_finish:
            on_finish(module, result, position)
        outcomes.append((module, result))

    return outcomes
