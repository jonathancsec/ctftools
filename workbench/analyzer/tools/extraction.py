"""Artifact extraction.

Two independent paths, both writing into the job's artifact directory:

* binwalk carves known signatures without executing extraction utilities
  (``-z``), so hostile archives never get unpacked by the shell.
* Python's zipfile unpacks entries with path, size and count limits, which
  makes appended or nested ZIP archives usable even when binwalk is absent.
"""

import stat
import zipfile
from pathlib import Path, PurePosixPath

from .. import runner
from ..base import ToolResult, ToolSpec


SPEC = ToolSpec(
    key="extraction",
    display_name="Artifact extraction",
    binary=None,
    timeout=120,
    install_hint="apt install binwalk (ZIP extraction is built in)",
)

BINWALK = ToolSpec(
    key="binwalk",
    display_name="binwalk",
    binary="binwalk",
    version_args=("-h",),
    timeout=120,
    install_hint="apt install binwalk",
)

MAX_CARVED_FILES = 20
MAX_ZIP_ENTRIES = 40
MAX_ZIP_BYTES = 20 * 1024 * 1024


def applies_to(file_info):
    return file_info.size > 0


def _files_under(directory):
    return [path for path in Path(directory).rglob("*") if path.is_file()]


def _binwalk_carve(context, lines):
    if not runner.available(BINWALK):
        lines.append("binwalk is not installed; only ZIP extraction is available.")
        return []

    output_dir = context.artifact_dir("extraction") / "binwalk"
    output_dir.mkdir(parents=True, exist_ok=True)
    args = [
        "-e", "-z",
        "-C", str(output_dir),
        "-n", str(MAX_CARVED_FILES),
        "-j", str(context.max_artifact_bytes),
        str(context.file_info.path),
    ]

    try:
        result = runner.run(BINWALK, args, timeout=max(SPEC.timeout, context.timeout))
    except runner.ToolTimeout as error:
        lines.append(f"binwalk carving timed out: {error}")
        return []
    except runner.ToolUnavailable as error:
        lines.append(f"binwalk carving was unavailable: {error}")
        return []

    lines.append("binwalk carve:")
    lines.append(result.output.strip() or "(no output)")
    return _files_under(output_dir)


def _safe_parts(name):
    """Return path parts for a ZIP entry, or None if it would escape."""
    pure = PurePosixPath(name.replace("\\", "/"))
    if pure.is_absolute():
        return None
    parts = [part for part in pure.parts if part not in {"", "."}]
    if not parts or any(part == ".." for part in parts):
        return None
    return parts


def _zip_extract(context, lines):
    try:
        is_zip = zipfile.is_zipfile(context.file_info.path)
    except OSError:
        is_zip = False
    if not is_zip:
        lines.append("No ZIP archive was found, so nothing was unpacked.")
        return []

    output_dir = context.artifact_dir("extraction") / "zip"
    output_dir.mkdir(parents=True, exist_ok=True)
    written = []
    skipped = 0
    total_bytes = 0

    try:
        with zipfile.ZipFile(context.file_info.path) as archive:
            entries = [info for info in archive.infolist() if not info.is_dir()]
            lines.append(f"ZIP archive: {len(entries)} file(s).")

            for info in entries:
                if len(written) >= MAX_ZIP_ENTRIES or total_bytes >= MAX_ZIP_BYTES:
                    skipped += 1
                    continue
                if stat.S_ISLNK(info.external_attr >> 16):
                    skipped += 1
                    continue
                if info.file_size > context.max_artifact_bytes:
                    skipped += 1
                    continue

                parts = _safe_parts(info.filename)
                if parts is None:
                    skipped += 1
                    continue

                target = output_dir.joinpath(*parts)
                try:
                    target.resolve().relative_to(output_dir.resolve())
                except ValueError:
                    skipped += 1
                    continue
                if target.exists():
                    skipped += 1
                    continue

                target.parent.mkdir(parents=True, exist_ok=True)
                try:
                    with archive.open(info) as source, open(target, "wb") as sink:
                        copied = 0
                        while True:
                            chunk = source.read(64 * 1024)
                            if not chunk:
                                break
                            copied += len(chunk)
                            total_bytes += len(chunk)
                            if (
                                copied > context.max_artifact_bytes
                                or total_bytes > MAX_ZIP_BYTES
                            ):
                                raise ValueError("entry exceeds the extraction budget")
                            sink.write(chunk)
                except (OSError, RuntimeError, ValueError, zipfile.BadZipFile) as error:
                    target.unlink(missing_ok=True)
                    skipped += 1
                    lines.append(f"Skipped {info.filename}: {error}")
                    continue

                if target.stat().st_size == 0:
                    target.unlink(missing_ok=True)
                    skipped += 1
                    continue
                written.append(target)
                lines.append(f"Extracted {info.filename} ({target.stat().st_size} bytes).")
    except (OSError, RuntimeError, zipfile.BadZipFile) as error:
        lines.append(f"ZIP extraction failed: {error}")

    if skipped:
        lines.append(f"{skipped} entry/entries were skipped (size, type or limits).")
    return written


def analyze(context):
    lines = []
    artifacts = []

    artifacts.extend(_binwalk_carve(context, lines))
    artifacts.extend(_zip_extract(context, lines))

    # Binwalk can carve oversized or duplicate files despite its limits.
    unique = []
    seen = set()
    for path in artifacts:
        try:
            path = path.resolve()
            size = path.stat().st_size
        except OSError:
            continue
        if path in seen or size <= 0 or size > context.max_artifact_bytes:
            continue
        seen.add(path)
        unique.append(path)

    output = "\n".join(lines).strip()
    if unique:
        summary = f"{len(unique)} file(s) extracted"
        status = "completed"
    else:
        summary = "No extractable artifacts found."
        status = "empty"

    return ToolResult(
        status=status,
        summary=summary,
        output=runner.truncate(output or "Nothing was extracted.", context.output_limit),
        artifacts=unique,
    )
