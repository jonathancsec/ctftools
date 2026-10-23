import io
import zipfile
from pathlib import Path

import pytest

from analyzer import runner
from analyzer.base import AnalysisContext, ToolSpec
from analyzer.file_detection import detect_file
from analyzer.tools import binwalk, extraction, hexdump, metadata, steganography, strings


@pytest.fixture()
def context(tmp_path, png_bytes):
    path = tmp_path / "sample.png"
    path.write_bytes(png_bytes)
    info = detect_file(path, "sample.png")
    return AnalysisContext(
        job_id="test-job",
        file_info=info,
        artifacts_root=tmp_path / "artifacts",
        timeout=30,
        output_limit=100_000,
        max_string_lines=50,
    )


def test_missing_binary_is_reported_as_unavailable():
    spec = ToolSpec(key="missing", display_name="NoSuchTool", binary="definitely-not-a-real-binary-xyz")

    assert runner.available(spec) is False
    assert runner.version(spec) == ""

    result = runner.unavailable(spec)
    assert result.status == "unavailable"
    assert "NoSuchTool" in result.error


def test_truncate_marks_shortened_output():
    text = "x" * 50

    assert runner.truncate(text, 100) == text
    assert "truncated" in runner.truncate(text, 10)


def test_strings_finds_embedded_text(context):
    result = strings.analyze(context)

    assert result.status == "completed"
    assert "flag{fixture_png}" in result.output
    assert result.duration_ms >= 0


def test_hexdump_starts_at_offset_zero(context):
    result = hexdump.analyze(context)

    assert result.status == "completed"
    assert result.output.startswith("00000000")
    assert "PNG" in result.output or "89 50 4e 47" in result.output


def test_binwalk_finds_png_signature(context):
    result = binwalk.analyze(context)

    assert result.status in {"completed", "empty", "failed"}
    if result.status == "completed":
        assert "PNG" in result.output or "0x00000000" in result.output


def test_steganography_reports_image_properties(context):
    result = steganography.analyze(context)

    assert result.status in {"completed", "failed"}
    assert "24 x 24" in result.output
    assert "Least-significant-bit" in result.output


def test_metadata_tool_degrades_gracefully(context):
    result = metadata.analyze(context)

    assert result.status in {"completed", "empty", "unavailable"}
    if result.status == "unavailable":
        assert "ExifTool" in result.error


def _extraction_context(tmp_path, path, name):
    return AnalysisContext(
        job_id="extract-job",
        file_info=detect_file(path, name),
        artifacts_root=tmp_path / "artifacts",
        timeout=30,
        output_limit=100_000,
        max_string_lines=50,
    )


def test_extraction_unpacks_zip_entries(tmp_path, zip_bytes):
    path = tmp_path / "archive.zip"
    path.write_bytes(zip_bytes)

    result = extraction.analyze(_extraction_context(tmp_path, path, "archive.zip"))

    assert result.status == "completed"
    assert any(Path(artifact).name == "flag.txt" for artifact in result.artifacts)
    target = tmp_path / "artifacts" / "extract-job" / "extraction" / "zip" / "flag.txt"
    assert target.read_text() == "flag{fixture_zip}"


def test_extraction_blocks_path_traversal(tmp_path):
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w") as archive:
        archive.writestr("../escaped.txt", "nope")
        archive.writestr("safe.txt", "yes")

    path = tmp_path / "archive.zip"
    path.write_bytes(buffer.getvalue())
    result = extraction.analyze(_extraction_context(tmp_path, path, "archive.zip"))

    assert not (tmp_path / "escaped.txt").exists()
    assert (tmp_path / "artifacts" / "extract-job" / "extraction" / "zip" / "safe.txt").read_text() == "yes"
    assert any(Path(artifact).name == "safe.txt" for artifact in result.artifacts)
