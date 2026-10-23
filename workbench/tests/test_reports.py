import json

from analyzer.file_detection import detect_file
from reports import exporter


def _job(job_id="job1"):
    return {
        "id": job_id,
        "status": "completed",
        "created_at": "2026-01-01T00:00:00+00:00",
        "started_at": "2026-01-01T00:00:01+00:00",
        "finished_at": "2026-01-01T00:00:02+00:00",
        "error": "",
    }


TOOL_RUNS = [
    {
        "tool": "hexdump",
        "display_name": "xxd",
        "status": "completed",
        "summary": "First 512 bytes",
        "output": "00000000  89 50 4e 47",
        "error": "",
        "version": "python fallback",
        "duration_ms": 3,
        "started_at": "2026-01-01T00:00:01+00:00",
        "finished_at": "2026-01-01T00:00:01+00:00",
    },
    {
        "tool": "tshark",
        "display_name": "tshark",
        "status": "skipped",
        "summary": "Not applicable",
        "output": "",
        "error": "tshark does not apply to PNG image.",
        "version": "",
        "duration_ms": 0,
        "started_at": None,
        "finished_at": None,
    },
]

ARTIFACTS = [
    {
        "id": 1,
        "name": "photo.png",
        "size": 128,
        "sha256": "a" * 64,
        "safe": 1,
        "tool": "tshark",
    }
]


def _report(tmp_path, png_bytes):
    path = tmp_path / "sample.png"
    path.write_bytes(png_bytes)
    info = detect_file(path, "sample.png")
    return exporter.build_report(_job(), info, TOOL_RUNS, ARTIFACTS)


def test_build_report_has_expected_sections(tmp_path, png_bytes):
    report = _report(tmp_path, png_bytes)

    assert report["file"]["name"] == "sample.png"
    assert report["file"]["type"] == "PNG image"
    assert report["file"]["sha256"]
    assert report["job"]["status"] == "completed"
    assert [tool["tool"] for tool in report["tools"]] == ["hexdump", "tshark"]
    assert report["artifacts"][0]["safe"] is True
    assert "not a conclusion" in report["disclaimer"]


def test_json_export_round_trips(tmp_path, png_bytes):
    report = _report(tmp_path, png_bytes)

    parsed = json.loads(exporter.to_json(report))

    assert parsed["file"]["sha256"] == report["file"]["sha256"]
    assert parsed["tools"][0]["output"].startswith("00000000")


def test_text_export_contains_overview_and_tool_output(tmp_path, png_bytes):
    report = _report(tmp_path, png_bytes)

    text = exporter.to_text(report)

    assert "FORENSIC ANALYSIS REPORT" in text
    assert report["file"]["sha256"] in text
    assert "== xxd [completed]" in text
    assert "00000000  89 50 4e 47" in text
    assert "NOTES" in text


def test_export_filename_uses_job_prefix():
    name = exporter.filename_for("abcdef123456", "json")

    assert name.startswith("forensics-abcdef12-")
    assert name.endswith(".json")
