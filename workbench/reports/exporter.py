"""Build downloadable reports from stored job data."""

import json
from datetime import datetime, timezone
from pathlib import Path

from database import utc_now


DISCLAIMER = (
    "Tool output is evidence, not a conclusion. A detected signature does not prove "
    "that data is extractable, and no result here proves that a file is malicious. "
    "Treat every finding as a lead to verify."
)


def _tool_entry(row):
    return {
        "tool": row.get("tool"),
        "name": row.get("display_name"),
        "status": row.get("status"),
        "summary": row.get("summary") or "",
        "output": row.get("output") or "",
        "error": row.get("error") or "",
        "version": row.get("version") or "",
        "duration_ms": row.get("duration_ms") or 0,
        "started_at": row.get("started_at"),
        "finished_at": row.get("finished_at"),
    }


def build_report(job, file_info, tool_runs, artifacts):
    """Assemble the canonical report dictionary stored with the job."""
    return {
        "format_version": 1,
        "generated_at": utc_now(),
        "disclaimer": DISCLAIMER,
        "job": {
            "id": job["id"],
            "status": job["status"],
            "created_at": job["created_at"],
            "started_at": job["started_at"],
            "finished_at": job["finished_at"],
            "error": job.get("error") or "",
        },
        "file": {
            "name": file_info.original_name,
            "stored_name": Path(file_info.path).name,
            "size": file_info.size,
            "size_human": file_info.display_size,
            "sha256": file_info.sha256,
            "md5": file_info.md5,
            "extension": file_info.extension,
            "type": file_info.type_label,
            "mime": file_info.mime,
            "image_format": file_info.image_format,
            "image_size": list(file_info.image_size) if file_info.image_size else None,
            "image_mode": file_info.image_mode,
        },
        "tools": [_tool_entry(row) for row in tool_runs],
        "artifacts": [
            {
                "id": artifact["id"],
                "name": artifact["name"],
                "size": artifact["size"],
                "sha256": artifact["sha256"],
                "safe": bool(artifact["safe"]),
                "tool": artifact.get("tool"),
            }
            for artifact in artifacts
        ],
    }


def to_json(report):
    return json.dumps(report, indent=2, sort_keys=False)


def to_text(report):
    file_info = report["file"]
    job = report["job"]

    lines = [
        "FORENSIC ANALYSIS REPORT",
        "=" * 60,
        f"Job ID:        {job['id']}",
        f"Status:        {job['status']}",
        f"Created:       {job['created_at']}",
        f"Started:       {job['started_at'] or '-'}",
        f"Finished:      {job['finished_at'] or '-'}",
        f"Generated:     {report['generated_at']}",
        "",
        "FILE OVERVIEW",
        "-" * 60,
        f"Name:          {file_info['name']}",
        f"Size:          {file_info['size_human']} ({file_info['size']} bytes)",
        f"Detected type: {file_info['type']} ({file_info['mime']})",
        f"Extension:     {file_info['extension'] or '(none)'}",
        f"SHA-256:       {file_info['sha256']}",
        f"MD5:           {file_info['md5']}",
    ]
    if file_info.get("image_format"):
        dimensions = file_info.get("image_size") or [None, None]
        lines.append(
            f"Image:         {file_info['image_format']} {dimensions[0]}x{dimensions[1]} {file_info.get('image_mode') or ''}".rstrip()
        )

    lines.extend(["", "TOOLS", "-" * 60])
    for tool in report["tools"]:
        lines.append(
            f"\n== {tool['name']} [{tool['status']}] "
            f"{tool['duration_ms']} ms"
            + (f" - {tool['version']}" if tool["version"] else "")
        )
        if tool["summary"]:
            lines.append(f"Summary: {tool['summary']}")
        if tool["error"]:
            lines.append(f"Error: {tool['error']}")
        if tool["output"]:
            lines.append(tool["output"])

    lines.extend(["", "ARTIFACTS", "-" * 60])
    if report["artifacts"]:
        for artifact in report["artifacts"]:
            download = "downloadable" if artifact["safe"] else "not downloadable"
            lines.append(
                f"- {artifact['name']} ({artifact['size']} bytes, {download}) sha256 {artifact['sha256']}"
            )
    else:
        lines.append("No artifacts were produced.")

    lines.extend(["", "NOTES", "-" * 60, report["disclaimer"]])
    if job.get("error"):
        lines.extend(["", f"Job error: {job['error']}"])

    return "\n".join(lines).rstrip() + "\n"


def filename_for(job_id, extension):
    stamp = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")
    return f"forensics-{job_id[:8]}-{stamp}.{extension}"
