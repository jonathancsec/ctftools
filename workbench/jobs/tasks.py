"""The analysis job.

This function is intentionally plain: it can run inline (development), in a
background thread, or on an RQ worker without changing any code.
"""

import json
import logging
import re
import traceback
from pathlib import Path

import database as store
from analyzer.base import AnalysisContext
from analyzer.dispatcher import TOOLS, run_analysis
from analyzer.file_detection import detect_file, hash_file
from reports.exporter import build_report


LOG = logging.getLogger(__name__)

MAX_ARTIFACTS = 50


def _settings(config=None):
    if config is None:
        from config import Config

        return {
            "DATABASE": Config.DATABASE,
            "UPLOAD_DIR": Config.UPLOAD_DIR,
            "ARTIFACT_DIR": Config.ARTIFACT_DIR,
            "TOOL_TIMEOUT": Config.TOOL_TIMEOUT,
            "TOOL_OUTPUT_LIMIT": Config.TOOL_OUTPUT_LIMIT,
            "MAX_STRING_LINES": Config.MAX_STRING_LINES,
            "MAX_ARTIFACT_BYTES": Config.MAX_ARTIFACT_BYTES,
        }

    if hasattr(config, "to_dict"):
        config = config.to_dict()
    return dict(config)


def _artifact_name(path, tool_key):
    """Give an extracted file a short, safe name for the download link."""
    cleaned = re.sub(r"[^A-Za-z0-9._-]", "_", path.name).strip("._")
    cleaned = cleaned or "artifact.bin"
    return f"{tool_key}__{cleaned}"[:160]


def _register_artifacts(db_path, settings, job_id, tool_key, candidates):
    root = Path(settings["ARTIFACT_DIR"]).resolve() / job_id
    registered = []
    budget = max(0, MAX_ARTIFACTS - len(store.list_artifacts(db_path, job_id)))

    for candidate in candidates or []:
        if budget <= 0:
            break
        path = Path(candidate)
        try:
            path = path.resolve()
            path.relative_to(root)
        except (OSError, ValueError):
            LOG.warning("Ignoring artifact outside the job directory: %s", candidate)
            continue

        try:
            if not path.is_file():
                continue
            size = path.stat().st_size
            if size <= 0 or size > settings["MAX_ARTIFACT_BYTES"]:
                continue
            name = _artifact_name(path, tool_key)
        except OSError:
            continue

        artifact = {
            "job_id": job_id,
            "tool": tool_key,
            "name": name,
            "path": str(path),
            "size": size,
            "sha256": hash_file(path, "sha256"),
            # Path and size are validated above; downloads are always forced
            # to an attachment by the view, so any extracted type is served.
            "safe": 1,
            "created_at": store.utc_now(),
        }
        store.add_artifact(db_path, artifact)
        registered.append(artifact)
        budget -= 1

    return registered


def execute_job(job_id, config=None, passphrase=None):
    settings = _settings(config)
    db_path = settings["DATABASE"]
    job = store.get_job(db_path, job_id)

    if job is None:
        LOG.warning("Job %s no longer exists", job_id)
        return

    if job["status"] in {"completed", "completed_with_errors", "failed"}:
        return

    store.update_job(db_path, job_id, status="running", started_at=store.utc_now())

    try:
        upload_path = Path(settings["UPLOAD_DIR"]) / job["stored_name"]
        if not upload_path.is_file():
            raise FileNotFoundError("The uploaded file is no longer available.")

        file_info = detect_file(upload_path, job["original_name"])
        store.update_job(
            db_path,
            job_id,
            detected_type=file_info.type_label,
            mime=file_info.mime,
            sha256=file_info.sha256,
        )

        for position, module in enumerate(TOOLS):
            store.add_tool_run(
                db_path,
                {
                    "job_id": job_id,
                    "tool": module.SPEC.key,
                    "display_name": module.SPEC.display_name,
                    "status": "queued",
                    "position": position,
                },
            )

        context = AnalysisContext(
            job_id=job_id,
            file_info=file_info,
            artifacts_root=Path(settings["ARTIFACT_DIR"]),
            timeout=settings["TOOL_TIMEOUT"],
            output_limit=settings["TOOL_OUTPUT_LIMIT"],
            max_string_lines=settings["MAX_STRING_LINES"],
            max_artifact_bytes=settings["MAX_ARTIFACT_BYTES"],
            passphrase=passphrase,
        )

        def on_start(module, position):
            store.update_tool_run(
                db_path,
                job_id,
                module.SPEC.key,
                status="running",
                started_at=store.utc_now(),
            )

        def on_finish(module, result, position):
            if passphrase:
                # A tool should never echo the secret. Only scrub lines that
                # mention a passphrase, so short secrets cannot mangle the
                # hex/string output of an unrelated line.
                for attribute in ("summary", "output", "error"):
                    value = getattr(result, attribute)
                    if value and "passphrase" in value.lower():
                        setattr(result, attribute, value.replace(passphrase, "***"))
            store.update_tool_run(
                db_path,
                job_id,
                module.SPEC.key,
                status=result.status,
                summary=result.summary,
                output=result.output,
                error=result.error,
                version=result.version,
                duration_ms=result.duration_ms,
                finished_at=store.utc_now(),
            )
            if result.artifacts:
                _register_artifacts(
                    db_path, settings, job_id, module.SPEC.key, result.artifacts
                )

        run_analysis(context, on_start=on_start, on_finish=on_finish)

        tool_runs = store.list_tool_runs(db_path, job_id)
        artifacts = store.list_artifacts(db_path, job_id)
        failed = [run for run in tool_runs if run["status"] == "failed"]

        job = store.get_job(db_path, job_id)
        finished_at = store.utc_now()
        job["status"] = "completed_with_errors" if failed else "completed"
        job["finished_at"] = finished_at
        report = build_report(job, file_info, tool_runs, artifacts)

        store.update_job(
            db_path,
            job_id,
            status=job["status"],
            finished_at=finished_at,
            report_json=json.dumps(report),
        )

    except Exception as error:
        LOG.error("Job %s failed: %s", job_id, error, exc_info=True)
        for tool in store.list_tool_runs(db_path, job_id):
            if tool["status"] in {"queued", "running"}:
                store.update_tool_run(
                    db_path,
                    job_id,
                    tool["tool"],
                    status="failed",
                    error=f"Job aborted: {error}",
                    finished_at=store.utc_now(),
                )
        store.update_job(
            db_path,
            job_id,
            status="failed",
            error=f"{error}\n{traceback.format_exc(limit=3)}"[:2000],
            finished_at=store.utc_now(),
        )
