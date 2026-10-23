"""Forensic Workbench web application."""

import hashlib
import json
import re
import shutil
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path

import click
from flask import (
    Flask,
    Response,
    abort,
    current_app,
    flash,
    jsonify,
    redirect,
    render_template,
    request,
    send_file,
    url_for,
)

import database as store
from analyzer.base import human_size
from analyzer.file_detection import detect_from_bytes
from config import Config
from jobs.queue import enqueue_job
from reports import exporter


PROJECT_NAME = "Forensic Workbench"
TERMINAL_STATUSES = {"completed", "completed_with_errors", "failed"}
SAFE_SUFFIX = re.compile(r"^\.[a-z0-9]{1,8}$")
CHUNK_SIZE = 1024 * 1024


def create_app(config_object=Config, **overrides):
    app = Flask(__name__)
    app.config.from_object(config_object)
    app.config.update(overrides)

    if app.config.get("TRUST_PROXY"):
        from werkzeug.middleware.proxy_fix import ProxyFix

        app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1)

    for directory in (app.config["UPLOAD_DIR"], app.config["ARTIFACT_DIR"]):
        Path(directory).mkdir(parents=True, exist_ok=True)
    store.init_db(app.config["DATABASE"])

    app.add_url_rule("/", "index", index, methods=["GET"])
    app.add_url_rule("/healthz", "healthz", healthz, methods=["GET"])
    app.add_url_rule("/robots.txt", "robots", robots, methods=["GET"])
    app.add_url_rule("/upload", "upload", upload, methods=["POST"])
    app.add_url_rule("/jobs/<job_id>", "job_detail", job_detail, methods=["GET"])
    app.add_url_rule("/api/jobs/<job_id>", "job_status", job_status, methods=["GET"])
    app.add_url_rule("/jobs/<job_id>/report", "report", report, methods=["GET"])
    app.add_url_rule("/jobs/<job_id>/report.json", "report_json", report_json, methods=["GET"])
    app.add_url_rule("/jobs/<job_id>/report.txt", "report_txt", report_txt, methods=["GET"])
    app.add_url_rule(
        "/jobs/<job_id>/artifacts/<int:artifact_id>",
        "artifact_download",
        artifact_download,
        methods=["GET"],
    )

    app.jinja_env.filters["human_size"] = human_size
    app.jinja_env.trim_blocks = True

    @app.after_request
    def security_headers(response):
        if not request.path.startswith("/static/"):
            response.headers.setdefault("Cache-Control", "no-store")
            response.headers.setdefault("X-Content-Type-Options", "nosniff")
            response.headers.setdefault("X-Frame-Options", "DENY")
            response.headers.setdefault("Referrer-Policy", "no-referrer")
            response.headers.setdefault(
                "Content-Security-Policy",
                "default-src 'self'; img-src 'self' data:; style-src 'self'; "
                "script-src 'self'; form-action 'self'; frame-ancestors 'none'; "
                "base-uri 'none'",
            )
        return response

    @app.context_processor
    def inject_globals():
        return {
            "project_name": PROJECT_NAME,
            "max_upload": human_size(app.config["MAX_CONTENT_LENGTH"]),
            "retention_hours": app.config["RETENTION_HOURS"],
        }

    @app.errorhandler(404)
    def not_found(error):
        return render_template("error.html", code=404, message="That page or job does not exist."), 404

    @app.errorhandler(413)
    def too_large(error):
        return (
            render_template(
                "error.html",
                code=413,
                message=f"That upload is larger than the {human_size(app.config['MAX_CONTENT_LENGTH'])} limit.",
            ),
            413,
        )

    @app.cli.command("preflight")
    def preflight():
        """Check the settings and toolchain before exposing the service."""
        import shutil

        from analyzer.dispatcher import TOOLS

        results = []

        secret = app.config.get("SECRET_KEY") or ""
        weak = {"dev-only-change-this-secret", "change-me-before-deploying"}
        if secret in weak or len(secret) < 16:
            results.append(("FAIL", "SECRET_KEY", "set a random value of 16+ characters"))
        else:
            results.append(("PASS", "SECRET_KEY", "configured"))

        for label, directory in (
            ("uploads", app.config["UPLOAD_DIR"]),
            ("artifacts", app.config["ARTIFACT_DIR"]),
        ):
            try:
                Path(directory).mkdir(parents=True, exist_ok=True)
                probe = Path(directory) / ".preflight"
                probe.write_text("ok", encoding="utf-8")
                probe.unlink()
            except OSError as error:
                results.append(("FAIL", label, f"not writable: {error}"))
            else:
                results.append(("PASS", label, f"writable at {directory}"))

        try:
            store.init_db(app.config["DATABASE"])
            store.recent_jobs(app.config["DATABASE"], limit=1)
        except Exception as error:
            results.append(("FAIL", "database", str(error)))
        else:
            results.append(("PASS", "database", str(app.config["DATABASE"])))

        missing = [
            module.SPEC.display_name
            for module in TOOLS
            if module.SPEC.binary and not shutil.which(module.SPEC.binary)
        ]
        if missing:
            results.append(("WARN", "tools", "missing: " + ", ".join(missing)))
        else:
            results.append(("PASS", "tools", "all binaries on PATH"))

        if (app.config.get("QUEUE_MODE") or "inline").lower() == "rq":
            try:
                from redis import Redis

                Redis.from_url(app.config["REDIS_URL"]).ping()
            except Exception as error:
                results.append(("FAIL", "redis", f"unreachable: {error}"))
            else:
                results.append(("PASS", "redis", "reachable"))
        else:
            results.append(
                ("WARN", "queue", f"QUEUE_MODE={app.config.get('QUEUE_MODE')}; use rq in production")
            )

        for status, name, detail in results:
            click.echo(f"{status:4}  {name:10}  {detail}")

        if any(status == "FAIL" for status, _name, _detail in results):
            raise click.ClickException("Preflight found blocking problems.")

    @app.cli.command("cleanup")
    def cleanup():
        """Delete jobs older than RETENTION_HOURS (files, artifacts and rows)."""
        cutoff = (
            datetime.now(timezone.utc) - timedelta(hours=app.config["RETENTION_HOURS"])
        ).isoformat(timespec="seconds")
        removed = 0
        for job in store.jobs_before(app.config["DATABASE"], cutoff):
            shutil.rmtree(
                Path(app.config["ARTIFACT_DIR"]) / job["id"], ignore_errors=True
            )
            (Path(app.config["UPLOAD_DIR"]) / job["stored_name"]).unlink(missing_ok=True)
            store.delete_job(app.config["DATABASE"], job["id"])
            removed += 1
        store.purge_upload_events(app.config["DATABASE"], cutoff)

        stale_cutoff = (
            datetime.now(timezone.utc)
            - timedelta(hours=app.config["JOB_STALE_HOURS"])
        ).isoformat(timespec="seconds")
        stale = store.fail_stale_jobs(
            app.config["DATABASE"],
            stale_cutoff,
            "Analysis was abandoned by its worker (timeout or restart).",
        )

        click.echo(f"Removed {removed} expired job(s), reaped {stale} stale job(s).")

    return app


def index():
    jobs = store.recent_jobs(current_app.config["DATABASE"], limit=6)
    return render_template("index.html", jobs=jobs)


def healthz():
    try:
        store.recent_jobs(current_app.config["DATABASE"], limit=1)
    except Exception:
        current_app.logger.exception("Health check failed")
        return jsonify({"status": "error"}), 503
    return jsonify({"status": "ok"})


def robots():
    return Response(
        "User-agent: *\nDisallow: /jobs/\nDisallow: /upload\nDisallow: /api/\n",
        mimetype="text/plain",
    )


def upload():
    upload_file = request.files.get("file")
    if upload_file is None or not upload_file.filename:
        flash("Choose a file to analyze.", "error")
        return redirect(url_for("index"), code=303)

    passphrase = request.form.get("passphrase") or ""
    if len(passphrase) > 256:
        flash("The steghide passphrase must be 256 characters or fewer.", "error")
        return redirect(url_for("index"), code=303)
    passphrase = passphrase or None

    db_path = current_app.config["DATABASE"]
    if store.count_active_jobs(db_path) >= current_app.config["MAX_PENDING_JOBS"]:
        flash(
            "The analysis queue is full right now. Try again in a few minutes.",
            "error",
        )
        return redirect(url_for("index"), code=303)

    client_ip = request.remote_addr or "unknown"
    cutoff = (datetime.now(timezone.utc) - timedelta(hours=1)).isoformat(timespec="seconds")
    if store.count_uploads_since(db_path, client_ip, cutoff) >= current_app.config["UPLOAD_LIMIT_PER_HOUR"]:
        flash(
            "Too many uploads from this address. Try again in an hour.",
            "error",
        )
        return redirect(url_for("index"), code=303)
    store.record_upload(db_path, client_ip, store.utc_now())

    original_name = upload_file.filename
    job_id = uuid.uuid4().hex
    suffix = Path(original_name).suffix.lower()
    if not SAFE_SUFFIX.match(suffix):
        suffix = ""

    stored_name = f"{job_id}{suffix}"
    destination = Path(current_app.config["UPLOAD_DIR"]) / stored_name
    limit = current_app.config["MAX_CONTENT_LENGTH"]

    digest = hashlib.sha256()
    size = 0
    try:
        with open(destination, "wb") as handle:
            while True:
                chunk = upload_file.stream.read(CHUNK_SIZE)
                if not chunk:
                    break
                size += len(chunk)
                if size > limit:
                    raise ValueError("too large")
                digest.update(chunk)
                handle.write(chunk)
        if size == 0:
            raise ValueError("empty")
    except ValueError:
        destination.unlink(missing_ok=True)
        message = (
            "That file is empty."
            if size == 0
            else f"That upload is larger than the {human_size(limit)} limit."
        )
        flash(message, "error")
        return redirect(url_for("index"), code=303)
    except OSError:
        destination.unlink(missing_ok=True)
        flash("The upload could not be saved. Try again.", "error")
        return redirect(url_for("index"), code=303)

    with open(destination, "rb") as handle:
        head = handle.read(4096)
    detected_type, mime, _kind = detect_from_bytes(head, original_name)

    store.create_job(
        current_app.config["DATABASE"],
        {
            "id": job_id,
            "original_name": original_name,
            "stored_name": stored_name,
            "size": size,
            "sha256": digest.hexdigest(),
            "detected_type": detected_type,
            "mime": mime,
            "status": "queued",
            "created_at": store.utc_now(),
        },
    )

    try:
        enqueue_job(current_app._get_current_object(), job_id, passphrase=passphrase)
    except Exception:
        current_app.logger.exception("Could not enqueue job %s", job_id)
        store.update_job(
            db_path,
            job_id,
            status="failed",
            error="The analysis queue was unavailable, so the job never started.",
            finished_at=store.utc_now(),
        )
        flash("The analysis queue is unavailable. Try again in a moment.", "error")
        return redirect(url_for("job_detail", job_id=job_id), code=303)

    return redirect(url_for("job_detail", job_id=job_id), code=303)


def _get_job(job_id):
    job = store.get_job(current_app.config["DATABASE"], job_id)
    if job is None:
        abort(404)
    return job


def job_detail(job_id):
    job = _get_job(job_id)
    runs = store.list_tool_runs(current_app.config["DATABASE"], job_id)
    return render_template(
        "job.html",
        job=job,
        runs=runs,
        terminal=job["status"] in TERMINAL_STATUSES,
    )


def job_status(job_id):
    job = _get_job(job_id)
    runs = store.list_tool_runs(current_app.config["DATABASE"], job_id)
    counts = {}
    for run in runs:
        counts[run["status"]] = counts.get(run["status"], 0) + 1

    finished = job["status"] in TERMINAL_STATUSES
    return jsonify(
        {
            "id": job["id"],
            "status": job["status"],
            "finished": finished,
            "error": job.get("error") or "",
            "started_at": job.get("started_at"),
            "finished_at": job.get("finished_at"),
            "report_url": url_for("report", job_id=job_id) if finished else None,
            "counts": counts,
            "tools": [
                {
                    "tool": run["tool"],
                    "name": run["display_name"],
                    "status": run["status"],
                    "summary": run["summary"] or "",
                    "duration_ms": run["duration_ms"] or 0,
                }
                for run in runs
            ],
        }
    )


def _load_report(job):
    if not job.get("report_json"):
        abort(409)
    return json.loads(job["report_json"])


def report(job_id):
    job = _get_job(job_id)
    if job["status"] not in TERMINAL_STATUSES or not job.get("report_json"):
        return redirect(url_for("job_detail", job_id=job_id))

    run = _load_report(job)
    artifacts = store.list_artifacts(current_app.config["DATABASE"], job_id)
    return render_template("report.html", job=job, report=run, artifacts=artifacts)


def report_json(job_id):
    job = _get_job(job_id)
    data = exporter.to_json(_load_report(job))
    return Response(
        data,
        mimetype="application/json",
        headers={
            "Content-Disposition": (
                f"attachment; filename={exporter.filename_for(job_id, 'json')}"
            )
        },
    )


def report_txt(job_id):
    job = _get_job(job_id)
    data = exporter.to_text(_load_report(job))
    return Response(
        data,
        mimetype="text/plain",
        headers={
            "Content-Disposition": (
                f"attachment; filename={exporter.filename_for(job_id, 'txt')}"
            )
        },
    )


def artifact_download(job_id, artifact_id):
    job = _get_job(job_id)
    artifact = store.get_artifact(
        current_app.config["DATABASE"], job["id"], artifact_id
    )
    if artifact is None or not artifact["safe"]:
        abort(404)

    root = Path(current_app.config["ARTIFACT_DIR"]).resolve()
    path = Path(artifact["path"]).resolve()
    try:
        path.relative_to(root)
    except ValueError:
        abort(404)

    if not path.is_file():
        abort(404)

    # Extracted files are untrusted samples. Always send them as an opaque
    # attachment so the browser never renders or executes them inline.
    response = send_file(
        path,
        mimetype="application/octet-stream",
        as_attachment=True,
        download_name=artifact["name"],
        conditional=False,
    )
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["Cache-Control"] = "no-store"
    return response


if __name__ == "__main__":
    create_app().run(host="127.0.0.1", port=5000, debug=True)
