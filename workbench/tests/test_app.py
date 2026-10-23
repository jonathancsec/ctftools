import io
import json
from pathlib import Path

import database as store
from app import TERMINAL_STATUSES, create_app


def _create_job(app, job_id, status="completed", created_at=None):
    db = app.config["DATABASE"]
    store.create_job(
        db,
        {
            "id": job_id,
            "original_name": "evidence.png",
            "stored_name": f"{job_id}.png",
            "size": 10,
            "sha256": "0" * 64,
            "detected_type": "PNG image",
            "mime": "image/png",
            "status": status,
            "created_at": created_at or store.utc_now(),
        },
    )


def test_index_renders_upload_form(client):
    response = client.get("/")

    assert response.status_code == 200
    assert b"upload-form" in response.data
    assert b"Analyze file" in response.data


def test_upload_runs_analysis_and_serves_report(app, client, png_bytes):
    response = client.post(
        "/upload",
        data={"file": (io.BytesIO(png_bytes), "evidence.png")},
        content_type="multipart/form-data",
        follow_redirects=False,
    )

    assert response.status_code == 303
    location = response.headers["Location"]
    job_id = location.rsplit("/", 1)[-1]

    job = store.get_job(app.config["DATABASE"], job_id)
    assert job is not None
    assert job["status"] in TERMINAL_STATUSES
    assert job["original_name"] == "evidence.png"
    assert job["detected_type"] == "PNG image"
    assert job["report_json"]

    assert client.get(location).status_code == 200

    api = client.get(f"/api/jobs/{job_id}").get_json()
    assert api["finished"] is True
    assert api["report_url"].endswith(f"/jobs/{job_id}/report")
    assert api["counts"].get("completed", 0) > 0

    report = client.get(f"/jobs/{job_id}/report")
    assert report.status_code == 200
    assert b"Findings vs conclusions" in report.data
    assert b"SHA-256" in report.data

    json_report = client.get(f"/jobs/{job_id}/report.json")
    assert json_report.status_code == 200
    assert json_report.headers["Content-Disposition"].startswith("attachment;")
    assert json.loads(json_report.data)["job"]["finished_at"]

    text_report = client.get(f"/jobs/{job_id}/report.txt")
    assert text_report.status_code == 200
    assert text_report.mimetype == "text/plain"
    assert b"FORENSIC ANALYSIS REPORT" in text_report.data
    assert b"Finished:" in text_report.data


def test_tool_failure_produces_completed_with_errors(app, client, png_bytes, monkeypatch):
    from analyzer.tools import strings

    def explode(context):
        raise RuntimeError("simulated tool crash")

    monkeypatch.setattr(strings, "analyze", explode)

    response = client.post(
        "/upload",
        data={"file": (io.BytesIO(png_bytes), "broken.png")},
        content_type="multipart/form-data",
        follow_redirects=False,
    )
    job_id = response.headers["Location"].rsplit("/", 1)[-1]

    job = store.get_job(app.config["DATABASE"], job_id)
    assert job["status"] == "completed_with_errors"

    runs = store.list_tool_runs(app.config["DATABASE"], job_id)
    strings_run = next(run for run in runs if run["tool"] == "strings")
    assert strings_run["status"] == "failed"
    assert "simulated tool crash" in strings_run["error"]

    api = client.get(f"/api/jobs/{job_id}").get_json()
    assert api["finished"] is True
    assert api["counts"]["failed"] == 1

    report = client.get(f"/jobs/{job_id}/report")
    assert report.status_code == 200
    assert b"completed_with_errors" in report.data


def test_upload_passes_passphrase_without_storing_it(app, client, png_bytes, monkeypatch):
    import app as app_module

    captured = {}

    def fake_enqueue(application, job_id, passphrase=None):
        captured["passphrase"] = passphrase

    monkeypatch.setattr(app_module, "enqueue_job", fake_enqueue)

    response = client.post(
        "/upload",
        data={
            "file": (io.BytesIO(png_bytes), "secret.png"),
            "passphrase": "hunter2",
        },
        content_type="multipart/form-data",
        follow_redirects=False,
    )

    assert response.status_code == 303
    assert captured["passphrase"] == "hunter2"

    job = store.get_job(
        app.config["DATABASE"], response.headers["Location"].rsplit("/", 1)[-1]
    )
    assert job["status"] == "queued"
    assert "hunter2" not in str(job)


def test_upload_rejects_overlong_passphrase(app, client, png_bytes):
    response = client.post(
        "/upload",
        data={
            "file": (io.BytesIO(png_bytes), "secret.png"),
            "passphrase": "x" * 300,
        },
        content_type="multipart/form-data",
        follow_redirects=True,
    )

    assert response.status_code == 200
    assert b"256" in response.data
    assert store.recent_jobs(app.config["DATABASE"]) == []


def test_upload_rate_limit_per_address(tmp_path, png_bytes):
    app = create_app(
        DATA_DIR=tmp_path,
        UPLOAD_DIR=tmp_path / "uploads",
        ARTIFACT_DIR=tmp_path / "artifacts",
        DATABASE=tmp_path / "throttle.db",
        QUEUE_MODE="sync",
        TESTING=True,
        UPLOAD_LIMIT_PER_HOUR=1,
    )
    client = app.test_client()

    first = client.post(
        "/upload",
        data={"file": (io.BytesIO(png_bytes), "one.png")},
        content_type="multipart/form-data",
    )
    second = client.post(
        "/upload",
        data={"file": (io.BytesIO(png_bytes), "two.png")},
        content_type="multipart/form-data",
        follow_redirects=True,
    )

    assert first.status_code == 303
    assert b"Too many uploads" in second.data
    assert len(store.recent_jobs(app.config["DATABASE"])) == 1


def test_full_queue_rejects_upload(tmp_path, png_bytes):
    app = create_app(
        DATA_DIR=tmp_path,
        UPLOAD_DIR=tmp_path / "uploads",
        ARTIFACT_DIR=tmp_path / "artifacts",
        DATABASE=tmp_path / "queue.db",
        QUEUE_MODE="sync",
        TESTING=True,
        MAX_PENDING_JOBS=0,
    )
    client = app.test_client()

    response = client.post(
        "/upload",
        data={"file": (io.BytesIO(png_bytes), "busy.png")},
        content_type="multipart/form-data",
        follow_redirects=True,
    )

    assert b"queue is full" in response.data
    assert store.recent_jobs(app.config["DATABASE"]) == []


def test_empty_upload_is_rejected(app, client):
    response = client.post(
        "/upload",
        data={"file": (io.BytesIO(b""), "empty.bin")},
        content_type="multipart/form-data",
        follow_redirects=True,
    )

    assert response.status_code == 200
    assert b"empty" in response.data.lower()
    assert store.recent_jobs(app.config["DATABASE"]) == []


def test_upload_without_file_redirects(app, client):
    response = client.post("/upload", data={}, follow_redirects=True)

    assert response.status_code == 200
    assert b"Choose a file" in response.data


def test_oversized_upload_returns_413(tmp_path):
    app = create_app(
        DATA_DIR=tmp_path,
        UPLOAD_DIR=tmp_path / "uploads",
        ARTIFACT_DIR=tmp_path / "artifacts",
        DATABASE=tmp_path / "oversize.db",
        QUEUE_MODE="sync",
        TESTING=True,
        MAX_CONTENT_LENGTH=500,
    )
    client = app.test_client()

    response = client.post(
        "/upload",
        data={"file": (io.BytesIO(b"x" * 5000), "big.bin")},
        content_type="multipart/form-data",
    )

    assert response.status_code == 413
    assert b"larger" in response.data


def test_unknown_job_returns_404(client):
    assert client.get("/jobs/does-not-exist").status_code == 404
    assert client.get("/api/jobs/does-not-exist").status_code == 404


def test_report_redirects_while_job_is_running(app, client):
    _create_job(app, "running-job", status="running")

    response = client.get("/jobs/running-job/report")

    assert response.status_code == 302
    assert "/jobs/running-job" in response.headers["Location"]


def test_artifact_download_only_for_safe_artifacts(app, client, png_bytes):
    job_id = "artifact-job"
    _create_job(app, job_id)

    artifact_dir = Path(app.config["ARTIFACT_DIR"]) / job_id / "network"
    artifact_dir.mkdir(parents=True)
    artifact_path = artifact_dir / "object.png"
    artifact_path.write_bytes(png_bytes)

    common = {
        "job_id": job_id,
        "tool": "network",
        "path": str(artifact_path),
        "size": len(png_bytes),
        "sha256": "a" * 64,
        "created_at": store.utc_now(),
    }
    safe_id = store.add_artifact(app.config["DATABASE"], {**common, "name": "object.png", "safe": 1})
    unsafe_id = store.add_artifact(
        app.config["DATABASE"], {**common, "name": "payload.bin", "safe": 0}
    )

    download = client.get(f"/jobs/{job_id}/artifacts/{safe_id}")
    assert download.status_code == 200
    assert download.mimetype == "application/octet-stream"
    assert "attachment" in download.headers["Content-Disposition"]
    assert download.headers["X-Content-Type-Options"] == "nosniff"
    assert client.get(f"/jobs/{job_id}/artifacts/{unsafe_id}").status_code == 404


def test_healthz(client):
    response = client.get("/healthz")

    assert response.status_code == 200
    assert response.get_json() == {"status": "ok"}


def test_security_headers_and_robots(client):
    response = client.get("/")

    assert response.headers["Cache-Control"] == "no-store"
    assert response.headers["X-Frame-Options"] == "DENY"
    assert "default-src 'self'" in response.headers["Content-Security-Policy"]

    robots = client.get("/robots.txt")
    assert robots.status_code == 200
    assert b"Disallow: /jobs/" in robots.data


def test_preflight_passes_with_strong_secret(tmp_path):
    app = create_app(
        DATA_DIR=tmp_path,
        UPLOAD_DIR=tmp_path / "uploads",
        ARTIFACT_DIR=tmp_path / "artifacts",
        DATABASE=tmp_path / "preflight.db",
        SECRET_KEY="a" * 32,
        QUEUE_MODE="inline",
        TESTING=True,
    )

    result = app.test_cli_runner().invoke(args=["preflight"])

    assert result.exit_code == 0
    assert "PASS" in result.output


def test_preflight_rejects_weak_secret(app):
    result = app.test_cli_runner().invoke(args=["preflight"])

    assert result.exit_code != 0
    assert "FAIL" in result.output


def test_cleanup_reaps_stale_jobs(app):
    from datetime import datetime, timedelta, timezone

    created = (datetime.now(timezone.utc) - timedelta(hours=3)).isoformat(timespec="seconds")
    _create_job(app, "stale-job", status="running", created_at=created)

    result = app.test_cli_runner().invoke(args=["cleanup"])

    assert result.exit_code == 0
    assert "reaped 1 stale job" in result.output
    assert store.get_job(app.config["DATABASE"], "stale-job")["status"] == "failed"


def test_cleanup_removes_expired_jobs(app, tmp_path):
    job_id = "old-job"
    _create_job(app, job_id, status="completed", created_at="2000-01-01T00:00:00+00:00")

    upload = Path(app.config["UPLOAD_DIR"]) / f"{job_id}.png"
    upload.write_bytes(b"data")
    artifact_dir = Path(app.config["ARTIFACT_DIR"]) / job_id
    artifact_dir.mkdir(parents=True)
    (artifact_dir / "thing.txt").write_text("artifact")

    result = app.test_cli_runner().invoke(args=["cleanup"])

    assert result.exit_code == 0
    assert "Removed 1 expired job" in result.output
    assert store.get_job(app.config["DATABASE"], job_id) is None
    assert not upload.exists()
    assert not artifact_dir.exists()
