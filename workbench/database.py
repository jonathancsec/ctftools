"""SQLite storage for jobs, tool runs and artifacts.

The schema is deliberately plain SQL so the same code can move to PostgreSQL
later with a small adapter layer.
"""

import sqlite3
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path

SCHEMA = """
CREATE TABLE IF NOT EXISTS jobs (
    id TEXT PRIMARY KEY,
    original_name TEXT NOT NULL,
    stored_name TEXT NOT NULL,
    size INTEGER NOT NULL,
    sha256 TEXT NOT NULL,
    detected_type TEXT NOT NULL,
    mime TEXT,
    status TEXT NOT NULL,
    error TEXT,
    created_at TEXT NOT NULL,
    started_at TEXT,
    finished_at TEXT,
    report_json TEXT
);

CREATE TABLE IF NOT EXISTS tool_runs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    job_id TEXT NOT NULL REFERENCES jobs(id) ON DELETE CASCADE,
    tool TEXT NOT NULL,
    display_name TEXT NOT NULL,
    status TEXT NOT NULL,
    summary TEXT,
    output TEXT,
    error TEXT,
    version TEXT,
    duration_ms INTEGER,
    started_at TEXT,
    finished_at TEXT,
    position INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS artifacts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    job_id TEXT NOT NULL REFERENCES jobs(id) ON DELETE CASCADE,
    tool TEXT,
    name TEXT NOT NULL,
    path TEXT NOT NULL,
    size INTEGER NOT NULL,
    sha256 TEXT NOT NULL,
    safe INTEGER NOT NULL DEFAULT 0,
    created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS upload_events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ip TEXT NOT NULL,
    created_at TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_tool_runs_job ON tool_runs(job_id, position);
CREATE INDEX IF NOT EXISTS idx_artifacts_job ON artifacts(job_id);
CREATE INDEX IF NOT EXISTS idx_jobs_created ON jobs(created_at);
CREATE INDEX IF NOT EXISTS idx_upload_events_ip ON upload_events(ip, created_at);
"""

JOB_UPDATE_FIELDS = {
    "status",
    "error",
    "started_at",
    "finished_at",
    "report_json",
    "detected_type",
    "mime",
    "sha256",
}

TOOL_RUN_FIELDS = {
    "job_id",
    "tool",
    "display_name",
    "status",
    "summary",
    "output",
    "error",
    "version",
    "duration_ms",
    "started_at",
    "finished_at",
    "position",
}

ARTIFACT_FIELDS = {"job_id", "tool", "name", "path", "size", "sha256", "safe", "created_at"}


def utc_now():
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


@contextmanager
def db(database_path):
    path = Path(database_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    connection = sqlite3.connect(path, timeout=30)
    connection.row_factory = sqlite3.Row
    connection.execute("PRAGMA foreign_keys = ON")
    try:
        yield connection
        connection.commit()
    finally:
        connection.close()


def init_db(database_path):
    with db(database_path) as connection:
        # WAL lets the web workers, RQ worker and scheduler read while another
        # process writes; the default rollback journal blocks readers.
        connection.execute("PRAGMA journal_mode = WAL")
        connection.executescript(SCHEMA)


def _insert(database_path, table, fields):
    columns = list(fields)
    placeholders = ", ".join("?" for _ in columns)
    sql = f"INSERT INTO {table} ({', '.join(columns)}) VALUES ({placeholders})"
    with db(database_path) as connection:
        cursor = connection.execute(sql, [fields[column] for column in columns])
        return cursor.lastrowid


def _update(database_path, table, row_id, fields):
    columns = list(fields)
    assignments = ", ".join(f"{column} = ?" for column in columns)
    sql = f"UPDATE {table} SET {assignments} WHERE id = ?"
    with db(database_path) as connection:
        connection.execute(sql, [fields[column] for column in columns] + [row_id])


def create_job(database_path, job):
    return _insert(database_path, "jobs", job)


def update_job(database_path, job_id, **fields):
    unknown = set(fields) - JOB_UPDATE_FIELDS
    if unknown:
        raise ValueError(f"Unknown job fields: {sorted(unknown)}")
    if fields:
        _update(database_path, "jobs", job_id, fields)


def get_job(database_path, job_id):
    with db(database_path) as connection:
        row = connection.execute("SELECT * FROM jobs WHERE id = ?", (job_id,)).fetchone()
    return dict(row) if row else None


def recent_jobs(database_path, limit=8):
    with db(database_path) as connection:
        rows = connection.execute(
            "SELECT id, original_name, detected_type, size, status, created_at "
            "FROM jobs ORDER BY created_at DESC, rowid DESC LIMIT ?",
            (limit,),
        ).fetchall()
    return [dict(row) for row in rows]


def add_tool_run(database_path, run):
    unknown = set(run) - TOOL_RUN_FIELDS
    if unknown:
        raise ValueError(f"Unknown tool run fields: {sorted(unknown)}")
    return _insert(database_path, "tool_runs", run)


def update_tool_run(database_path, job_id, tool, **fields):
    allowed = TOOL_RUN_FIELDS - {"job_id", "tool"}
    unknown = set(fields) - allowed
    if unknown:
        raise ValueError(f"Unknown tool run fields: {sorted(unknown)}")
    assignments = ", ".join(f"{column} = ?" for column in fields)
    with db(database_path) as connection:
        connection.execute(
            f"UPDATE tool_runs SET {assignments} WHERE job_id = ? AND tool = ?",
            [fields[column] for column in fields] + [job_id, tool],
        )


def list_tool_runs(database_path, job_id):
    with db(database_path) as connection:
        rows = connection.execute(
            "SELECT * FROM tool_runs WHERE job_id = ? ORDER BY position, id",
            (job_id,),
        ).fetchall()
    return [dict(row) for row in rows]


def add_artifact(database_path, artifact):
    unknown = set(artifact) - ARTIFACT_FIELDS
    if unknown:
        raise ValueError(f"Unknown artifact fields: {sorted(unknown)}")
    return _insert(database_path, "artifacts", artifact)


def list_artifacts(database_path, job_id):
    with db(database_path) as connection:
        rows = connection.execute(
            "SELECT * FROM artifacts WHERE job_id = ? ORDER BY id",
            (job_id,),
        ).fetchall()
    return [dict(row) for row in rows]


def get_artifact(database_path, job_id, artifact_id):
    with db(database_path) as connection:
        row = connection.execute(
            "SELECT * FROM artifacts WHERE job_id = ? AND id = ?",
            (job_id, artifact_id),
        ).fetchone()
    return dict(row) if row else None


def count_active_jobs(database_path):
    with db(database_path) as connection:
        row = connection.execute(
            "SELECT COUNT(*) AS total FROM jobs WHERE status IN ('queued', 'running')"
        ).fetchone()
    return row["total"]


def record_upload(database_path, ip, timestamp):
    with db(database_path) as connection:
        connection.execute(
            "INSERT INTO upload_events (ip, created_at) VALUES (?, ?)", (ip, timestamp)
        )


def count_uploads_since(database_path, ip, since):
    with db(database_path) as connection:
        row = connection.execute(
            "SELECT COUNT(*) AS total FROM upload_events "
            "WHERE ip = ? AND created_at >= ?",
            (ip, since),
        ).fetchone()
    return row["total"]


def purge_upload_events(database_path, before):
    with db(database_path) as connection:
        connection.execute("DELETE FROM upload_events WHERE created_at < ?", (before,))


def fail_stale_jobs(database_path, before, message):
    """Mark jobs whose worker disappeared as failed.

    A killed RQ worker or a restarted container leaves rows in ``running``
    forever, which would otherwise consume MAX_PENDING_JOBS until the upload
    endpoint refuses every request.
    """
    with db(database_path) as connection:
        rows = connection.execute(
            "SELECT id FROM jobs WHERE status IN ('queued', 'running') "
            "AND COALESCE(started_at, created_at) < ?",
            (before,),
        ).fetchall()
        job_ids = [row["id"] for row in rows]
        if not job_ids:
            return 0

        finished = utc_now()
        placeholders = ", ".join("?" for _ in job_ids)
        connection.execute(
            f"UPDATE jobs SET status = 'failed', error = ?, finished_at = ? "
            f"WHERE id IN ({placeholders})",
            [message, finished, *job_ids],
        )
        connection.execute(
            f"UPDATE tool_runs SET status = 'failed', error = ?, finished_at = ? "
            f"WHERE job_id IN ({placeholders}) AND status IN ('queued', 'running')",
            [message, finished, *job_ids],
        )
        return len(job_ids)


def jobs_before(database_path, timestamp):
    with db(database_path) as connection:
        rows = connection.execute(
            "SELECT * FROM jobs WHERE created_at < ?",
            (timestamp,),
        ).fetchall()
    return [dict(row) for row in rows]


def delete_job(database_path, job_id):
    with db(database_path) as connection:
        connection.execute("DELETE FROM artifacts WHERE job_id = ?", (job_id,))
        connection.execute("DELETE FROM tool_runs WHERE job_id = ?", (job_id,))
        connection.execute("DELETE FROM jobs WHERE id = ?", (job_id,))
