"""Queue selection.

QUEUE_MODE decides how a job is executed:

* ``sync``   — inside the request (used by the test suite)
* ``inline`` — a background thread (no Redis needed; good for local development)
* ``rq``     — an RQ worker backed by Redis (used by Docker Compose)
"""

import logging
import threading

from .tasks import execute_job


LOG = logging.getLogger(__name__)


JOB_TIMEOUT = 900


def _run_in_thread(job_id, config, passphrase):
    try:
        execute_job(job_id, config, passphrase=passphrase)
    except Exception:  # pragma: no cover - last-resort logging
        LOG.exception("Job %s crashed in its worker thread", job_id)


def enqueue_job(app, job_id, passphrase=None):
    mode = (app.config.get("QUEUE_MODE") or "inline").lower()

    if mode == "sync":
        execute_job(job_id, dict(app.config), passphrase=passphrase)
        return "sync"

    if mode == "rq":
        from redis import Redis
        from rq import Queue

        connection = Redis.from_url(app.config["REDIS_URL"])
        queue = Queue(app.config.get("RQ_QUEUE", "forensics"), connection=connection)
        # The passphrase is only an argument for this run: keep neither the job
        # nor its result in Redis after it finishes. The longer timeout covers
        # the worst case of several 60-90s tools on a large upload.
        queue.enqueue(
            "jobs.tasks.execute_job",
            job_id,
            passphrase=passphrase,
            job_timeout=JOB_TIMEOUT,
            result_ttl=0,
            failure_ttl=0,
        )
        return "rq"

    thread = threading.Thread(
        target=_run_in_thread,
        args=(job_id, dict(app.config), passphrase),
        daemon=True,
        name=f"forensics-{job_id[:8]}",
    )
    thread.start()
    return "thread"
