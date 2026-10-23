# CTF Toolkit & Forensic Workbench

This repository contains two runnable projects:

- **Static CTF toolkit** at the repository root - cryptography and file-analysis
  pages served by `server.py`.
- **Forensic Workbench** in `workbench/` - the Flask upload and analysis
  platform.

Deployment assets (Docker, Compose, Caddy, environment template) live in
`deploy/`. See [Static CTF toolkit](#static-ctf-toolkit) for the root pages.

## Forensic Workbench

A self-hosted, Aperi'Solve-inspired file analysis platform. Upload a file, and a
worker runs a Linux forensic toolchain against it, then returns a structured
report with tool output, versions, timings and downloadable artifacts.

The UI is original (flat terminal styling, monospace type) and works on desktop
and mobile.

## Features

- Drag-and-drop or file-picker upload with client- and server-side validation.
- Content-based file identification (magic bytes + Pillow), never extension-only.
- Background analysis jobs with live progress polling and stable job URLs.
- Nine independent analysis modules: file type, metadata, strings, hexdump,
  embedded signatures, artifact extraction, steganography/LSB, network captures,
  disk images.
- Per-tool status (`queued`, `running`, `completed`, `empty`, `skipped`,
  `unavailable`, `failed`), version and duration.
- JSON and plain-text report downloads, plus a searchable HTML report.
- Downloadable artifacts: binwalk carvings (carve-only, no shell utilities),
  safely unpacked ZIP entries, `tshark` HTTP objects and steghide extractions,
  all served as opaque attachments.
- Optional steghide passphrase supplied at upload, used once and never stored.
- SQLite storage, Redis/RQ queue for Docker, inline thread queue for local use.
- Per-address upload throttling and a global pending-job cap for shared use.
- pytest suite covering detection, tools, reports and the HTTP flow.

## Architecture

```
browser --HTTP--> Flask web app --enqueue--> RQ / Redis --> worker container
                       |                                       |
                       |-- SQLite (jobs, tool runs, artifacts) |
                       |-- /data/uploads, /data/artifacts <----+
                                       |
                                 forensic binaries
                     (file, exiftool, strings, xxd, binwalk,
                      steghide, tshark, mmls/fls, Pillow)
```

The web process never runs analysis itself (except in `sync`/`inline` modes);
the worker container is where tools execute. Uploads are written with random
names and analyzed from `/data`.

## Quick start (Docker Compose)

Requirements: Docker Engine with Compose v2.

```bash
cp deploy/.env.example deploy/.env
# edit deploy/.env and set a real SECRET_KEY
docker compose -f deploy/docker-compose.yml --env-file deploy/.env up --build
```

Open <http://localhost:8000>. The stack starts:

- `web` - Gunicorn + Flask on port 8000
- `worker` - RQ worker, same image, tools installed
- `redis` - RQ broker

The analysis image installs `file`, `binutils` (strings), `xxd`, `binwalk`,
`exiftool`, `steghide`, `tshark` and `sleuthkit` at build time. Jobs never
install packages at runtime.

Stop with `docker compose -f deploy/docker-compose.yml down` (add `-v` to remove
uploads and reports).

## Local development

Python 3.11+ is required. On Windows, use the inline queue (no Redis needed):

```bash
python -m venv .venv
.venv\Scripts\activate          # Windows
# source .venv/bin/activate     # macOS/Linux
pip install -r workbench/requirements-dev.txt
```

Run the app from the workbench directory so its local imports resolve:

```bash
cd workbench

# Windows PowerShell
$env:QUEUE_MODE="inline"
flask --app "app:create_app" run --port 5000

# macOS/Linux
QUEUE_MODE=inline flask --app "app:create_app" run --port 5000
```

Open <http://127.0.0.1:5000>. Jobs run in a background thread; the progress page
polls the job API.

Forensic binaries that are missing on the host are reported as `unavailable`,
and the Python fallbacks (string extraction, hexdump, signature scan, LSB
checks, Pillow properties) still run. Use the Docker image for the full
toolchain.

### Full toolchain on Windows with WSL

Windows itself cannot run most of these tools. The simplest local setup is to
run the app inside an Ubuntu WSL distribution:

```bash
sudo apt install -y file binutils vim-common libimage-exiftool-perl \
  binwalk steghide tshark sleuthkit

cd /mnt/c/path/to/ctftools
python3 -m venv --without-pip ~/.venvs/ctftools
curl -fsSL https://bootstrap.pypa.io/pip/pip.pyz -o /tmp/pip.pyz
~/.venvs/ctftools/bin/python /tmp/pip.pyz install -r workbench/requirements.txt

cd workbench
QUEUE_MODE=inline DATA_DIR="$HOME/ctftools-data" \
  ~/.venvs/ctftools/bin/python -m flask --app "app:create_app" run --port 5001
```

Open <http://localhost:5001>. A separate `DATA_DIR` keeps the WSL job database
away from a Windows run of the same checkout. The `--without-pip` / `pip.pyz`
form works when Ubuntu does not have `python3-venv` installed; installing that
package lets `python3 -m venv` create a pip-equipped environment normally.

### Queue modes

| `QUEUE_MODE` | Behaviour | Use |
| --- | --- | --- |
| `inline` | daemon thread per job | local development |
| `sync` | job runs during the upload request | tests, CI |
| `rq` | enqueued to Redis for an RQ worker | Docker Compose |

## Configuration

All settings are environment variables (see `deploy/.env.example`).

| Variable | Default | Purpose |
| --- | --- | --- |
| `SECRET_KEY` | dev value | Flask session/flash signing |
| `DATA_DIR` | `data/` at the repository root | Root for uploads, artifacts and the DB |
| `DATABASE_PATH` | `<DATA_DIR>/forensics.db` | SQLite file |
| `MAX_UPLOAD_BYTES` | 33554432 | Upload limit (32 MB) |
| `MAX_ARTIFACT_BYTES` | 5242880 | Largest artifact kept/downloadable |
| `RETENTION_HOURS` | 24 | Cleanup age for jobs and files |
| `TOOL_TIMEOUT` | 60 | Default per-tool execution budget (s) |
| `TOOL_OUTPUT_LIMIT` | 100000 | Characters stored per tool |
| `MAX_STRING_LINES` | 500 | Strings shown in the report |
| `UPLOAD_LIMIT_PER_HOUR` | 20 | Uploads accepted per IP per hour |
| `MAX_PENDING_JOBS` | 25 | Queued + running jobs before uploads are refused |
| `JOB_STALE_HOURS` | 2 | Age after which an abandoned running job is failed |
| `COOKIE_SECURE` | 0 | Mark session cookies Secure (set by the production stack) |
| `TRUST_PROXY` | 0 | Trust one `X-Forwarded-For` hop (set only behind a proxy) |
| `QUEUE_MODE` | inline | inline / sync / rq |
| `REDIS_URL` | redis://127.0.0.1:6379/0 | RQ broker |
| `RQ_QUEUE` | forensics | Queue name |

## Analysis modules

| Module | Binary / library | Notes when unavailable |
| --- | --- | --- |
| File type | `file` | Built-in magic detection still runs |
| Metadata | `exiftool` | Marked unavailable |
| Strings | `strings` | Python extractor fallback |
| Hexadecimal preview | `xxd` | Python hexdump fallback |
| Embedded signatures | `binwalk` | Built-in signature scan fallback |
| Artifact extraction | `binwalk -e -z` + Python `zipfile` | ZIP unpacking always runs; binwalk carving is optional |
| Steganography | `steghide` + Pillow | LSB/pixel checks still run; extraction needs a passphrase |
| Network | `tshark` | Only for pcap/pcapng; HTTP objects exported as artifacts |
| Disk image | `mmls`, `fls` | Only for ISO/raw/ext images; listing only, no extraction |

Statuses are explicit: `completed` (findings), `empty` (ran, nothing found),
`skipped` (tool does not apply to this file), `unavailable` (binary missing),
`failed` (tool error or timeout). A tool failure never stops the other tools.

steghide runs `info` once with the passphrase supplied at upload (or an empty
one). If it reports an embedded file, that file is extracted once to the
artifacts directory. No guessing or password lists are used, and the passphrase
is never written to the database, report or logs. In `rq` mode it is a job
argument, so it exists in Redis only until that job runs; keep Redis on the
internal Compose network. Disk images are listed but not mounted or extracted.

## Reports and artifacts

Every finished job stores a canonical JSON report:

- **HTML** - `/jobs/<id>/report` (collapsible sections, search, artifact links)
- **JSON** - `/jobs/<id>/report.json`
- **TXT** - `/jobs/<id>/report.txt`
- **Artifacts** - `/jobs/<id>/artifacts/<artifact_id>`

Artifacts are registered only when they are inside the job's artifact directory,
non-empty and below `MAX_ARTIFACT_BYTES`; at most 50 are kept per job. ZIP
entries are filtered for path traversal, symlinks, encrypted entries and
per-entry/total size limits. Downloads are always sent as
`application/octet-stream` with `Content-Disposition: attachment` and
`X-Content-Type-Options: nosniff`, so a carved HTML/SVG/executable is never
rendered inline. Artifacts are untrusted by definition: open them in a VM or
sandbox. Reports include tool versions, durations and timestamps, and state
explicitly that findings are leads, not conclusions.

## HTTP routes

| Method | Path | Purpose |
| --- | --- | --- |
| GET | `/` | Upload page + recent analyses |
| GET | `/healthz` | Liveness probe (database reachable) |
| POST | `/upload` | Validate, store, create job, enqueue |
| GET | `/jobs/<id>` | Progress page (polling) |
| GET | `/api/jobs/<id>` | Job status JSON |
| GET | `/jobs/<id>/report` | HTML report |
| GET | `/jobs/<id>/report.json` | JSON report download |
| GET | `/jobs/<id>/report.txt` | Text report download |
| GET | `/jobs/<id>/artifacts/<id>` | Artifact download (forced attachment) |

## Retention

`RETENTION_HOURS` controls how long uploads, artifacts and reports are kept.
The production stack runs `cleanup` hourly in its `scheduler` service. The
development stack does not, so run it manually:

```bash
docker compose -f deploy/docker-compose.yml --env-file deploy/.env \
  exec web flask --app "app:create_app" cleanup
```

It deletes expired jobs, their uploads and artifacts, prunes upload throttle
records and marks analyses abandoned by a dead worker as failed. The upload page
advertises the retention window, so keep the schedule in sync with it.

## Tests

```bash
python -m pytest
```

The suite uses a temporary data directory and `QUEUE_MODE=sync`, so it never
needs Redis, Docker or the forensic binaries. It covers magic-byte detection,
tool fallbacks, report assembly/exporters, the upload -> job -> report flow,
oversized/empty uploads, safe vs unsafe artifact downloads and the cleanup
command.

## Deploy on a VPS

This is the public setup: Caddy terminates TLS, only ports 80/443 are exposed,
and the Flask port is never published.

Requirements: a Linux VPS with Docker Engine + Compose v2 (2 vCPU / 2 GB RAM is
a reasonable start), a domain whose `A`/`AAAA` record points at the server, and
ports 22, 80 and 443 open in the firewall.

```bash
git clone <your-repo> ctftools && cd ctftools
cp deploy/.env.example deploy/.env
chmod 600 deploy/.env
# Set SECRET_KEY (e.g. `openssl rand -hex 32`) and SITE_DOMAIN.
docker compose -f deploy/docker-compose.prod.yml --env-file deploy/.env up -d --build
docker compose -f deploy/docker-compose.prod.yml --env-file deploy/.env ps
docker compose -f deploy/docker-compose.prod.yml --env-file deploy/.env \
  exec web flask --app app:create_app preflight
docker compose -f deploy/docker-compose.prod.yml --env-file deploy/.env logs -f caddy
```

Open `https://<SITE_DOMAIN>/`. Caddy obtains and renews the certificate; the
first request can take a few seconds. `GET /healthz` returns `{"status":"ok"}`
when the database is reachable.

The production stack runs:

- `caddy` - TLS 1.3, HSTS, gzip/zstd, reverse proxy to `web:8000`
- `web` - Gunicorn, no published port, `TRUST_PROXY=1` so rate limits use the
  client address
- `worker` - RQ worker with the full forensic toolchain
- `redis` - RQ broker (not published)
- `scheduler` - hourly retention cleanup and stale-job reaping

Uploads are throttled per address (`UPLOAD_LIMIT_PER_HOUR`, default 20/h) and
refused while `MAX_PENDING_JOBS` analyses are queued or running. Lower both if
the instance is popular or the host is small. There is no login: anyone who
reaches the URL can upload a file, so keep the limits conservative and watch
`docker compose -f deploy/docker-compose.prod.yml --env-file deploy/.env logs -f web worker`.

Updates and backups:

```bash
git pull && docker compose -f deploy/docker-compose.prod.yml \
  --env-file deploy/.env up -d --build
# Stop writes first if you need a consistent copy of the volume:
docker compose -f deploy/docker-compose.prod.yml --env-file deploy/.env \
  stop web worker scheduler
docker run --rm \
  -v forensic-workbench-prod_forensics-data:/data:ro \
  -v "$PWD":/backup \
  alpine tar czf "/backup/forensics-data-$(date +%F).tgz" -C /data .
docker compose -f deploy/docker-compose.prod.yml --env-file deploy/.env \
  start web worker scheduler
```

A GitHub Actions workflow ([.github/workflows/ci.yml](.github/workflows/ci.yml))
runs the tests, builds the image, validates the production Compose file and
smoke-tests `/healthz` on every push, so a broken Dockerfile is caught before
the VPS update.

The SQLite database and all uploads/artifacts live in the `forensics-data`
volume. Losing it loses every stored job; back it up to another machine.

## Deployment notes

- Put the web service behind a TLS-terminating reverse proxy; do not expose the
  raw container port to the internet without one.
- Set a strong `SECRET_KEY`, keep `.env` out of version control, and back up the
  `forensics-data` volume if reports matter.
- For more throughput, scale workers: `docker compose -f deploy/docker-compose.prod.yml --env-file deploy/.env up -d --scale worker=3`.
- SQLite is fine for a single host. To move to PostgreSQL, replace the functions
  in `workbench/database.py` with an adapter using the same schema; the rest of the app
  only calls those helpers.
- Reduce `MAX_UPLOAD_BYTES` and `TOOL_TIMEOUT` on small hosts; the worker is
  memory-limited in Compose.

## Security model

Uploaded files are hostile input. The worker runs as an unprivileged user inside
a read-only container with dropped capabilities, tmpfs `/tmp`, memory/PID limits,
per-tool timeouts and output caps, and it publishes no ports (it only needs the
Compose network to reach Redis). That is defense in depth, **not** a hardened
sandbox: do not expose this service to the public internet without a container
escape review, and never mount host directories into the worker beyond the data
volume.

Uploads are throttled per address (`UPLOAD_LIMIT_PER_HOUR`) and refused while
`MAX_PENDING_JOBS` analyses are queued or running. Set `TRUST_PROXY=1` only
when a reverse proxy overwrites `X-Forwarded-For`; otherwise clients can spoof
the address behind the limit. App responses set CSP, `nosniff`, `DENY` framing
and `no-store`; job and report pages are never cached. There is still no
authentication or per-user isolation; add auth before opening it to an
untrusted audience.

## Project layout

```
index.html, cryptography.html, ...   static CTF pages at the repository root
styles.css, cryptography.js, ...     static page assets
server.py                            local HTTP server for the static tools
crypto/                              cipher and encoding implementations
forensics/                           static-page file analysis helpers
tests/test_crypto.py                 static toolkit tests

workbench/
  app.py                             Flask factory, routes, CLI cleanup
  config.py                          environment configuration
  database.py                        SQLite schema + helpers
  analyzer/                          detection, dispatcher, runner, tools
  jobs/                              queue selection + analysis task
  reports/exporter.py                JSON/TXT report builders
  templates/ static/                 Jinja UI
  tests/                             workbench pytest suite
  requirements*.txt                  workbench dependencies

deploy/
  Dockerfile                         workbench image
  docker-compose.yml                 development stack
  docker-compose.prod.yml            Caddy + TLS production stack
  Caddyfile                          reverse proxy and TLS config
  .env.example                       deployment environment template

pytest.ini                           root test/import configuration
.github/workflows/ci.yml             tests, image build and smoke test
```

## Static CTF toolkit

The pages at the repository root are deliberately standalone and can be hosted
as static files, but their decoder and upload features call the local API. Start
the API and page server with:

```bash
python server.py
```

Open <http://127.0.0.1:8000>. The cryptography page has an auto-decoder plus
Caesar, rail fence, Atbash, ROT47, Vigenère, columnar transposition, binary,
hex, Base32/64/85, URL, HTML, Morse, Bacon's cipher and A1Z26. The static
`forensics.html` page is the earlier uploader prototype; the Flask workbench in
`workbench/` is the fuller analysis platform.

### About the original CTF toolkit

> Hi i suck at coding but im gonna try to compile a bunch of CTF tools into a website
> Stuff like
> - Cryptography
> - Maybe some file forensics?
