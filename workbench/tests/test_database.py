import sqlite3
from concurrent.futures import ThreadPoolExecutor

import database as store


def test_concurrent_worker_boot_initializes_database(tmp_path):
    database_path = tmp_path / "race.db"

    with ThreadPoolExecutor(max_workers=8) as pool:
        list(pool.map(lambda _index: store.init_db(database_path), range(8)))

    with sqlite3.connect(database_path) as connection:
        mode = connection.execute("PRAGMA journal_mode").fetchone()[0]
        tables = {
            row[0]
            for row in connection.execute(
                "SELECT name FROM sqlite_master WHERE type = 'table'"
            )
        }

    assert mode.lower() == "wal"
    assert {"jobs", "tool_runs", "artifacts", "upload_events"} <= tables
