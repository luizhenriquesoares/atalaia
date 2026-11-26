"""Dedicated scan worker: python -m atalaia.worker

Run as many of these as needed, on any machine that reaches the database. Set
ATALAIA_EMBEDDED_WORKER=false on the API processes so that they only queue scans.
"""
from __future__ import annotations

import logging
import signal

from .config import Settings
from .db import ensure_schema, make_engine, make_session_factory
from .scans import ScanManager
from .security import SecretBox


def main() -> None:
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(name)s %(levelname)s %(message)s")
    settings = Settings()
    engine = make_engine(settings.database_url)
    ensure_schema(engine)
    manager = ScanManager(settings, make_session_factory(engine), SecretBox(settings.secret_key))
    signal.signal(signal.SIGTERM, lambda *_: manager._stop.set())
    logging.getLogger("atalaia.worker").info("worker %s started (%d slots)", manager.worker_id,
                                             settings.scan_workers)
    manager.run_forever()
    engine.dispose()


if __name__ == "__main__":
    main()
