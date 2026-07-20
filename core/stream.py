# core/stream.py

import json
import sys
from datetime import datetime, timezone
from threading import Lock

_lock = Lock()
_initialized = False


def init_ndjson():
    """
    Initialize NDJSON streaming.
    Currently stdout-based, but keeps API stable.
    """
    global _initialized
    _initialized = True


def ndjson_emit(event: dict):
    """
    Emit a single NDJSON event (thread-safe).
    """
    if not _initialized:
        return

    event.setdefault(
        "timestamp",
        datetime.now(timezone.utc).isoformat()
    )

    with _lock:
        sys.stdout.write(json.dumps(event, ensure_ascii=False) + "\n")
        sys.stdout.flush()


def close_ndjson():
    """
    Close NDJSON stream (reserved for future file/socket backends).
    """
    global _initialized
    _initialized = False

