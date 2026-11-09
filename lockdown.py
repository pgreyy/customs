"""customs lockdown: sessions that tried to leak credentials.

Pure Python, no Hermes imports. A locked session stays locked until
/customs unlock, including across a gateway restart (kept in lockdown.json in
the data folder). Entries older than 30 days are dropped.
"""
from __future__ import annotations

import json
import os
import threading
import time
from pathlib import Path

FILE_NAME = "lockdown.json"
MAX_AGE = 30 * 24 * 3600
MESSAGE = ("customs lockdown: this session tried to leak credentials. Approve network actions "
           "one by one, or run /customs unlock.")


class Lockdown:
    def __init__(self):
        self._lock = threading.Lock()
        self._locked = {}  # session_id -> {"since", "rule", "bait_path"}
        self._path = None

    def load(self, data_dir) -> None:
        try:
            self._path = Path(data_dir) / FILE_NAME
            raw = json.loads(self._path.read_text(encoding="utf-8"))
            now = time.time()
            with self._lock:
                self._locked = {k: v for k, v in (raw or {}).items()
                                if isinstance(v, dict) and now - float(v.get("since", 0)) < MAX_AGE}
        except (OSError, ValueError, TypeError, AttributeError):
            pass

    def _save_locked(self) -> None:
        if self._path is None:
            return
        tmp = self._path.with_name(f".{self._path.name}.{os.getpid()}.tmp")
        fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            json.dump(self._locked, fh)
        os.replace(tmp, self._path)

    def lock(self, session_id, rule="", bait_path="") -> bool:
        """Returns True when the session was not locked before."""
        if not session_id:
            return False
        with self._lock:
            new = session_id not in self._locked
            if new:
                self._locked[session_id] = {"since": time.time(), "rule": rule, "bait_path": bait_path}
                try:
                    self._save_locked()
                except OSError:
                    pass
            return new

    def unlock(self, *session_ids) -> list:
        done = []
        with self._lock:
            for sid in session_ids:
                if sid and sid in self._locked:
                    del self._locked[sid]
                    done.append(sid)
            if done:
                try:
                    self._save_locked()
                except OSError:
                    pass
        return done

    def is_locked(self, session_id) -> bool:
        return bool(session_id) and session_id in self._locked

    def info(self, session_id):
        return self._locked.get(session_id) if session_id else None

    def count(self) -> int:
        return len(self._locked)
