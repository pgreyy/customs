"""customs alerts: the incident log and the error log.

Stores no fake secret values, no file contents and no full tool args: only
the tool name, which rule fired, the bait path and a short redacted preview.
"""
from __future__ import annotations

import contextvars
import json
import os
import re
import shutil
import subprocess
import threading
import time
from pathlib import Path

INCIDENTS_NAME = "incidents.jsonl"
ERRORS_NAME = "errors.log"
PREVIEW_LEN = 200
ROTATE_BYTES = 5 * 1024 * 1024

# Shapes of real secrets, so a preview never stores one even if it isn't bait.
_SECRET_SHAPES = re.compile(
    r"AKIA[0-9A-Z]{16}"
    r"|gh[pousr]_[A-Za-z0-9]{20,}"
    r"|github_pat_[A-Za-z0-9_]{20,}"
    r"|sk-[A-Za-z0-9_\-]{20,}"
    r"|sk_live_[A-Za-z0-9]{10,}"
    r"|xox[abprs]-[A-Za-z0-9\-]{10,}"
    r"|-----BEGIN[A-Z ]*PRIVATE KEY-----"
    r"|(?i:(?:password|passwd|secret|token|api_?key)\s*[=:]\s*)\S+"
    r"|://[^/\s:@]+:[^@\s]+@"
)


# Long runs that may be keys or blobs. Used for previews, not for source URLs
# (a long URL slug is not a secret, and query strings are already dropped).
_LONG_RUN = re.compile(r"[A-Za-z0-9+/=_\-]{40,}")


def redact(text: str, needles=(), long_runs: bool = True) -> str:
    """Replace bait values (any encoded form) and secret-shaped strings."""
    if not text:
        return ""
    t = str(text)[:4000]
    for n in needles:
        if n and n in t:
            t = t.replace(n, "<bait-value>")
    t = _SECRET_SHAPES.sub("<redacted>", t)
    return _LONG_RUN.sub("<redacted>", t) if long_runs else t


def _append(path: Path, line: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    try:
        if path.stat().st_size > ROTATE_BYTES:
            os.replace(path, path.with_name(path.name + ".1"))
    except FileNotFoundError:
        pass
    fd = os.open(path, os.O_WRONLY | os.O_APPEND | os.O_CREAT, 0o600)
    try:
        os.write(fd, (line.rstrip("\n") + "\n").encode("utf-8"))
    finally:
        os.close(fd)
    try:
        os.chmod(path, 0o600)
    except OSError:
        pass


def record_incident(data_dir, *, session_id, tool_name, decision, needles=(), extra=None) -> None:
    entry = {
        "time": time.strftime("%Y-%m-%dT%H:%M:%S%z"),
        "session_id": str(session_id or ""),
        "tool_name": str(tool_name or ""),
        "decision": decision.action,
        "rule": decision.rule,
        "bait_path": decision.bait_path,
        "preview": redact(decision.preview, needles)[:PREVIEW_LEN],
    }
    for k, v in (extra or {}).items():  # e.g. which kind of value matched; never the value
        if k not in entry and isinstance(v, (str, int)):
            entry[k] = v
    _append(Path(data_dir) / INCIDENTS_NAME, json.dumps(entry, ensure_ascii=False))
    return entry


def read_incidents(data_dir, n: int = 10) -> list:
    """Last n incidents, newest first."""
    path = Path(data_dir) / INCIDENTS_NAME
    try:
        with open(path, "rb") as fh:
            fh.seek(0, os.SEEK_END)
            size = fh.tell()
            fh.seek(max(0, size - 512 * 1024))
            lines = fh.read().decode("utf-8", errors="replace").splitlines()
    except FileNotFoundError:
        return []
    out = []
    for line in reversed(lines):
        try:
            item = json.loads(line)
        except ValueError:
            continue
        if isinstance(item, dict):
            out.append(item)
        if len(out) >= n:
            break
    return out


def log_error(data_dir, where: str, exc: BaseException) -> None:
    """Never raises. Messages are redacted and cut, since they may echo input."""
    try:
        if not data_dir:
            return
        msg = redact(f"{exc.__class__.__name__}: {exc}")[:300]
        line = f"{time.strftime('%Y-%m-%dT%H:%M:%S%z')} {where}: {msg}"
        _append(Path(data_dir) / ERRORS_NAME, line)
    except Exception:
        pass


# ---------------------------------------------------------------- chat and push alerts

PUSH_INTERVAL = 30.0  # seconds between pushes for one session

_WHAT = {
    "block": "customs BLOCKED a {tool} call: it tried to access protected credentials.",
    "approve": "customs asked for your approval on a {tool} call: it would read or move a folder "
               "holding credentials.",
    "redact": "customs REDACTED protected credentials from {where}.",
}


# Approval alerts whose reason isn't "a folder holding credentials".
_APPROVE_WHAT = {
    "pipe-to-shell": "customs asked for your approval on a {tool} call: it pipes a downloaded script "
                     "straight into a shell, so its contents can't be inspected.",
    "script-hunt": "customs asked for your approval on a {tool} call: the script it runs searches "
                   "for credential files.",
}


def _short(path: str) -> str:
    home = os.path.expanduser("~")
    return "~" + path[len(home):] if path and path.startswith(home + os.sep) else (path or "")


def alert_text(entry: dict) -> str:
    """Short alert built only from the incident entry (already masked)."""
    decision = entry.get("decision", "")
    tool = entry.get("tool_name", "") or "tool"
    rule = entry.get("rule", "")
    if decision == "redact":
        where = "a model request" if tool == "llm_request" else f"a {tool} result"
        head = _WHAT["redact"].format(where=where)
    elif decision == "approve" and rule in _APPROVE_WHAT:
        head = _APPROVE_WHAT[rule].format(tool=tool)
    else:
        head = _WHAT.get(decision, "customs incident in a {tool} call.").format(tool=tool)
    lines = [head,
             f"Rule: {entry.get('rule', '?')}. Bait file: {_short(entry.get('bait_path', ''))}.",
             f"Likely source: {entry.get('source') or 'none seen'}."]
    prev = (entry.get("preview") or "").replace("\n", " ")
    if prev and tool != "llm_request":
        lines.append(f"Preview (masked): {prev[:PREVIEW_LEN]}")
    return "\n".join(lines)


class Notifier:
    """Posts alerts into the current chat and, optionally, pushes them to a
    messaging target with `hermes send`. Both run on background threads."""

    def __init__(self, data_dir_getter):
        self._data_dir = data_dir_getter
        self._lock = threading.Lock()
        self._pending = {}     # session -> [alert texts]
        self._last_push = {}   # session -> time of last push
        self._scheduled = set()

    def chat(self, ctx, text: str) -> None:
        """post_message reads the session from the calling context, so the
        thread runs in a copy of this hook's context."""
        snapshot = contextvars.copy_context()

        def run():
            try:
                res = snapshot.run(ctx.post_message, text)
                if getattr(res, "ok", True) is False and getattr(res, "error", "") != "no_conversation":
                    log_error(self._data_dir(), "chat alert", RuntimeError(str(res.error)))
            except Exception as exc:
                log_error(self._data_dir(), "chat alert", exc)

        threading.Thread(target=run, name="customs-chat-alert", daemon=True).start()

    def push(self, ctx, session_id: str, text: str, target: str) -> None:
        if not target:
            return
        key = session_id or "-"
        with self._lock:
            self._pending.setdefault(key, []).append(text)
            if key in self._scheduled:
                return  # the next push will include it
            self._scheduled.add(key)
            delay = max(0.0, self._last_push.get(key, 0.0) + PUSH_INTERVAL - time.time())
        t = threading.Timer(delay, self._flush, (ctx, key, target))
        t.daemon = True
        t.start()

    def _flush(self, ctx, key: str, target: str) -> None:
        with self._lock:
            texts = self._pending.pop(key, [])
            self._scheduled.discard(key)
            self._last_push[key] = time.time()
        if not texts:
            return
        msg = texts[0]
        if len(texts) > 1:
            msg += f"\n(+{len(texts) - 1} more customs incident(s) in this session. Run /customs incidents.)"
        try:
            send_push(target, msg)
        except Exception as exc:
            log_error(self._data_dir(), "push alert", exc)


_TARGET_RE = re.compile(r"^[A-Za-z0-9_][A-Za-z0-9_:#@.+\-]{0,200}$")
SEND_TIMEOUT = 15


def _hermes_exe() -> str:
    exe = shutil.which("hermes")
    if exe:
        return exe
    fallback = os.path.expanduser("~/.local/bin/hermes")
    return fallback if os.path.exists(fallback) else "hermes"


def send_push(target: str, message: str) -> None:
    """Push through the documented CLI: hermes send --to <target> --quiet "<message>".
    Runs on the notifier's background thread. No shell; the target is checked so
    it can't be read as an option."""
    if not _TARGET_RE.match(target or ""):
        raise ValueError("alert_target has an unexpected format")
    r = subprocess.run([_hermes_exe(), "send", "--to", target, "--quiet", message],
                       stdin=subprocess.DEVNULL, capture_output=True, text=True,
                       timeout=SEND_TIMEOUT)
    if r.returncode != 0:
        raise RuntimeError(f"hermes send exited {r.returncode}: "
                           + redact((r.stderr or r.stdout or "").strip())[:300])
