"""customs alerts: the incident log and the error log.

Stores no fake secret values, no file contents and no full tool args: only
the tool name, which rule fired, the bait path and a short redacted preview.
"""
from __future__ import annotations

import contextvars
import json
import os
import re
import secrets
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
        "id": secrets.token_hex(6),
        "time": time.strftime("%Y-%m-%dT%H:%M:%S%z"),
        "session_id": str(session_id or ""),
        "tool_name": str(tool_name or ""),
        "decision": decision.action,
        "rule": decision.rule,
        "bait_path": decision.bait_path,
        "preview": redact(decision.preview, needles)[:PREVIEW_LEN],
    }
    for k, v in (extra or {}).items():  # e.g. which kind of value matched; never the value
        if k in entry:
            continue
        if isinstance(v, (str, int)):  # bool is an int
            entry[k] = v
        elif isinstance(v, (list, tuple)):  # short event lines; masked again here
            entry[k] = [redact(x, needles)[:200] for x in v[:12] if isinstance(x, str)]
    _append(Path(data_dir) / INCIDENTS_NAME, json.dumps(entry, ensure_ascii=False))
    return entry


def read_incidents(data_dir, n: int = 10) -> list:
    """Last n incidents, newest first, with any later user decision merged in."""
    path = Path(data_dir) / INCIDENTS_NAME
    try:
        with open(path, "rb") as fh:
            fh.seek(0, os.SEEK_END)
            size = fh.tell()
            fh.seek(max(0, size - 512 * 1024))
            lines = fh.read().decode("utf-8", errors="replace").splitlines()
    except FileNotFoundError:
        return []
    out, decisions = [], {}
    for line in reversed(lines):
        try:
            item = json.loads(line)
        except ValueError:
            continue
        if not isinstance(item, dict):
            continue
        if "decision_for" in item:  # a user's answer to an approval request, logged later
            decisions.setdefault(str(item["decision_for"]), item.get("user_decision"))
            continue
        ans = decisions.get(str(item.get("id", "")))
        if ans in USER_DECISIONS:
            item = dict(item, user_decision=ans, outcome=ans)
        out.append(item)
        if len(out) >= n:
            break
    return out


USER_DECISIONS = ("user approved", "user denied")


def record_decision(data_dir, incident_id: str, user_decision: str) -> None:
    """Append the user's answer to an approval request. Only the two values Hermes
    reports from a person are accepted; anything else is not recorded."""
    if not incident_id or user_decision not in USER_DECISIONS:
        return
    _append(Path(data_dir) / INCIDENTS_NAME, json.dumps(
        {"decision_for": str(incident_id), "user_decision": user_decision,
         "time": time.strftime("%Y-%m-%dT%H:%M:%S%z")}))


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

# How a decision is labelled anywhere a person reads it.
LABEL = {"block": "BLOCKED", "approve": "ASKED", "redact": "REDACTED"}
_HEAD = {"block": "BLOCKED", "approve": "ASKED FOR APPROVAL", "redact": "REDACTED"}
_DEFAULT_SEVERITY = {"block": "high", "approve": "medium", "redact": "medium"}


def _short(path: str) -> str:
    home = os.path.expanduser("~")
    return "~" + path[len(home):] if path and path.startswith(home + os.sep) else (path or "")


# ---------------------------------------------------------------- defanging (alerts only)

# Endings that make Telegram turn text into a link. File extensions that are
# also country domains (.sh, .py, .pl, .md, .rs, .so) and .zip/.mov are left
# out, so script and file names stay readable.
_TLDS = ("com", "net", "org", "edu", "gov", "mil", "int", "io", "dev", "app", "ai", "co", "me", "info",
         "biz", "xyz", "site", "online", "tech", "cloud", "page", "link", "live", "pro", "gg", "tv",
         "us", "uk", "de", "fr", "nl", "ru", "cn", "jp", "in", "br", "au", "ca", "eu", "ch", "se", "es",
         "it", "be", "at", "dk", "fi", "ie", "nz", "za", "kr", "tw", "hk", "sg", "mx", "ar",
         "invalid", "example", "test", "localhost", "local", "internal", "onion")
_URL_DEFANG_RE = re.compile(r"\b(h)tt(ps?)://([^\s/`'\"<>)\]]+)", re.I)
_DOMAIN_DEFANG_RE = re.compile(
    r"(?<![\w-])((?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+(?:" + "|".join(_TLDS) + r"))(?![\w-])", re.I)


def defang(text: str) -> str:
    """https://a.b.com/x -> hxxps://a[.]b[.]com/x, and bare a.b.com -> a[.]b[.]com.
    Used only for alerts; the incident log and the export keep the real text."""
    t = _URL_DEFANG_RE.sub(lambda m: m.group(1) + "xx" + m.group(2) + "://" + m.group(3).replace(".", "[.]"),
                           str(text or ""))
    return _DOMAIN_DEFANG_RE.sub(lambda m: m.group(1).replace(".", "[.]"), t)


def _code(text: str) -> str:
    """Inline code: Hermes' Telegram formatter passes code through untouched, so
    underscores and asterisks in paths or commands can't turn into formatting."""
    t = re.sub(r"\s*[\r\n]+\s*", " ", str(text or "")).strip().replace("`", "'")
    # hermes send switches to HTML when it sees anything tag-like (<redacted>, cat <f >x),
    # and Telegram then rejects the message as bad HTML: use look-alike brackets instead.
    t = t.replace("<", "\u2039").replace(">", "\u203a")
    return f"`{t}`" if t else ""


# ---------------------------------------------------------------- alert text

def _what_happened(decision: str, rule: str, tool: str) -> str:
    t = _code(tool)
    if decision == "redact":
        if tool == "llm_request":
            return ("A request to the model provider contained a fake credential value. "
                    "customs replaced it before the request was sent.")
        return f"A {t} result contained a fake credential value. customs replaced it before the model saw it."
    if decision == "block":
        if rule == "value-in-args":
            return f"A {t} call carried a fake credential value, possibly encoded. customs stopped it before it ran."
        if rule == "script-bait":
            return f"The script this {t} call runs touches a bait file. customs stopped it before it ran."
        if rule == "script-exfil":
            return (f"The script this {t} call runs searches for credential files and uploads them. "
                    "customs stopped it before it ran.")
        return (f"A {t} call reached for a bait file, a fake credential nothing legitimate opens. "
                "customs stopped it before it ran.")
    if rule == "pipe-to-shell":
        return (f"This {t} call pipes a downloaded script straight into a shell, so its contents can't be "
                "inspected. customs asked you to approve it.")
    if rule == "script-hunt":
        return f"The script this {t} call runs searches for credential files. customs asked you to approve it."
    if rule == "attack-chain":
        return (f"This {t} call would send data out, and earlier steps in this session looked like searching "
                "for and packaging credentials. They may be unrelated, so customs asked you to approve it.")
    return f"This {t} call would read or move a folder holding credentials. customs asked you to approve it."


def alert_text(entry: dict) -> str:
    """The alert for chat and push, built only from the (already masked) entry.
    Short labelled sections for a phone screen; URLs and domains defanged."""
    decision = entry.get("decision", "")
    tool = entry.get("tool_name", "") or "tool"
    rule = entry.get("rule", "") or "?"
    severity = entry.get("severity") or _DEFAULT_SEVERITY.get(decision, "medium")
    parts = [f"customs · {_HEAD.get(decision, decision.upper() or 'INCIDENT')}\nSeverity: {severity}",
             "What happened\n" + _what_happened(decision, rule, tool)]
    rule_block = "Rule\n" + _code(rule)
    if entry.get("chain_reason"):
        rule_block += "\nPattern: " + str(entry["chain_reason"])
    parts.append(rule_block)
    bait_path = entry.get("bait_path") or ""
    script = entry.get("script") or ""
    if rule in ("script-exfil", "script-hunt"):
        script = script or bait_path
        bait_path = ""
    if bait_path:
        parts.append("Bait file\n" + _code(_short(bait_path)))
    if script:
        parts.append("Script\n" + _code(_short(script)))
    prev = (entry.get("preview") or "").replace("\n", " ")[:PREVIEW_LEN]
    if prev and tool != "llm_request":
        parts.append(("Command (masked)" if tool == "terminal" else "Preview (masked)") + "\n" + _code(prev))
    chain = [c for c in (entry.get("chain") or []) if isinstance(c, str)]
    before = [b for b in (entry.get("before") or []) if isinstance(b, str)]
    if chain:
        parts.append("Steps seen together, oldest first (not proven connected)\n"
                     + "\n".join(_code(c) for c in chain[-6:]))
    elif before:
        parts.append("Earlier in this session, most recent last\n" + "\n".join(_code(b) for b in before[-5:]))
    source = entry.get("source") or ""
    parts.append(("Source: " + (_code(source) if source and source != "none seen" else "none seen")) + "\n"
                 + "Lockdown: " + ("on for this session" if entry.get("lockdown_active") else "off"))
    return defang("\n\n".join(parts))


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
