"""customs events: a small, sanitized log of what each session did.

Pure Python, no Hermes imports. Nothing here decides whether a call is
blocked: the hooks call it after the tripwire has decided, inside their own
try/except, and use it only to describe incidents and to spot a chain of steps
that is worth a human look (correlate.py).

Each event holds only a type tag, the tool name and a short label for the
target: a host name, a shortened path or a command name. Never a full tool
argument, file contents or a value. The log is in memory only, at most
MAX_EVENTS per session (oldest dropped) and MAX_SESSIONS sessions.
"""
from __future__ import annotations

import json
import os
import re
import threading
import time
import urllib.parse
from collections import OrderedDict, deque

from . import alerts, detect

MAX_EVENTS = 50
MAX_SESSIONS = 200
LABEL_LEN = 80

UNTRUSTED_READ = "untrusted-content-read"
UNTRUSTED_ATTEMPT = "untrusted-content-attempt"   # a fetch that failed: nothing was read
RECON = "credential-recon"
STAGING = "file-staging"
ENCODING = "encoding-or-transform"
OUTBOUND = "outbound-attempt"
BAIT_HIT = "bait-hit"
TYPES = (UNTRUSTED_READ, UNTRUSTED_ATTEMPT, RECON, STAGING, ENCODING, OUTBOUND, BAIT_HIT)

# A reference to a credential location or credential-like file name.
CRED_PATH_RE = re.compile(
    r"(?:^|[\s/'\"=~:(])\.(?:ssh|aws|gnupg|kube|docker|azure)(?=[/\s'\")]|$)"
    r"|(?:^|[\s/'\"=~:(])\.env(?:[._-][\w.-]*)?(?=[\s'\")]|$)"
    r"|\bid_(?:rsa|dsa|ecdsa|ed25519)\b|[\w-]\.(?:pem|p12|pfx|key)\b"
    r"|\bcredentials?\b|\.netrc\b|\.npmrc\b|\.pypirc\b|\.git-credentials\b|\.pgpass\b"
    r"|\bwallet\.dat\b|\bkeystore\b|\bsecrets?\.(?:json|ya?ml|txt|env)\b|\.config/gcloud\b",
    re.I)

_SEG_SPLIT_RE = re.compile(r"\|\||&&|[|;&\n]|\$\(|`")
_WRAPPERS = {"sudo", "doas", "nohup", "time", "nice", "ionice", "command", "builtin", "exec", "xargs"}
_READERS = {"cat", "head", "tail", "less", "more", "strings", "bat", "nl", "ls", "stat", "cp",
            "find", "fd", "locate", "grep", "egrep", "fgrep", "rg", "ag", "ack", "awk", "sed", "tree"}
_SEARCHERS = {"find", "fd", "locate", "grep", "egrep", "fgrep", "rg", "ag", "ack"}
_ARCHIVERS = {"tar", "zip", "7z", "7za", "7zr", "rar", "cpio", "ar", "ditto"}
_ENCODERS = {"base64", "base32", "basenc", "xxd", "od", "hexdump", "uuencode", "rev", "gpg",
             "gzip", "bzip2", "xz", "zstd", "age"}
_NET_SENDERS = {"nc", "ncat", "netcat", "socat", "telnet", "ftp", "sftp"}
_CODE_TOOLS = {"execute_code", "browser_exec"}

_CODE_READ_RE = re.compile(r"\bopen\s*\(|read_text|read_bytes|readFile|glob|os\.walk|scandir|readdir", re.I)
_CODE_STAGE_RE = re.compile(r"\b(?:zipfile|tarfile)\b|make_archive|copytree|archiver\b|JSZip", re.I)
_CODE_ENCODE_RE = re.compile(
    r"b64encode|b32encode|\bbtoa\s*\(|hexlify|codecs\.encode|\.hex\s*\(\s*\)|encodeURIComponent"
    r"|zlib\.compress|gzip\.compress|Buffer\.from\([^)]*\)\.toString\(\s*['\"](?:base64|hex)", re.I)
_URL_RE = re.compile(r"https?://[^\s'\"<>)\]`]+", re.I)
_SCP_HOST_RE = re.compile(r"(?:[\w.-]+@)?([\w-]+(?:\.[\w-]+)+|[\w-]+@[\w.-]+):")


# ---------------------------------------------------------------- labels

def _home_short(text: str, home: str) -> str:
    if home and text.startswith(home + "/"):
        return "~" + text[len(home):]
    return text


def label(text: str, home: str = "") -> str:
    """A short, masked, single-line label. Never longer than LABEL_LEN."""
    t = " ".join(str(text or "").split())
    t = _home_short(t, home)
    t = alerts.redact(t, long_runs=True)
    return t[:LABEL_LEN]


def _host(url: str) -> str:
    try:
        return (urllib.parse.urlsplit(url).hostname or "")[:LABEL_LEN]
    except ValueError:
        return ""


def _first_host(text: str) -> str:
    m = _URL_RE.search(text or "")
    if m:
        return _host(m.group(0))
    m = _SCP_HOST_RE.search(text or "")
    return m.group(1)[:LABEL_LEN] if m else ""


def _cred_ref(text: str, home: str) -> str:
    """The first credential-like reference in text, shortened, or ''."""
    m = CRED_PATH_RE.search(text or "")
    if not m:
        return ""
    start = m.start()
    # widen to the surrounding word so the label shows the path, not a fragment
    left = max((text.rfind(c, 0, start + 1) for c in " \t'\"=("), default=-1) + 1
    right_cands = [i for i in (text.find(c, m.end()) for c in " \t'\")") if i != -1]
    right = min(right_cands) if right_cands else len(text)
    return label(text[left:right], home)


# ---------------------------------------------------------------- classification

def _segments(command: str) -> list:
    return [s.strip() for s in _SEG_SPLIT_RE.split(command or "") if s.strip()]


_ASSIGN_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*=")


def _first_word(seg: str) -> str:
    words = seg.split()
    skip_next = False
    for i, w in enumerate(words):
        w = w.strip("()")
        if skip_next:
            skip_next = False
            continue
        if not w or _ASSIGN_RE.match(w):
            continue  # FOO=bar prefixes
        base = os.path.basename(w)
        if base in _WRAPPERS or (base == "env" and i + 1 < len(words)):
            continue  # "env FOO=1 cmd" runs cmd; a bare "env" dumps the environment
        if base.startswith("-"):
            skip_next = base in ("-u", "-g", "-n", "-p")  # a wrapper's flag and its value
            continue
        return base.lower()
    return ""


def _classify_shell(command: str, home: str) -> list:
    out = []
    cmd = command[:16384]
    whole_cred = _cred_ref(cmd, home)
    hunt, upload = detect._hunt_and_upload(cmd)
    if detect._REMOTE_DEST_RE.search(cmd):
        upload = True
    seen = set()
    for seg in _segments(cmd):
        name = _first_word(seg)
        if not name:
            continue
        seg_cred = _cred_ref(seg, home)
        if RECON not in seen and (
                (name in _READERS and seg_cred)
                or (name in _SEARCHERS and (detect._CRED_NAME_RE.search(seg) or detect.SECRET_RE.search(seg)))
                or (name in ("env", "printenv") and len(seg.split()) == 1)):
            out.append((RECON, f"{name} {seg_cred}".strip() if seg_cred else
                        (f"{name} (environment)" if name in ("env", "printenv") else f"{name} (secret search)"),
                        True))
            seen.add(RECON)
        if STAGING not in seen and (
                name in _ARCHIVERS
                or (name == "rsync" and not detect._REMOTE_DEST_RE.search(seg))
                or (name == "cp" and re.search(r"\s-[a-zA-Z]*[rRa]", seg))):
            out.append((STAGING, f"{name} {seg_cred}".strip() if seg_cred else name, bool(seg_cred or whole_cred)))
            seen.add(STAGING)
        if ENCODING not in seen and (
                name in _ENCODERS
                or (name == "openssl" and re.search(r"\b(?:enc|base64)\b", seg))):
            out.append((ENCODING, f"{name} {whole_cred}".strip() if whole_cred else name, bool(whole_cred)))
            seen.add(ENCODING)
        if OUTBOUND not in seen and (name in _NET_SENDERS or "/dev/tcp/" in seg or "/dev/udp/" in seg):
            upload = True
    if RECON not in seen and hunt:
        out.append((RECON, whole_cred or "credential search", True))
    if upload:
        host = _first_host(cmd)
        out.append((OUTBOUND, label(f"{_first_word(cmd) or 'shell'} to {host}" if host else
                                    (_first_word(cmd) or "shell"), home), bool(whole_cred)))
    return out


def _classify_code(code: str, home: str) -> list:
    out = []
    text = code[:65536]
    cred = _cred_ref(text, home)
    hunt, upload = detect._hunt_and_upload(text)
    if hunt or (cred and _CODE_READ_RE.search(text)):
        out.append((RECON, cred or "credential search in code", True))
    if _CODE_STAGE_RE.search(text):
        out.append((STAGING, "archive in code", bool(cred)))
    if _CODE_ENCODE_RE.search(text):
        out.append((ENCODING, "encoding in code", bool(cred)))
    if upload:
        host = _first_host(text)
        out.append((OUTBOUND, label(f"upload in code to {host}" if host else "upload in code", home), bool(cred)))
    return out


def classify_call(tool_name, args, home: str = "") -> list:
    """[(type, label, touches_credentials)] for one proposed tool call. Never raises."""
    try:
        name = tool_name or ""
        a = detect._as_dict(args)
        if name == "terminal":
            cmd = a.get("command")
            return _classify_shell(cmd, home) if isinstance(cmd, str) else []
        if name in _CODE_TOOLS:
            code = a.get("code")
            return _classify_code(code, home) if isinstance(code, str) else []
        if name == "read_file":
            p = a.get("path")
            ref = _cred_ref(p, home) if isinstance(p, str) else ""
            return [(RECON, label(p, home), True)] if ref else []
        if name == "search_files":
            text = " ".join(str(a.get(k) or "") for k in ("pattern", "path"))
            if CRED_PATH_RE.search(text) or detect._CRED_NAME_RE.search(str(a.get("pattern") or "")):
                return [(RECON, label(f"search {a.get('pattern') or ''}", home), True)]
            return []
        if name == "send_message":
            return [(OUTBOUND, "send_message", False)]
        return []
    except Exception:
        return []


def call_failed(status, result) -> bool:
    """True when a finished fetch or browser call reports an error, so nothing was read."""
    try:
        if str(status or "").lower() == "error":
            return True
        data = json.loads(result) if isinstance(result, str) else result
        if not isinstance(data, dict):
            return False
        if data.get("error") or data.get("success") is False:
            return True
        results = data.get("results")
        if isinstance(results, list):
            got = [r for r in results if isinstance(r, dict) and not r.get("error")
                   and (r.get("content") or r.get("text") or r.get("title"))]
            return not got
        return False
    except (ValueError, TypeError):
        return False


def untrusted_read_event(sources, home: str = "", failed: bool = False):
    """One (type, label, False) event for the sources a finished call read (or
    tried to read, when it failed), or None."""
    try:
        if not sources:
            return None
        first = str(sources[0])
        host = _host(first) if first.startswith(("http://", "https://")) else ""
        lab = host or label(first, home)
        more = len(sources) - 1
        return (UNTRUSTED_ATTEMPT if failed else UNTRUSTED_READ,
                lab + (f" (+{more} more)" if more > 0 else ""), False)
    except Exception:
        return None


# ---------------------------------------------------------------- the log

class EventLog:
    """Per-session ring buffers of sanitized events. Thread safe, memory only."""

    def __init__(self, max_events: int = MAX_EVENTS, max_sessions: int = MAX_SESSIONS):
        self._lock = threading.Lock()
        self._sessions = OrderedDict()   # session_id -> deque of event dicts
        self._consumed = {}              # session_id -> last seq used by a correlation finding
        self._seq = 0
        self._max_events = max_events
        self._max_sessions = max_sessions

    def add(self, session_id, tool_name, events, now=None) -> list:
        """Append events; returns their sequence numbers."""
        if not session_id or not events:
            return []
        now = time.time() if now is None else now
        seqs = []
        with self._lock:
            buf = self._sessions.get(session_id)
            if buf is None:
                if len(self._sessions) >= self._max_sessions:
                    old, _ = self._sessions.popitem(last=False)
                    self._consumed.pop(old, None)
                buf = self._sessions[session_id] = deque(maxlen=self._max_events)
            else:
                self._sessions.move_to_end(session_id)
            for etype, lab, cred in events:
                if etype not in TYPES:
                    continue
                self._seq += 1
                buf.append({"seq": self._seq, "t": now, "type": etype,
                            "tool": str(tool_name or "")[:40], "label": str(lab)[:LABEL_LEN],
                            "cred": bool(cred)})
                seqs.append(self._seq)
        return seqs

    def recent(self, session_id, n: int = 8) -> list:
        with self._lock:
            buf = self._sessions.get(session_id) or ()
            return [dict(e) for e in list(buf)[-n:]] if n > 0 else []

    def since_consumed(self, session_id) -> list:
        with self._lock:
            cut = self._consumed.get(session_id, 0)
            return [dict(e) for e in (self._sessions.get(session_id) or ()) if e["seq"] > cut]

    def consume(self, session_id, seq) -> None:
        with self._lock:
            if session_id in self._sessions:
                self._consumed[session_id] = max(seq, self._consumed.get(session_id, 0))

    def count(self, session_id=None) -> int:
        with self._lock:
            if session_id is None:
                return sum(len(b) for b in self._sessions.values())
            return len(self._sessions.get(session_id) or ())


def describe(event: dict) -> str:
    """One line for incidents and alerts: time, type, tool and label."""
    when = time.strftime("%H:%M:%S", time.localtime(event.get("t", 0)))
    return f"{when}  {event.get('type', '?')} · {event.get('tool', '?')} {event.get('label', '')}".rstrip()
