"""customs provenance: the untrusted things each session read recently.

Pure Python, no Hermes imports. Kept in memory, with a small cache file in
the data folder so it survives a gateway restart. Sessions idle for more than
24 hours are dropped. Sources are stored without query strings or fragments
(those can carry tokens), and cut to 300 characters.
"""
from __future__ import annotations

import json
import os
import re
import threading
import time
import urllib.parse
from collections import deque
from pathlib import Path

CACHE_NAME = "provenance.json"
PER_SESSION = 10
IDLE_SECONDS = 24 * 3600
MAX_SESSIONS = 500
NONE_SEEN = "none seen"
LOCAL_SOURCE = "local (not linked to a remote source)"
MAX_WRITES = 50

_URL_RE = re.compile(r"""(?:https?|file)://[^\s'"()<>\]\[`{}|\\^]+""")
FETCHERS = {"curl", "wget", "aria2c", "http", "https", "xh", "lynx", "links", "w3m"}


def clean_url(url: str) -> str:
    """scheme://host/path, no user info, query or fragment."""
    try:
        p = urllib.parse.urlsplit(url.strip().rstrip(".,;)'\""))
        if p.scheme == "file":
            return ("file://" + p.path)[:300]
        host = p.hostname or ""
        if p.port:
            host += f":{p.port}"
        return f"{p.scheme}://{host}{p.path}"[:300]
    except ValueError:
        return url[:120]


def urls_in(text: str, limit: int = 20) -> list:
    out = []
    for u in _URL_RE.findall(text or "")[:limit]:
        c = clean_url(u)
        if c not in out:
            out.append(c)
    return out


def _under(path: str, root: str) -> bool:
    root = root.rstrip("/")
    return path == root or path.startswith(root + "/")


_CLONE_RE = re.compile(r"\bgit\b[^\n;&|]*\bclone\b([^\n;&|]*)", re.I)


def parse_git_clone(command: str, home: str, cwd: str):
    """(clean url, target dir abs path) for a `git clone`, or None."""
    m = _CLONE_RE.search(command or "")
    if not m:
        return None
    args = [a for a in m.group(1).split() if a and not a.startswith("-")]
    url = next((a for a in args if "://" in a or "@" in a or a.endswith(".git")), None)
    if not url:
        return None
    rest = [a for a in args if a != url]
    if rest:
        target = rest[-1]
        tdir = os.path.expanduser(target)
        if not tdir.startswith("/"):
            tdir = os.path.join(cwd or home, tdir)
    else:  # default dir is the repo name
        name = url.rstrip("/").split("/")[-1]
        if name.endswith(".git"):
            name = name[:-4]
        tdir = os.path.join(cwd or home, name)
    return clean_url(url), os.path.normpath(tdir)


_DOWNLOAD_RE = re.compile(
    r"\b(?:curl\b[^\n;&|]*?(?:\s-o\s*|\s--output[\s=])(\S+)|wget\b[^\n;&|]*?(?:\s-O\s*|\s--output-document[\s=])(\S+))")
_REDIRECT_RE = re.compile(r"(?:^|[^0-9&<>])>>?\s*([^\s;&|<>()]+)|\btee\s+(?:-a\s+)?([^\s;&|<>()]+)")
_PATCH_FILE_RE = re.compile(r"^\*\*\* (?:Add|Update) File:\s*(.+?)\s*$|^\*\*\* Move to:\s*(.+?)\s*$", re.M)


def _abs(path: str, home: str, cwd: str) -> str:
    q = os.path.expanduser(path.strip().strip("'\""))
    if q.startswith("~"):
        q = home + q[1:]
    if not q.startswith("/"):
        q = os.path.join(cwd or home, q)
    return os.path.normpath(q)


def parse_writes(tool_name, args, *, home, cwd) -> list:
    """Files a finished tool call wrote: [(abs path, url it was downloaded from or None)]."""
    a = args if isinstance(args, dict) else {}
    out = []
    if tool_name in ("write_file", "patch"):
        if isinstance(a.get("path"), str) and a["path"].strip():
            out.append((_abs(a["path"], home, cwd), None))
        if isinstance(a.get("patch"), str):
            for m in _PATCH_FILE_RE.finditer(a["patch"][:200000]):
                p = (m.group(1) or m.group(2) or "").strip()
                if p:
                    out.append((_abs(p, home, cwd), None))
    elif tool_name == "terminal":
        cmd = a.get("command")
        wd = a.get("workdir")
        base = _abs(wd, home, cwd) if isinstance(wd, str) and wd.strip() else cwd
        if isinstance(cmd, str):
            cmd = cmd[:65536]
            for m in _DOWNLOAD_RE.finditer(cmd):
                target = m.group(1) or m.group(2)
                if target and target != "-":
                    urls = urls_in(cmd[m.start():m.start() + 4096])
                    out.append((_abs(target, home, base), urls[0] if urls else None))
            for m in _REDIRECT_RE.finditer(cmd):
                target = m.group(1) or m.group(2)
                if target and not target.startswith(("/dev/", "&")):
                    out.append((_abs(target, home, base), None))
    seen, res = set(), []
    for path, url in out:
        if path not in seen:
            seen.add(path)
            res.append((path, url))
    return res[:20]


def sources_for(tool_name, args, result, *, home, cwd, untrusted_tool=False) -> list:
    """The untrusted sources one finished tool call brought into the session."""
    name = tool_name or ""
    a = args if isinstance(args, dict) else {}
    out = []
    if name == "web_extract":
        urls = a.get("urls")
        for u in (urls if isinstance(urls, list) else [urls] if isinstance(urls, str) else []):
            if isinstance(u, str):
                out.append(clean_url(u))
        try:  # the URLs actually fetched (after redirects)
            data = json.loads(result) if isinstance(result, str) else {}
            for r in (data.get("results") or [])[:20] if isinstance(data, dict) else []:
                if isinstance(r, dict) and isinstance(r.get("url"), str):
                    out.append(clean_url(r["url"]))
        except (ValueError, TypeError, AttributeError):
            pass
    elif name == "browser_exec" or name.startswith("browser_"):
        for key in ("code", "url"):
            if isinstance(a.get(key), str):
                out.extend(urls_in(a[key]))
    elif name == "read_file":
        p = a.get("path")
        if isinstance(p, str) and p:
            q = os.path.expanduser(p)
            if not q.startswith("/"):
                q = os.path.join(cwd or home, q)
            q = os.path.normpath(q)
            roots = [os.path.join(home, "Downloads"), "/tmp",
                     os.path.join(home, ".hermes", "cache", "browser-use", "workspace")]
            if any(_under(q, r) for r in roots):
                out.append(q[:300])
    elif name == "terminal":
        cmd = a.get("command")
        if isinstance(cmd, str):
            clone = parse_git_clone(cmd, home, cwd)
            if clone:
                out.append(clone[0])
            if any(re.search(rf"(?:^|[\s;&|(`]){re.escape(f)}\b", cmd) for f in FETCHERS):
                out.extend(urls_in(cmd))
    elif untrusted_tool:
        out.append(f"tool:{name}"[:300])
    seen, res = set(), []
    for s in out:
        if s and s not in seen:
            seen.add(s)
            res.append(s)
    return res


def call_failed(status, result) -> bool:
    """True when a finished call reports that it failed, so nothing was read and
    it must not become a likely source: an error status, an error or
    success=false in the result, a web fetch whose results all failed or came
    back empty, a non-zero exit code, or a file that wasn't found."""
    try:
        if str(status or "").lower() == "error":
            return True
        data = json.loads(result) if isinstance(result, str) else result
        if not isinstance(data, dict):
            return False
        if data.get("error") or data.get("success") is False or data.get("not_found") is True:
            return True
        code = data.get("exit_code")
        if isinstance(code, int) and not isinstance(code, bool) and code != 0:
            return True
        results = data.get("results")
        if isinstance(results, list):
            got = [r for r in results if isinstance(r, dict) and not r.get("error")
                   and (r.get("content") or r.get("text") or r.get("title"))]
            return not got
        return False
    except (ValueError, TypeError):
        return False


class Provenance:
    def __init__(self):
        self._lock = threading.Lock()
        self._sessions = {}  # session_id -> {"seen": t, "items": deque}
        self._path = None

    # ---- persistence
    def load(self, data_dir) -> None:
        try:
            self._path = Path(data_dir) / CACHE_NAME
            raw = json.loads(self._path.read_text(encoding="utf-8"))
            now = time.time()
            with self._lock:
                for sid, s in (raw.get("sessions") or {}).items():
                    if now - float(s.get("seen", 0)) > IDLE_SECONDS:
                        continue
                    items = [i for i in s.get("items", []) if isinstance(i, dict)][-PER_SESSION:]
                    clones = [c for c in s.get("clones", []) if isinstance(c, list) and len(c) == 2][-30:]
                    writes = [w for w in s.get("writes", []) if isinstance(w, list) and len(w) == 2]
                    self._sessions[sid] = {"seen": float(s.get("seen", now)),
                                           "items": deque(items, maxlen=PER_SESSION),
                                           "clones": clones, "writes": writes[-MAX_WRITES:]}
        except (OSError, ValueError, TypeError, AttributeError):
            pass

    def _save_locked(self) -> None:
        if self._path is None:
            return
        data = {"sessions": {sid: {"seen": s["seen"], "items": list(s["items"]),
                                   "clones": s.get("clones", []), "writes": s.get("writes", [])}
                             for sid, s in self._sessions.items()}}
        tmp = self._path.with_name(f".{self._path.name}.{os.getpid()}.tmp")
        fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            json.dump(data, fh)
        os.replace(tmp, self._path)

    def _prune_locked(self, now: float) -> None:
        for sid in [sid for sid, s in self._sessions.items() if now - s["seen"] > IDLE_SECONDS]:
            del self._sessions[sid]
        while len(self._sessions) > MAX_SESSIONS:
            oldest = min(self._sessions, key=lambda k: self._sessions[k]["seen"])
            del self._sessions[oldest]

    # ---- use
    def add(self, session_id, tool_name, sources, tool_call_id="", turn_id="") -> None:
        if not session_id or not sources:
            return
        now = time.time()
        with self._lock:
            s = self._sessions.setdefault(session_id,
                                          {"seen": now, "items": deque(maxlen=PER_SESSION), "clones": []})
            s["seen"] = now
            for src in sources:
                s["items"].append({"time": time.strftime("%Y-%m-%dT%H:%M:%S%z"),
                                   "tool_name": str(tool_name or ""), "source": src,
                                   "tool_call_id": str(tool_call_id or ""),
                                   "turn_id": str(turn_id or "")})
            self._prune_locked(now)
            try:
                self._save_locked()
            except OSError:
                pass

    def latest(self, session_id) -> str:
        with self._lock:
            s = self._sessions.get(session_id or "")
            if not s or not s["items"]:
                return NONE_SEEN
            return s["items"][-1]["source"]

    def recent(self, session_id) -> list:
        with self._lock:
            s = self._sessions.get(session_id or "")
            return list(s["items"]) if s else []

    def note_clone(self, session_id, url, dirpath) -> None:
        if not session_id or not url or not dirpath:
            return
        now = time.time()
        with self._lock:
            s = self._sessions.setdefault(session_id,
                                          {"seen": now, "items": deque(maxlen=PER_SESSION), "clones": []})
            s["seen"] = now
            clones = s.setdefault("clones", [])
            if [dirpath, url] not in clones:
                clones.append([dirpath, url])
                del clones[:-30]
            try:
                self._save_locked()
            except OSError:
                pass

    def note_writes(self, session_id, writes, turn_id="") -> None:
        """Remember files the agent wrote. A write is linked to a remote source
        only if it was downloaded from it, or happened in the same user turn as
        an untrusted read (the most recent one in that turn)."""
        if not session_id or not writes:
            return
        now = time.time()
        with self._lock:
            s = self._sessions.setdefault(session_id,
                                          {"seen": now, "items": deque(maxlen=PER_SESSION),
                                           "clones": [], "writes": []})
            s["seen"] = now
            same_turn = ""
            if turn_id:
                for it in reversed(s["items"]):
                    if it.get("turn_id") == turn_id:
                        same_turn = it["source"]
                        break
            w = s.setdefault("writes", [])
            for path, url in writes:
                w[:] = [x for x in w if x[0] != path]
                w.append([path, url or same_turn or ""])
            del w[:-MAX_WRITES]
            try:
                self._save_locked()
            except OSError:
                pass

    def source_for_script(self, session_id, path, home) -> str:
        """Likely source for a blocked local script, or LOCAL_SOURCE when the
        script isn't plausibly linked to anything remote this session read."""
        if not path:
            return LOCAL_SOURCE
        p = os.path.normpath(path)
        repo = self.source_for_path(session_id, p)
        if repo:
            return repo
        with self._lock:
            s = self._sessions.get(session_id or "")
            for wpath, linked in reversed(s.get("writes", []) if s else []):
                if wpath == p:
                    return linked or LOCAL_SOURCE
        roots = [os.path.join(home, "Downloads"), "/tmp",
                 os.path.join(home, ".hermes", "cache", "browser-use", "workspace")]
        if any(_under(p, r) for r in roots):
            latest = self.latest(session_id)
            return latest if latest != NONE_SEEN else LOCAL_SOURCE
        return LOCAL_SOURCE

    def source_for_path(self, session_id, path):
        """The clone URL of the repo a path lives in, if this session cloned it."""
        if not session_id or not path:
            return None
        p = os.path.normpath(path)
        with self._lock:
            s = self._sessions.get(session_id)
            best = None
            for dirpath, url in (s.get("clones", []) if s else []):
                if _under(p, dirpath) and (best is None or len(dirpath) > len(best[0])):
                    best = (dirpath, url)
            return best[1] if best else None
