"""customs detect: does a tool call touch bait?

Pure functions, no Hermes imports, so this can be tried in a plain Python
shell. pre_tool_call calls check_tool_call() on every tool call, so the rules
here are:
- no directory walks and no network;
- the only file system calls are lexists/realpath, and only for tokens whose
  file name equals a bait file name (or a folder for the bulk-copy rules),
  at most MAX_FS_CALLS per tool call;
- long inputs are cut or tokenized with a fast regex instead of shlex.
"""
from __future__ import annotations

import fnmatch
import json
import os
import posixpath
import re
import shlex
import urllib.parse
from dataclasses import dataclass, field

BLOCK_MESSAGE = ("customs blocked this action: it tried to access protected credentials. "
                 "The user has been alerted.")
APPROVE_MESSAGE = ("customs: this command would read or move a folder holding credentials. "
                   "Approve only if you asked for this.")

MAX_FS_CALLS = 50       # lexists/realpath calls per tool call
SHLEX_LIMIT = 8192      # longer commands get the regex tokenizer
MAX_TOKENS = 3000
MAX_STRINGS = 300       # strings looked at in code or generic args
MAX_STRING_LEN = 16384  # longer strings are cut
MAX_DEPTH = 2           # code inside a command inside code ...

PATH_TOOLS = {"read_file", "write_file", "patch"}
CODE_TOOLS = {"execute_code", "browser_exec"}

# Commands that only look at names or metadata. Their arguments never count,
# except redirection targets (ls > bait still writes the bait).
META_ONLY = {"ls", "ll", "la", "dir", "vdir", "stat", "du", "tree", "exa", "eza", "lsd",
             "test", "[", "[[", "realpath", "readlink", "basename", "dirname", "cd", "pushd"}
WRAPPERS = {"sudo", "doas", "env", "nohup", "time", "nice", "ionice", "command", "builtin",
            "exec", "timeout", "stdbuf", "then", "do", "else", "if", "while", "until", "!",
            "{", "}", "xargs"}
ARCHIVERS = {"tar", "zip", "7z", "7za", "7zr", "rar", "rsync", "rclone", "gsutil"}
GREPPERS = {"grep", "egrep", "fgrep", "rg", "ag", "ack", "ugrep", "find", "fd", "git"}

SECRET_RE = re.compile(
    r"AKIA|gh[opsu]_|(?<![A-Za-z])sk-|sk_live|BEGIN.{0,30}PRIVATE|private.?key|password|passwd"
    r"|secret|token|api.?key|credential", re.I)

_GLOB_CHARS = set("*?[")
_PUNCT = set("();<>|&\n")
_ASSIGN_RE = re.compile(r"(?:^|[\s;&|(])([A-Za-z_][A-Za-z0-9_]*)=(\"[^\"]*\"|'[^']*'|[^\s;&|)]+)")
_HOME_RE = re.compile(r"\$\{HOME\}|\$HOME(?![A-Za-z0-9_])")
_VAR_RE = re.compile(r"\$\{([A-Za-z_][A-Za-z0-9_]*)\}|\$([A-Za-z_][A-Za-z0-9_]*)")
_FALLBACK_TOKEN_RE = re.compile(r"""[^\s'"`;|&<>()]+""")
_STR_RE = re.compile(
    r'"""(.*?)"""|\'\'\'(.*?)\'\'\'|"((?:[^"\\\n]|\\.)*)"|\'((?:[^\'\\\n]|\\.)*)\'', re.S)
_FILE_URL_RE = re.compile(r"file://[^\s'\"<>)\]`]+")
_PATCH_FILE_RE = re.compile(r"^\*\*\* (?:Update|Add|Delete) File:\s*(.+?)\s*$|^\*\*\* Move to:\s*(.+?)\s*$",
                            re.M)
_REDIRECT_PREFIX_RE = re.compile(r"^(?:\d*>>?|&>>?|<<?<?|>\|)(.+)$")
_BRACE_RE = re.compile(r"\{([^{}]*,[^{}]*)\}")


@dataclass(frozen=True)
class Decision:
    action: str       # "block" or "approve"
    rule: str         # which rule fired
    bait_path: str    # the bait file (or a bait file inside the folder) involved
    preview: str      # what the call looked like; the caller redacts and cuts it


@dataclass
class Context:
    cwd: str                      # the session's working folder (home if unknown)
    home: str
    extra_bases: tuple = ()       # e.g. the folder the session last cd'd into
    vars: dict = field(default_factory=dict)
    fs_calls: int = 0

    def take_fs(self) -> bool:
        if self.fs_calls >= MAX_FS_CALLS:
            return False
        self.fs_calls += 1
        return True


# ---------------------------------------------------------------- bait lookup tables

class _Bait:
    def __init__(self, paths):
        self.paths = frozenset(paths)
        self.names = frozenset(posixpath.basename(p) for p in self.paths)
        self.parents = frozenset(posixpath.dirname(p) for p in self.paths)
        anc = set()
        for p in self.paths:
            d = posixpath.dirname(p)
            while True:
                anc.add(d)
                nd = posixpath.dirname(d)
                if nd == d:
                    break
                d = nd
        self.ancestors = frozenset(anc)
        self.split = tuple((p, tuple(p.split("/"))) for p in sorted(self.paths))
        self.by_name = {}
        for p in self.paths:
            self.by_name.setdefault(posixpath.basename(p), []).append(p)


_bait_cache = [None, None]


def _bait(paths) -> _Bait:
    if _bait_cache[0] is not paths:
        _bait_cache[1] = _Bait(paths)
        _bait_cache[0] = paths
    return _bait_cache[1]


# ---------------------------------------------------------------- path helpers

def _has_glob(s: str) -> bool:
    return any(c in _GLOB_CHARS for c in s)


def _expand_braces(s: str, limit: int = 32) -> list:
    out, todo = [], [s]
    while todo and len(out) + len(todo) <= limit:
        cur = todo.pop()
        m = _BRACE_RE.search(cur)
        if not m:
            out.append(cur)
            continue
        for alt in m.group(1).split(","):
            todo.append(cur[:m.start()] + alt + cur[m.end():])
    return out + todo


def _glob_match(pat_parts, parts, i=0, j=0) -> bool:
    if i == len(pat_parts):
        return j == len(parts)
    if pat_parts[i] == "**":
        return any(_glob_match(pat_parts, parts, i + 1, k) for k in range(j, len(parts) + 1))
    if j == len(parts):
        return False
    return fnmatch.fnmatchcase(parts[j], pat_parts[i]) and _glob_match(pat_parts, parts, i + 1, j + 1)


def _subst_vars(s: str, ctx: Context) -> str:
    s = _HOME_RE.sub(ctx.home, s)
    if ctx.vars and "$" in s:
        s = _VAR_RE.sub(lambda m: ctx.vars.get(m.group(1) or m.group(2), m.group(0)), s)
    return s


def normalize(token: str, base: str, ctx: Context) -> str:
    """Expand ~, $HOME and known variables, make absolute against base, normpath."""
    t = token
    if t.startswith("file://"):
        t = urllib.parse.unquote(t[7:])
        if t.startswith("localhost/"):
            t = t[9:]
    t = _subst_vars(t, ctx)
    if t == "~":
        t = ctx.home
    elif t.startswith("~/"):
        t = ctx.home + t[1:]
    if not t.startswith("/"):
        t = base.rstrip("/") + "/" + t
    return posixpath.normpath(t)


def _unresolved(token: str) -> bool:
    return "$" in token or "{" in token


def _pathish(piece: str, bait: _Bait) -> bool:
    if not piece or len(piece) > 4096:
        return False
    if "://" in piece and not piece.startswith("file://"):
        return False
    if "/" in piece or piece.startswith("~") or piece.startswith("$"):
        return True
    if piece in bait.names:
        return True
    if _has_glob(piece) or "{" in piece:
        return any(fnmatch.fnmatchcase(n, pat) for pat in _expand_braces(piece) for n in bait.names)
    return False


def _bases(token: str, ctx: Context) -> list:
    t = _subst_vars(token, ctx)
    if t.startswith(("/", "~", "file://")):
        return [ctx.cwd]
    out = [ctx.cwd]
    for b in ctx.extra_bases:
        if b and b not in out:
            out.append(b)
    return out


def match_path(cand: str, bait: _Bait, ctx: Context):
    """(how, bait path) when this absolute path is (or globs onto) bait."""
    if cand in bait.paths:
        return "path", cand
    if _has_glob(cand) or "{" in cand:
        for pat in _expand_braces(cand):
            if pat in bait.paths:
                return "path", pat
            if _has_glob(pat):
                pp = tuple(pat.split("/"))
                for p, parts in bait.split:
                    if _glob_match(pp, parts):
                        return "glob", p
        return None
    if posixpath.basename(cand) in bait.names and ctx.take_fs():
        try:
            if os.path.lexists(cand):
                real = os.path.realpath(cand)
                if real in bait.paths:
                    return "symlink", real
        except (OSError, ValueError):
            pass
    return None


def _suffix_hit(token: str, bait: _Bait):
    """A path we can't fully resolve ($VAR/old/x, {home}/old/x, old/x) whose
    last two parts or more equal a bait path's last parts."""
    parts = [p for p in token.split("/") if p not in ("", ".")]
    if len(parts) < 2 or parts[-1] not in bait.names:
        return None
    for p in bait.by_name[parts[-1]]:
        bparts = p.split("/")
        tail = parts[1:] if _unresolved(parts[0]) else parts
        if len(tail) >= 2 and bparts[-len(tail):] == tail:
            return p
    return None


def _check_piece(piece: str, bait: _Bait, ctx: Context):
    """(how, bait path) if this one token touches bait."""
    if not _pathish(piece, bait):
        return None
    for base in _bases(piece, ctx):
        hit = match_path(normalize(piece, base, ctx), bait, ctx)
        if hit:
            return hit
    if _unresolved(piece) or not piece.startswith(("/", "~")):
        p = _suffix_hit(_subst_vars(piece, ctx), bait)
        if p:
            return "suffix", p
    return None


def _pieces(tok: str) -> list:
    """The token plus the parts of it that may be paths: @path, <path, >path,
    --flag=path, name=@path;type=x, $(path), `path`."""
    out = [tok]
    m = _REDIRECT_PREFIX_RE.match(tok)
    if m:
        out.append(m.group(1))
    if "=" in tok:
        out.append(tok.split("=", 1)[1])
    more = []
    for p in out:
        q = p
        while q[:1] in ("@", "<", "(", "`", "$") and len(q) > 1 and not q.startswith(("$HOME", "${")):
            q = q[1:]
        q = q.rstrip(")`;,")
        if ";" in q:
            more.append(q.split(";", 1)[0])
        more.append(q)
    seen, res = set(), []
    for p in out + more:
        if p and p not in seen:
            seen.add(p)
            res.append(p)
    return res


# ---------------------------------------------------------------- terminal

def _tokenize(cmd: str) -> list:
    """Shell-like tokens; operators (; && || | & ( ) newline < >) are separate tokens."""
    if len(cmd) <= SHLEX_LIMIT:
        try:
            lex = shlex.shlex(cmd, posix=True, punctuation_chars="();<>|&\n")
            lex.whitespace = " \t\r"
            lex.whitespace_split = True
            lex.commenters = ""
            toks = []
            for t in lex:
                toks.append(t)
                if len(toks) >= MAX_TOKENS:
                    break
            return toks
        except ValueError:
            pass
    return _FALLBACK_TOKEN_RE.findall(cmd[:MAX_STRING_LEN * 4])[:MAX_TOKENS]


def _is_op(tok: str) -> bool:
    return bool(tok) and all(c in _PUNCT for c in tok)


def _segments(tokens: list) -> list:
    """Simple commands: [(words, redirect_targets)] split at ; && || | & ( ) newline."""
    segs, words, redirs = [], [], []
    expect_redirect = False
    for t in tokens:
        if _is_op(t):
            if "<" in t or ">" in t:
                expect_redirect = True
                continue
            if words or redirs:
                segs.append((words, redirs))
            words, redirs = [], []
            expect_redirect = False
            continue
        if expect_redirect:
            redirs.append(t)
            expect_redirect = False
        else:
            words.append(t)
    if words or redirs:
        segs.append((words, redirs))
    return segs


def _command_name(words: list):
    """(name, index of name) skipping VAR=x, sudo, env, timeout 5 ..."""
    i = 0
    while i < len(words):
        w = words[i].lstrip("`$(")
        if re.match(r"^[A-Za-z_][A-Za-z0-9_]*=", w):
            i += 1
            continue
        base = posixpath.basename(w)
        if base in WRAPPERS:
            i += 1
            while i < len(words) and (words[i].startswith("-") or
                                      (base == "timeout" and words[i][:1].isdigit())):
                i += 1
            continue
        return base, i
    return "", len(words)


def _short_flags(words) -> str:
    return "".join(w[1:] for w in words if w.startswith("-") and not w.startswith("--"))


def _dirs_with_bait(words, bait: _Bait, ctx: Context) -> list:
    """Arguments that name a folder holding bait (no walking: in-memory ancestor set)."""
    hits = []
    for w in words:
        for piece in _pieces(w):
            if not ("/" in piece or piece.startswith(("~", "$", ".")) or piece in ("*", "")):
                continue
            if "://" in piece and not piece.startswith("file://"):
                continue
            if ":" in piece.split("/")[0] and not piece.startswith(("/", "~", ".")):
                continue  # host:path (remote)
            for base in _bases(piece, ctx):
                cand = normalize(piece, base, ctx).rstrip("/") or "/"
                if cand in bait.ancestors:
                    hits.append(cand)
                    break
                if ctx.take_fs():
                    try:
                        if os.path.isdir(cand) and os.path.realpath(cand) in bait.ancestors:
                            hits.append(cand)
                            break
                    except (OSError, ValueError):
                        pass
    return hits


def _a_bait_under(d: str, bait: _Bait) -> str:
    for p in sorted(bait.paths):
        if p.startswith(d.rstrip("/") + "/"):
            return p
    return ""


def _heuristics(name: str, args: list, bait: _Bait, ctx: Context, text: str):
    """Approve-level rules for bulk copies and secret searches."""
    if name in ARCHIVERS:
        if name == "tar":
            flags = _short_flags(args) + (args[0] if args and not args[0].startswith("-") else "")
            if "c" not in flags and "r" not in flags and "u" not in flags \
                    and "--create" not in args and "--append" not in args:
                return None
        if name == "rclone" and not (set(args) & {"copy", "sync", "move", "copyto", "moveto"}):
            return None
        if name == "7z" or name.startswith("7z"):
            if not args or args[0] not in ("a", "u"):
                return None
        dirs = _dirs_with_bait(args, bait, ctx)
        if dirs:
            return Decision("approve", "bulk-copy", _a_bait_under(dirs[0], bait), text)
    if name in ("cp", "scp"):
        flags = _short_flags(args)
        if any(c in flags for c in "rRa") or "--recursive" in args or "--archive" in args:
            dirs = _dirs_with_bait(args, bait, ctx)
            if dirs:
                return Decision("approve", "bulk-copy", _a_bait_under(dirs[0], bait), text)
    if name == "curl":
        targets = []
        for i, a in enumerate(args):
            if a in ("-T", "--upload-file", "-F", "--form", "--form-string") and i + 1 < len(args):
                targets.append(args[i + 1])
            elif a.startswith(("-T", "-F")) and len(a) > 2:
                targets.append(a[2:])
            elif a.startswith(("--upload-file=", "--form=")):
                targets.append(a.split("=", 1)[1])
        dirs = _dirs_with_bait(targets, bait, ctx)
        if dirs:
            return Decision("approve", "bulk-upload", _a_bait_under(dirs[0], bait), text)
    if name in GREPPERS:
        if name == "git" and (not args or args[0] != "grep"):
            return None
        recursive = name in ("rg", "ag", "ack", "ugrep", "find", "fd", "git") or \
            any(c in _short_flags(args) for c in "rR") or "--recursive" in args or \
            "--dereference-recursive" in args
        if not recursive:
            return None
        dirs = _dirs_with_bait(args, bait, ctx)
        has_path_arg = any("/" in a or a.startswith(("~", ".", "$")) for a in args
                           if not a.startswith("-"))
        if not dirs and not has_path_arg and ctx.cwd in bait.ancestors:
            dirs = [ctx.cwd]
        if not dirs:
            return None
        if name == "find" and any(a in ("-exec", "-execdir", "-ok", "-okdir") for a in args):
            return Decision("approve", "find-exec", _a_bait_under(dirs[0], bait), text)
        if SECRET_RE.search(" ".join(args)):
            return Decision("approve", "secret-search", _a_bait_under(dirs[0], bait), text)
    return None


def _collect_assignments(cmd: str) -> dict:
    out = {}
    for m in _ASSIGN_RE.finditer(cmd[:SHLEX_LIMIT]):
        v = m.group(2)
        if len(v) >= 2 and v[0] == v[-1] and v[0] in "\"'":
            v = v[1:-1]
        out[m.group(1)] = v
    return out


def cd_targets(command: str, ctx: Context) -> list:
    """Folders a command cd's into (absolute). Used to remember the shell's cwd."""
    out = []
    try:
        for words, _r in _segments(_tokenize(command or "")):
            name, i = _command_name(words)
            if name in ("cd", "pushd") and i + 1 < len(words) and not words[i + 1].startswith("-"):
                t = words[i + 1]
                if not _unresolved(_subst_vars(t, ctx)):
                    out.append(normalize(t, ctx.cwd, ctx))
    except Exception:
        pass
    return out


def _tokens_around_names(text: str, bait: _Bait, limit: int = 40) -> list:
    """For input too long to parse fully: the tokens around every place a bait
    file name appears (a fast substring search over the whole text)."""
    out = []
    for name in bait.names:
        start = 0
        while len(out) < limit:
            i = text.find(name, start)
            if i < 0:
                break
            a, b = i, i + len(name)
            while a > 0 and a > i - 4096 and not text[a - 1].isspace() and text[a - 1] not in "'\"`;|&<>(":
                a -= 1
            while b < len(text) and b < i + 4096 and not text[b].isspace() and text[b] not in "'\"`;|&<>)":
                b += 1
            out.append(text[a:b])
            start = i + len(name)
    return out


def _long_input_hit(text: str, cut: int, bait: _Bait, ctx: Context, rule_prefix: str):
    if len(text) <= cut:
        return None
    for tok in _tokens_around_names(text, bait):
        for piece in _pieces(tok):
            hit = _check_piece(piece, bait, ctx)
            if hit:
                return Decision("block", f"{rule_prefix}-{hit[0]}", hit[1], tok)
    return None


def check_command(command: str, bait: _Bait, ctx: Context, depth: int = 0, rule_prefix="terminal"):
    """Block when a command names a bait path; approve for bulk copies and
    secret searches over a folder holding bait."""
    if not command:
        return None
    d = _long_input_hit(command, MAX_STRING_LEN * 4, bait, ctx, rule_prefix)
    if d:
        return Decision(d.action, d.rule, d.bait_path, command)
    command = command[:MAX_STRING_LEN * 4]
    ctx.vars.update(_collect_assignments(command))
    tokens = _tokenize(command)
    segs = _segments(tokens)
    saved = ctx.extra_bases
    extra = list(ctx.extra_bases)
    for words, _r in segs:  # cd targets inside this command count as bases too
        name, i = _command_name(words)
        if name in ("cd", "pushd") and i + 1 < len(words):
            extra.append(normalize(words[i + 1], ctx.cwd, ctx))
    ctx.extra_bases = tuple(extra)
    try:
        approve = None
        for words, redirs in segs:
            name, i = _command_name(words)
            args = words[i + 1:] if i < len(words) else []
            checked = list(redirs) + ([] if name in META_ONLY else words)
            for tok in checked:
                for piece in _pieces(tok):
                    hit = _check_piece(piece, bait, ctx)
                    if hit:
                        return Decision("block", f"{rule_prefix}-{hit[0]}", hit[1], command)
                if depth < MAX_DEPTH and name not in META_ONLY and \
                        any(c in tok for c in "'\"(") and len(tok) > 3:
                    d = check_code(tok, bait, ctx, depth + 1, rule_prefix)
                    if d and d.action == "block":
                        return Decision("block", d.rule, d.bait_path, command)
                    approve = approve or (d and Decision(d.action, d.rule, d.bait_path, command))
                if depth < MAX_DEPTH and name not in META_ONLY and " " in tok and tok not in (command,):
                    d = check_command(tok, bait, ctx, depth + 1, rule_prefix)
                    if d and d.action == "block":
                        return Decision("block", d.rule, d.bait_path, command)
                    approve = approve or (d and Decision(d.action, d.rule, d.bait_path, command))
            if approve is None and name:
                approve = _heuristics(name, args, bait, ctx, command)
        # ls dir | xargs cat: a listing of a bait folder fed to xargs
        if approve is None and "xargs" in tokens:
            for words, _r in segs:
                name, i = _command_name(words)
                if name in ("ls", "find", "fd"):
                    for w in words[i + 1:]:
                        if w.startswith("-"):
                            continue
                        for base in _bases(w, ctx):
                            cand = normalize(w, base, ctx)
                            if cand in bait.parents:
                                approve = Decision("approve", "listing-to-xargs",
                                                   _a_bait_under(cand, bait), command)
        return approve
    finally:
        ctx.extra_bases = saved


# ---------------------------------------------------------------- code

def _code_strings(code: str) -> list:
    out = []
    for m in _STR_RE.finditer(code[:MAX_STRING_LEN * 4]):
        s = next((g for g in m.groups() if g is not None), "")
        if s:
            out.append(s[:MAX_STRING_LEN])
        if len(out) >= MAX_STRINGS:
            break
    out.extend(_FILE_URL_RE.findall(code[:MAX_STRING_LEN * 4])[:50])
    return out


def check_code(code: str, bait: _Bait, ctx: Context, depth: int = 0, rule_prefix="code"):
    """Quoted strings and file:// URLs in code, checked like paths; strings
    that look like shell commands are checked like terminal commands."""
    d = _long_input_hit(code or "", MAX_STRING_LEN * 4, bait, ctx, rule_prefix)
    if d:
        return d
    strings = _code_strings(code or "")
    approve = None
    for s in strings:
        if any(c.isspace() for c in s):
            if depth < MAX_DEPTH:
                d = check_command(s, bait, ctx, depth + 1, rule_prefix)
                if d and d.action == "block":
                    return Decision("block", d.rule, d.bait_path, s)
                approve = approve or (d and Decision(d.action, d.rule, d.bait_path, s))
            continue
        hit = _check_piece(s, bait, ctx)
        if hit:
            return Decision("block", f"{rule_prefix}-{hit[0]}", hit[1], s)
    # os.path.join("~", "old", "id_x.old") / Path.home() / "old" / "id_x.old"
    sset = set(strings)
    for name in bait.names & sset:
        for p in bait.by_name[name]:
            parent = posixpath.basename(posixpath.dirname(p))
            if parent and parent in sset:
                return Decision("block", f"{rule_prefix}-path-parts", p, name)
    return approve


# ---------------------------------------------------------------- generic args

def _walk_strings(obj, out: list, depth: int = 0):
    if len(out) >= MAX_STRINGS or depth > 8:
        return
    if isinstance(obj, str):
        if len(obj) > MAX_STRING_LEN:  # keep what's around bait names in the cut part
            out.extend(t for t in obj[MAX_STRING_LEN:].split() if len(t) < 4096 and "/" in t)
        out.append(obj[:MAX_STRING_LEN])
    elif isinstance(obj, dict):
        for v in obj.values():
            _walk_strings(v, out, depth + 1)
    elif isinstance(obj, (list, tuple)):
        for v in obj:
            _walk_strings(v, out, depth + 1)


def check_strings(strings, bait: _Bait, ctx: Context, rule_prefix="args"):
    approve = None
    for s in strings:
        for url in _FILE_URL_RE.findall(s)[:20]:
            hit = _check_piece(url, bait, ctx)
            if hit:
                return Decision("block", f"{rule_prefix}-{hit[0]}", hit[1], url)
        if any(c.isspace() for c in s):
            d = check_command(s, bait, ctx, 1, rule_prefix)
            if d and d.action == "block":
                return Decision("block", d.rule, d.bait_path, s)
            approve = approve or d
            continue
        hit = _check_piece(s, bait, ctx)
        if hit:
            return Decision("block", f"{rule_prefix}-{hit[0]}", hit[1], s)
    return approve


# ---------------------------------------------------------------- entry point

def _as_dict(args):
    if isinstance(args, dict):
        return args
    if isinstance(args, str):
        try:
            v = json.loads(args)
            return v if isinstance(v, dict) else {"value": v}
        except ValueError:
            return {"value": args}
    return {"value": args} if args is not None else {}


def check_tool_call(tool_name, args, bait_paths, ctx: Context):
    """Decision or None. bait_paths is BaitIndex.paths (a frozenset)."""
    if not bait_paths:
        return None
    bait = _bait(bait_paths)
    args = _as_dict(args)
    name = tool_name or ""

    if name in PATH_TOOLS:
        path = args.get("path")
        if isinstance(path, str) and path:
            hit = _check_piece(path, bait, ctx)
            if hit is None and path.strip():
                # the path tools take the path literally: check it even if it doesn't look pathish
                cand = normalize(path.strip(), ctx.cwd, ctx)
                hit = match_path(cand, bait, ctx)
            if hit:
                return Decision("block", f"{name}-{hit[0]}", hit[1], path)
        patch_text = args.get("patch")
        if isinstance(patch_text, str):
            for m in _PATCH_FILE_RE.finditer(patch_text[:MAX_STRING_LEN * 8]):
                p = (m.group(1) or m.group(2) or "").strip()
                hit = p and match_path(normalize(p, ctx.cwd, ctx), bait, ctx)
                if hit:
                    return Decision("block", f"patch-file-{hit[0]}", hit[1], p)
        return None

    if name == "terminal":
        wd = args.get("workdir")
        if isinstance(wd, str) and wd.strip():
            ctx.cwd = normalize(wd.strip(), ctx.cwd, ctx)
        cmd = args.get("command")
        return check_command(cmd, bait, ctx) if isinstance(cmd, str) else None

    if name in CODE_TOOLS:
        code = args.get("code")
        if not isinstance(code, str):
            code = args.get("command") if isinstance(args.get("command"), str) else ""
        return check_code(code, bait, ctx)

    if name == "search_files":
        path = args.get("path") if isinstance(args.get("path"), str) else "."
        cand = normalize(path or ".", ctx.cwd, ctx)
        hit = match_path(cand, bait, ctx)
        if hit:
            return Decision("block", f"search_files-{hit[0]}", hit[1], path)
        pattern = args.get("pattern") if isinstance(args.get("pattern"), str) else ""
        target = args.get("target") or "content"
        if target == "content" and cand.rstrip("/") in bait.ancestors and SECRET_RE.search(pattern):
            return Decision("approve", "secret-search", _a_bait_under(cand, bait),
                            f"search {pattern!r} in {path}")
        return None

    strings = []
    _walk_strings(args, strings)
    return check_strings(strings, bait, ctx)
