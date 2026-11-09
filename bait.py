"""customs bait: fake secrets, bait files and the registry that remembers them.

No Hermes imports here. Functions take the plugin's data folder as an
argument, so this file can be tried by hand in a plain Python shell.

Safety rules this file follows:
- A bait file is only ever created where nothing exists. Creation uses
  O_CREAT | O_EXCL | O_NOFOLLOW, so it never overwrites a file or follows a
  symlink, even if something appears at that path at the same moment.
- Bait only goes under the home folder, never through a symlink that leads
  out of it, never under /mnt, never at a name tools load automatically, and
  inside a git repository only where git already ignores the path.
- Unplant only deletes regular files that are in the registry and still hold
  the values written into them.
- Every bait file gets its own fake values, so a leak names the file.
- The registry stores the fake values, so it is written with mode 600.
"""
from __future__ import annotations

import base64
import contextlib
import json
import os
import secrets
import stat
import string
import struct
import subprocess
import threading
import time
import urllib.parse
from dataclasses import dataclass, field, replace
from pathlib import Path

REGISTRY_NAME = "bait.json"
REGISTRY_VERSION = 2
V1_BACKUP_NAME = "bait.v1-backup.json"
BLEND_EXCLUDE_NAME = "blend-exclude.txt"
MAX_BAIT = 100
MAX_READ = 64 * 1024  # never read more than this from a bait path
GIT_TIMEOUT = 3

_rng = secrets.SystemRandom()

TYPES = ("env", "aws", "ssh", "db", "json", "github")
TYPE_LABELS = {
    "env": "env file",
    "aws": "AWS credentials",
    "ssh": "SSH private key",
    "db": "database credentials",
    "json": "JSON config",
    "github": "GitHub token note",
}

# ---------------------------------------------------------------- name rules

# Exact names that tools load on their own. Bait never uses these.
AUTOLOAD_NAMES = {
    ".env", ".env.local", ".env.development", ".env.production", ".env.test",
    ".env.development.local", ".env.production.local", ".env.test.local", ".envrc",
    ".npmrc", ".pypirc", ".netrc", ".pgpass", ".git-credentials", ".gitconfig",
    ".yarnrc", ".yarnrc.yml", ".bashrc", ".profile", ".zshrc", ".bash_profile",
    "credentials", "config", "id_rsa", "id_dsa", "id_ecdsa", "id_ecdsa_sk",
    "id_ed25519", "id_ed25519_sk", "authorized_keys", "known_hosts",
}
BACKUP_MARKERS = (".bak", ".old", ".backup", ".save", "-copy")


def is_backup_style(name: str) -> bool:
    low = name.lower()
    return any(m in low for m in BACKUP_MARKERS)


def name_problem(name: str, strict: bool = False):
    """Why this file name can't be bait, or None. strict also demands a
    backup-style name (used for every name customs picks itself)."""
    if not name or name in (".", "..") or "/" in name or "\x00" in name:
        return "that isn't a usable file name"
    low = name.lower()
    if low in AUTOLOAD_NAMES:
        return f"tools load '{name}' automatically, so customs never uses that name"
    if low.startswith(".env") and not is_backup_style(low):
        return (f"tools may load '{name}' automatically; use a backup-style name "
                "such as .env.bak")
    if strict and not is_backup_style(low):
        return "not a backup-style name"
    return None


# ---------------------------------------------------------------- name and folder pools

NAME_POOL = {
    "env": [".env.bak", ".env.old", ".env.backup", ".env.save", ".env.production.bak",
            ".env.prod.old", ".env.staging.backup", "env-copy.txt", "production.env.bak"],
    "aws": ["credentials.bak", "credentials.old", "credentials-copy", "aws-credentials.bak",
            "aws_keys.old.txt", "credentials.backup"],
    "ssh": ["id_rsa.old", "id_rsa.bak", "id_ed25519.old", "id_rsa-copy", "deploy_key.bak",
            "id_rsa.backup", "server-key.pem.bak"],
    "db": ["prod-db-credentials.old.txt", "db-passwords.old.txt", "database.bak.txt",
           "postgres-prod.txt.bak", "db_creds-copy.txt", "prod-db.backup.txt", "pgpass.old"],
    "json": ["config.old.json", "secrets.bak.json", "credentials.backup.json",
             "service-account.old.json", "settings-copy.json", "config.backup.json",
             "keys.save.json", "app-secrets.bak.json"],
    "github": ["github-token.txt.bak", "gh-token.old", "github_pat-copy.txt",
               "git-token.backup.txt", "deploy-token.old.txt", "github-recovery.bak.txt",
               "gh_pat.save.txt"],
}

GENERAL_DIRS = ["", "backup", "backups", "old", "archive", "Documents/keys", "Documents/old",
                "dev/old-configs", "projects/archive", "old-laptop"]
CONFIG_APPS = ["gh", "docker", "heroku", "vercel", "stripe", "gcloud", "netlify",
               "supabase", "fly", "railway"]
TYPE_DIRS = {
    "aws": [".aws", "backup", "backups", "old", "archive", "Documents/keys"],
    "ssh": [".ssh", "backup", "old", "archive", "Documents/keys"],
}


def _folders_for(btype: str) -> list:
    if btype in TYPE_DIRS:
        return list(TYPE_DIRS[btype])
    return GENERAL_DIRS + [f".config/{app}-backup" for app in CONFIG_APPS]


# ---------------------------------------------------------------- fake values

_ALNUM = string.ascii_letters + string.digits
_B64_CHARS = string.ascii_letters + string.digits + "+/"
_AWS_ID_CHARS = string.ascii_uppercase + "234567"  # the set real AWS key ids use

DB_HOSTS = ["prod-db.internal", "db-primary.internal", "pg-main.internal",
            "postgres.prod.internal", "billing-db.internal"]  # .internal is reserved
DB_USERS = ["prod_admin", "app_prod", "postgres_admin", "svc_billing", "deploy"]
DB_NAMES = ["production", "app_prod", "billing", "main"]
GH_ACCOUNTS = ["deploy-bot", "ci-runner", "release-bot", "ops-automation", "build-svc"]


def _rand(alphabet: str, n: int) -> str:
    return "".join(_rng.choice(alphabet) for _ in range(n))


def _aws():
    return "AKIA" + _rand(_AWS_ID_CHARS, 16), _rand(_B64_CHARS, 40)


def _db():
    pw = _rand(_ALNUM, 24)
    host, user, name = _rng.choice(DB_HOSTS), _rng.choice(DB_USERS), _rng.choice(DB_NAMES)
    return pw, host, user, name, f"postgres://{user}:{pw}@{host}:5432/{name}"


def _ssh_string(data: bytes) -> bytes:
    return struct.pack(">I", len(data)) + data


def _fake_openssh_key() -> str:
    """Looks like an unencrypted OpenSSH key: the real header, then random bytes."""
    body = (b"openssh-key-v1\x00" + _ssh_string(b"none") + _ssh_string(b"none")
            + _ssh_string(b"") + struct.pack(">I", 1) + secrets.token_bytes(1860))
    b64 = base64.b64encode(body).decode("ascii")
    lines = [b64[i:i + 70] for i in range(0, len(b64), 70)]
    return ("-----BEGIN OPENSSH PRIVATE KEY-----\n" + "\n".join(lines)
            + "\n-----END OPENSSH PRIVATE KEY-----\n")


def make_bait(btype: str):
    """Fresh fake values and the file text for one bait file. Returns (values, text).
    Only the values are stored; the text is written once and never rebuilt."""
    if btype == "env":
        key_id, secret = _aws()
        pw, _h, _u, _n, url = _db()
        v = {"postgres_url": url, "postgres_password": pw, "aws_access_key_id": key_id,
             "aws_secret_access_key": secret, "stripe_key": "sk_live_" + _rand(_ALNUM, 24),
             "openai_key": "sk-proj-" + _rand(_ALNUM, 48), "github_token": "ghp_" + _rand(_ALNUM, 36)}
        text = ("NODE_ENV=production\n"
                f"DATABASE_URL={url}\n"
                f"AWS_ACCESS_KEY_ID={key_id}\n"
                f"AWS_SECRET_ACCESS_KEY={secret}\n"
                "AWS_DEFAULT_REGION=us-east-1\n"
                f"STRIPE_SECRET_KEY={v['stripe_key']}\n"
                f"OPENAI_API_KEY={v['openai_key']}\n"
                f"GITHUB_TOKEN={v['github_token']}\n")
        return v, text
    if btype == "aws":
        key_id, secret = _aws()
        return ({"aws_access_key_id": key_id, "aws_secret_access_key": secret},
                f"[default]\naws_access_key_id = {key_id}\naws_secret_access_key = {secret}\n")
    if btype == "ssh":
        key = _fake_openssh_key()
        # A full 70 character line from the random part of the body. That's what
        # gets watched, since the whole key is wrapped over many lines.
        return {"ssh_key_fragment": key.splitlines()[3]}, key
    if btype == "db":
        pw, host, user, name, url = _db()
        text = ("Production database (primary)\n"
                f"host: {host}\nport: 5432\ndatabase: {name}\n"
                f"username: {user}\npassword: {pw}\nurl: {url}\n")
        return {"postgres_password": pw, "postgres_url": url}, text
    if btype == "json":
        key_id, secret = _aws()
        pw, host, user, name, _url = _db()
        v = {"postgres_password": pw, "aws_access_key_id": key_id, "aws_secret_access_key": secret,
             "stripe_key": "sk_live_" + _rand(_ALNUM, 24),
             "openai_key": "sk-proj-" + _rand(_ALNUM, 48)}
        doc = {
            "environment": "production",
            "database": {"host": host, "port": 5432, "name": name, "user": user, "password": pw},
            "aws": {"access_key_id": key_id, "secret_access_key": secret, "region": "us-east-1"},
            "stripe": {"secret_key": v["stripe_key"]},
            "openai": {"api_key": v["openai_key"]},
        }
        return v, json.dumps(doc, indent=2) + "\n"
    if btype == "github":
        token = "ghp_" + _rand(_ALNUM, 36)
        made = time.strftime("%Y-%m-%d", time.gmtime(time.time() - _rng.randint(60, 700) * 86400))
        text = ("GitHub personal access token (classic)\n"
                f"account: {_rng.choice(GH_ACCOUNTS)}\n"
                "scopes: repo, workflow, admin:org\n"
                f"created: {made}\n"
                "expires: never\n"
                f"token: {token}\n")
        return {"github_token": token}, text
    raise ValueError(f"unknown bait type {btype!r}")


def encoded_variants(value: str) -> dict:
    raw = value.encode("utf-8")
    return {
        "base64": base64.b64encode(raw).decode("ascii"),
        "hex": raw.hex(),
        "url": urllib.parse.quote(value, safe=""),
        "reversed": value[::-1],
    }


def infer_type(name: str) -> str:
    low = name.lower()
    if low.endswith(".json") or ".json." in low:
        return "json"
    if ".env" in low or low.startswith("env"):
        return "env"
    if any(k in low for k in ("id_rsa", "id_ed25519", "id_ecdsa", "ssh", ".pem", "_key", "-key")):
        return "ssh"
    if "aws" in low or "credentials" in low:
        return "aws"
    if any(k in low for k in ("github", "gh_", "gh-", "token", "pat")):
        return "github"
    if any(k in low for k in ("db", "database", "postgres", "sql", "pass")):
        return "db"
    return "env"


# ---------------------------------------------------------------- registry

def registry_path(data_dir) -> Path:
    return Path(data_dir) / REGISTRY_NAME


def _now() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%S%z")


def _empty_registry() -> dict:
    return {"version": REGISTRY_VERSION, "created": _now(), "files": {}, "created_dirs": []}


# Phase 1 kept one shared set of values; these are the ones each file held.
_V1_FILE_VALUES = {
    "env": ["postgres_url", "postgres_password", "aws_access_key_id", "aws_secret_access_key",
            "stripe_key", "openai_key", "github_token"],
    "aws": ["aws_access_key_id", "aws_secret_access_key"],
    "ssh": ["ssh_key_fragment"],
    "db": ["postgres_password", "postgres_url"],
}


def _migrate(reg: dict):
    """Returns (v2 registry, migrated?)."""
    if reg.get("version") == REGISTRY_VERSION:
        reg.setdefault("files", {})
        reg.setdefault("created_dirs", [])
        return reg, False
    if reg.get("version", 1) != 1 or not isinstance(reg.get("values"), dict):
        raise RuntimeError("bait registry has an unknown format")
    shared = reg["values"]
    files = {}
    for path, entry in (reg.get("files") or {}).items():
        kind = (entry or {}).get("kind")
        files[path] = {
            "type": kind,
            "origin": "default",
            "planted": (entry or {}).get("planted", ""),
            "values": {n: shared[n] for n in _V1_FILE_VALUES.get(kind, []) if shared.get(n)},
            "migrated_from": 1,
        }
    return {"version": REGISTRY_VERSION, "created": reg.get("created", _now()),
            "files": files, "created_dirs": list(reg.get("created_dirs") or [])}, True


def _read_registry_file(path: Path):
    """The raw registry dict, or None when there is none. Raises RuntimeError
    when it exists but can't be read, so a damaged registry is never replaced
    with new values by accident."""
    try:
        with open(path, encoding="utf-8") as fh:
            raw = json.load(fh)
    except FileNotFoundError:
        return None
    except (OSError, ValueError) as exc:
        raise RuntimeError(f"bait registry at {path} can't be read ({exc.__class__.__name__}). "
                           "Move it aside by hand if you want a fresh one.") from exc
    if not isinstance(raw, dict):
        raise RuntimeError(f"bait registry at {path} has an unexpected shape.")
    return raw


def load_registry(data_dir) -> dict:
    """The registry in the current format (migrated in memory if needed)."""
    raw = _read_registry_file(registry_path(data_dir))
    if raw is None:
        return _empty_registry()
    return _migrate(raw)[0]


def _write_private_json(path: Path, obj) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_name(f".{path.name}.{os.getpid()}.tmp")
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            json.dump(obj, fh, indent=2)
            fh.flush()
            os.fsync(fh.fileno())
        os.chmod(tmp, 0o600)
        os.replace(tmp, path)
    except Exception:
        with contextlib.suppress(OSError):
            os.unlink(tmp)
        raise


def save_registry(data_dir, reg: dict) -> None:
    _write_private_json(registry_path(data_dir), reg)


@contextlib.contextmanager
def _locked_registry(data_dir):
    """Lock, load (migrating a Phase 1 registry and keeping a backup of it),
    yield the registry, and save it afterwards."""
    Path(data_dir).mkdir(parents=True, exist_ok=True)
    with open(Path(data_dir) / ".bait.lock", "a+") as fh:
        try:
            import fcntl
            fcntl.flock(fh.fileno(), fcntl.LOCK_EX)
        except Exception:
            pass  # no fcntl: carry on without the lock
        raw = _read_registry_file(registry_path(data_dir))
        if raw is None:
            reg = _empty_registry()
        else:
            reg, migrated = _migrate(raw)
            if migrated:
                backup = Path(data_dir) / V1_BACKUP_NAME
                if not backup.exists():
                    _write_private_json(backup, raw)
                save_registry(data_dir, reg)
        try:
            yield reg
        finally:
            save_registry(data_dir, reg)


# ---------------------------------------------------------------- path checks

def _home() -> str:
    return os.path.normpath(os.path.expanduser("~"))


def _under(path: str, root: str) -> bool:
    root = root.rstrip(os.sep) or os.sep
    return path == root or path.startswith(root + os.sep)


def _nearest_existing(path: str) -> str:
    while not os.path.lexists(path):
        parent = os.path.dirname(path)
        if parent == path:
            break
        path = parent
    return path


def normalize(raw: str) -> str:
    """Expand ~; relative paths count from the home folder."""
    p = os.path.expanduser(raw.strip())
    if not os.path.isabs(p):
        p = os.path.join(_home(), p)
    return os.path.normpath(p)


def location_problem(path: str):
    home = _home()
    if not _under(path, home) or path == home:
        return "it's outside your home folder"
    if _under(path, "/mnt"):
        return "it's under /mnt"
    near = _nearest_existing(os.path.dirname(path))
    real = os.path.realpath(near)
    if not _under(real, os.path.realpath(home)) or _under(real, "/mnt"):
        return "its folder leads outside your home folder through a symlink"
    if not os.path.isdir(near):
        return "a file is in the way of its folder"
    return None


def _git_root(path: str):
    home = _home()
    cur = _nearest_existing(os.path.dirname(path))
    while _under(cur, home):
        if os.path.lexists(os.path.join(cur, ".git")):
            return cur
        if cur == home:
            break
        cur = os.path.dirname(cur)
    return None


def git_problem(path: str):
    """Inside a git repository, the path must already be ignored by git."""
    root = _git_root(path)
    if root is None:
        return None
    env = {k: v for k, v in os.environ.items() if not k.startswith("GIT_")}
    try:
        r = subprocess.run(["git", "-C", root, "check-ignore", "-q", "--", path],
                           stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                           stderr=subprocess.DEVNULL, timeout=GIT_TIMEOUT, env=env)
    except FileNotFoundError:
        return "it's inside a git repository and git isn't installed to check it"
    except subprocess.TimeoutExpired:
        return "it's inside a git repository and git took too long to answer"
    if r.returncode == 0:
        return None
    if r.returncode == 1:
        return "it's inside a git repository that doesn't ignore it"
    return "it's inside a git repository and git couldn't check it"


def spot_problem(path: str, reg: dict, strict: bool, taken=()):
    """Why bait can't go at this absolute path, or None."""
    if path in taken or path in reg["files"]:
        return "already customs bait"
    if os.path.lexists(path):
        return "a file already exists there"
    return (name_problem(os.path.basename(path), strict=strict)
            or location_problem(path) or git_problem(path))


# ---------------------------------------------------------------- file helpers

def _read_small(path: str):
    """Text of a regular file (not following symlinks), or None."""
    try:
        if not stat.S_ISREG(os.lstat(path).st_mode):
            return None
        fd = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
        with os.fdopen(fd, "rb") as fh:
            return fh.read(MAX_READ).decode("utf-8", errors="replace")
    except OSError:
        return None


def file_state(reg: dict, path: str) -> str:
    """One of: missing, ours, modified, not_ours."""
    if not os.path.lexists(path):
        return "missing"
    entry = reg["files"].get(path)
    if not entry:
        return "not_ours"
    text = _read_small(path)
    values = list((entry.get("values") or {}).values())
    if text is not None and values and all(v in text for v in values):
        return "ours"
    return "modified"


def _make_parents(path: str, made: list) -> None:
    """Create missing parent folders with mode 700, remembering which we made."""
    missing = []
    p = os.path.dirname(path)
    while not os.path.lexists(p):
        missing.append(p)
        p = os.path.dirname(p)
    for d in reversed(missing):
        os.mkdir(d, 0o700)
        made.append(d)


def _create_exclusive(path: str, text: str) -> None:
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
    fd = os.open(path, flags, 0o600)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            fh.write(text)
        os.chmod(path, 0o600)
    except Exception:
        with contextlib.suppress(OSError):
            os.unlink(path)
        raise


def _plant_at(data_dir, reg: dict, path: str, btype: str, origin: str) -> None:
    """Create one bait file. Raises on failure (and undoes folders it made)."""
    values, text = make_bait(btype)
    made = []
    try:
        _make_parents(path, made)
        _create_exclusive(path, text)
    except Exception:
        for d in reversed(made):
            with contextlib.suppress(OSError):
                os.rmdir(d)
        raise
    reg["created_dirs"].extend(d for d in made if d not in reg["created_dirs"])
    reg["files"][path] = {"type": btype, "origin": origin, "planted": _now(), "values": values}
    save_registry(data_dir, reg)  # save after each file, so a crash orphans nothing


def _random_spot(reg: dict, btype: str, taken: set):
    home = _home()
    for _ in range(40):
        folder = _rng.choice(_folders_for(btype))
        name = _rng.choice(NAME_POOL[btype])
        path = os.path.normpath(os.path.join(home, folder, name))
        if spot_problem(path, reg, strict=True, taken=taken) is None:
            return path
    return None


def _cap_problem(reg: dict, adding: int):
    have = len(reg["files"])
    if have + adding > MAX_BAIT:
        return (f"customs keeps at most {MAX_BAIT} bait files. You have {have}; "
                f"adding {adding} would make {have + adding}.")
    return None


# ---------------------------------------------------------------- actions

def plant_default(data_dir) -> dict:
    """One bait file of each type. Types that already have default bait in
    place are left alone, so running it again is safe."""
    rep = {"created": [], "present": [], "failed": [], "refused": None}
    with _locked_registry(data_dir) as reg:
        todo = []
        for btype in TYPES:
            mine = [p for p, e in reg["files"].items()
                    if e.get("origin") == "default" and e.get("type") == btype]
            alive = [p for p in mine if file_state(reg, p) != "missing"]
            if alive:
                rep["present"].extend((p, btype) for p in alive)
            else:
                for p in mine:  # deleted by hand: forget it, plant a fresh one
                    reg["files"].pop(p, None)
                todo.append(btype)
        rep["refused"] = _cap_problem(reg, len(todo))
        if rep["refused"]:
            return rep
        taken = set()
        for btype in todo:
            path = _random_spot(reg, btype, taken)
            if path is None:
                rep["failed"].append((btype, "no free spot found"))
                continue
            try:
                _plant_at(data_dir, reg, path, btype, "default")
                taken.add(path)
                rep["created"].append((path, btype))
            except Exception as exc:
                rep["failed"].append((btype, f"{exc.__class__.__name__}: {exc}"))
    return rep


def plant_random(data_dir, n: int) -> dict:
    rep = {"created": [], "failed": [], "refused": None}
    if n < 1:
        rep["refused"] = "the number must be 1 or more."
        return rep
    with _locked_registry(data_dir) as reg:
        rep["refused"] = _cap_problem(reg, n)
        if rep["refused"]:
            return rep
        taken = set()
        for _ in range(n):
            btype = _rng.choice(TYPES)
            path = _random_spot(reg, btype, taken)
            if path is None:
                rep["failed"].append((btype, "no free spot found"))
                continue
            try:
                _plant_at(data_dir, reg, path, btype, "random")
                taken.add(path)
                rep["created"].append((path, btype))
            except Exception as exc:
                rep["failed"].append((btype, f"{exc.__class__.__name__}: {exc}"))
    return rep


def add(data_dir, raw_path: str, btype=None) -> dict:
    rep = {"created": None, "refused": None}
    path = normalize(raw_path)
    if btype is not None and btype not in TYPES:
        rep["refused"] = f"unknown type '{btype}'. Types: {', '.join(TYPES)}."
        return rep
    if os.path.isdir(path):
        rep["refused"] = f"{path} is a folder. Give a file path."
        return rep
    btype = btype or infer_type(os.path.basename(path))
    with _locked_registry(data_dir) as reg:
        problem = _cap_problem(reg, 1) or spot_problem(path, reg, strict=False)
        if problem:
            rep["refused"] = f"not planting at {path}: {problem}."
            return rep
        _plant_at(data_dir, reg, path, btype, "add")
        rep["created"] = (path, btype)
    return rep


def unplant(data_dir, raw_path=None) -> dict:
    """Delete one bait file (or all of them). Files changed since planting are
    kept on disk and dropped from the registry."""
    rep = {"deleted": [], "kept": [], "missing": [], "dirs_removed": [], "refused": None}
    with _locked_registry(data_dir) as reg:
        if raw_path:
            path = normalize(raw_path)
            if path not in reg["files"]:
                rep["refused"] = f"{path} isn't a customs bait file."
                return rep
            targets = [path]
        else:
            targets = sorted(reg["files"])
        for path in targets:
            state = file_state(reg, path)
            if state == "missing":
                rep["missing"].append(path)
            elif state == "ours":
                try:
                    os.unlink(path)
                    rep["deleted"].append(path)
                except OSError as exc:
                    rep["kept"].append((path, f"couldn't delete it ({exc.__class__.__name__})"))
                    continue  # still ours on disk: keep tracking it
            else:
                rep["kept"].append((path, "changed since planting, so left on disk; "
                                          "no longer tracked"))
            reg["files"].pop(path, None)
        # Folders customs made: remove the empty ones, deepest first.
        still = []
        for d in sorted(reg["created_dirs"], key=len, reverse=True):
            if not os.path.lexists(d):
                continue
            try:
                os.rmdir(d)  # only works when empty
                rep["dirs_removed"].append(d)
            except OSError:
                still.append(d)
        reg["created_dirs"] = sorted(still)
    return rep


def status(data_dir) -> dict:
    """Never includes fake values."""
    reg = load_registry(data_dir)
    rows = sorted((p, e.get("type", "?"), e.get("origin", "?"), file_state(reg, p))
                  for p, e in reg["files"].items())
    counts = {}
    for _p, t, _o, _s in rows:
        counts[t] = counts.get(t, 0) + 1
    return {"registry": str(registry_path(data_dir)), "rows": rows, "counts": counts,
            "total": len(rows), "cap": MAX_BAIT}


# ---------------------------------------------------------------- blend

SKIP_DIRS = {
    ".cache", ".local", ".hermes", ".claude", "node_modules", ".git", "venv", ".venv",
    "virtualenv", ".virtualenvs", ".tox", "__pycache__", "site-packages", ".mypy_cache",
    ".pytest_cache", ".ruff_cache", "dist", "build", "target", ".next", ".nuxt", "vendor",
    "snap", "miniconda3", "anaconda3",
}
HIDDEN_ALLOWED = {".ssh", ".aws"}  # the only hidden folders blend looks at (home level)
PROJECT_MARKERS = {"package.json": "node", "pyproject.toml": "python",
                   "requirements.txt": "python", "Cargo.toml": "rust", "go.mod": "go"}
HINT_WORDS = ("backup", "old", "archive", "key", "secret", "deploy", "infra", "ops",
              "config", "dotfiles", "scripts", "docs", "documents", "notes", "projects",
              "work", "dev", "code", "src")
FIT_NAMES = {
    "node": [(".env.backup", "env"), (".env.bak", "env"), (".env.local.bak", "env"),
             ("config.old.json", "json"), ("secrets.backup.json", "json")],
    "python": [(".env.bak", "env"), (".env.old", "env"), ("settings.backup.json", "json"),
               ("db-credentials.old.txt", "db")],
    "rust": [(".env.bak", "env"), ("config.old.json", "json"), ("deploy_key.bak", "ssh")],
    "go": [(".env.bak", "env"), ("config.old.json", "json"), ("deploy_key.bak", "ssh")],
    "git": [(".env.backup", "env"), ("deploy_key.old", "ssh"), ("github-token.old.txt", "github")],
}


def blend_excludes(data_dir) -> list:
    """Folders the user never wants blend to touch: one path per line in
    <data dir>/blend-exclude.txt (# starts a comment)."""
    out = []
    try:
        with open(Path(data_dir) / BLEND_EXCLUDE_NAME, encoding="utf-8") as fh:
            for line in fh:
                line = line.split("#", 1)[0].strip()
                if line:
                    out.append(normalize(line))
    except OSError:
        pass
    return out


def scan_home(excludes=(), max_depth=3, max_dirs=4000, budget_s=3.0) -> list:
    """Folders worth planting in. Reads names only, never file contents, and
    never follows symlinks. Returns dicts: path, kind (project, hint, .ssh,
    .aws) and project kinds."""
    home = _home()
    real_home = os.path.realpath(home)
    t0 = time.monotonic()
    stack = [(home, 0)]
    out = []
    listed = 0
    while stack and listed < max_dirs and time.monotonic() - t0 < budget_s:
        d, depth = stack.pop()
        if any(_under(d, ex) for ex in excludes):
            continue
        real = os.path.realpath(d)
        if not _under(real, real_home) or _under(real, "/mnt"):
            continue
        try:
            with os.scandir(d) as it:
                entries = list(it)
        except OSError:
            continue
        listed += 1
        names = {e.name for e in entries}
        if "pyvenv.cfg" in names:
            continue  # a virtualenv
        base = os.path.basename(d)
        kinds = sorted({PROJECT_MARKERS[n] for n in names if n in PROJECT_MARKERS}
                       | ({"git"} if ".git" in names else set()))
        if depth >= 1:
            if depth == 1 and base in HIDDEN_ALLOWED:
                out.append({"path": d, "kind": base, "kinds": []})
                continue  # don't look inside .ssh or .aws
            if kinds:
                out.append({"path": d, "kind": "project", "kinds": kinds})
            elif any(w in base.lower() for w in HINT_WORDS):
                out.append({"path": d, "kind": "hint", "kinds": []})
        if depth >= max_depth:
            continue
        for e in entries:
            try:
                if not e.is_dir(follow_symlinks=False):
                    continue
            except OSError:
                continue
            n = e.name
            if n in SKIP_DIRS:
                continue
            if n.startswith(".") and not (depth == 0 and n in HIDDEN_ALLOWED):
                continue
            stack.append((e.path, depth + 1))
    return out


def _blend_options(folders) -> list:
    """(weight, path, type, why) for every name that fits a folder."""
    opts = []
    for f in folders:
        if f["kind"] == "project":
            fits = []
            for k in f["kinds"]:
                fits += [x for x in FIT_NAMES.get(k, []) if x not in fits]
            weight, why = 3.0, "project (" + ", ".join(f["kinds"]) + ")"
        elif f["kind"] == ".ssh":
            fits, weight, why = [(n, "ssh") for n in NAME_POOL["ssh"]], 1.5, "your .ssh folder"
        elif f["kind"] == ".aws":
            fits, weight, why = [(n, "aws") for n in NAME_POOL["aws"]], 1.5, "your .aws folder"
        else:
            fits = [(n, t) for t in TYPES if t not in ("aws", "ssh") for n in NAME_POOL[t]]
            weight, why = 1.0, "folder name fits"
        for name, btype in fits:
            opts.append((weight, os.path.join(f["path"], name), btype, why))
    return opts


def plan_blend(data_dir, reg: dict, n: int):
    """Pick up to n spots that fit the user's folders. Returns (plan, skipped)
    where plan is [(path, type, why)] and skipped counts reasons."""
    ours = set(reg["created_dirs"])  # folders customs made aren't the user's structure
    folders = [f for f in scan_home(blend_excludes(data_dir)) if f["path"] not in ours]
    opts = _blend_options(folders)
    # Projects first, then .ssh/.aws, then other folders; random order within each tier.
    opts.sort(key=lambda o: (o[0], _rng.random()), reverse=True)
    plan, skipped, per_folder, taken = [], {}, {}, set()
    t0 = time.monotonic()
    for _w, path, btype, why in opts:
        if len(plan) >= n or time.monotonic() - t0 > 20:
            break
        folder = os.path.dirname(path)
        if per_folder.get(folder, 0) >= 2:
            continue
        problem = spot_problem(path, reg, strict=True, taken=taken)
        if problem:
            skipped[problem] = skipped.get(problem, 0) + 1
            continue
        plan.append((path, btype, why))
        taken.add(path)
        per_folder[folder] = per_folder.get(folder, 0) + 1
    return plan, skipped, len(folders)


def blend(data_dir, n: int, preview: bool) -> dict:
    rep = {"planned": [], "created": [], "failed": [], "skipped": {}, "folders": 0,
           "refused": None, "preview": preview}
    if n < 1:
        rep["refused"] = "the number must be 1 or more."
        return rep
    if preview:
        reg = load_registry(data_dir)
        rep["refused"] = _cap_problem(reg, n)
        if not rep["refused"]:
            rep["planned"], rep["skipped"], rep["folders"] = plan_blend(data_dir, reg, n)
        return rep
    with _locked_registry(data_dir) as reg:
        rep["refused"] = _cap_problem(reg, n)
        if rep["refused"]:
            return rep
        rep["planned"], rep["skipped"], rep["folders"] = plan_blend(data_dir, reg, n)
        for path, btype, _why in rep["planned"]:
            try:
                if spot_problem(path, reg, strict=True):
                    raise FileExistsError("the spot is no longer free")
                _plant_at(data_dir, reg, path, btype, "blend")
                rep["created"].append((path, btype))
            except Exception as exc:
                rep["failed"].append((path, f"{exc.__class__.__name__}: {exc}"))
    return rep


# ---------------------------------------------------------------- fast index for hooks

@dataclass(frozen=True)
class Needle:
    text: str   # the string to look for
    path: str   # the bait file it came from
    name: str   # which fake value, e.g. "aws_secret_access_key"
    form: str   # raw, base64, hex, url or reversed


@dataclass(frozen=True)
class BaitIndex:
    paths: frozenset = frozenset()          # absolute bait paths (plus their real paths)
    needles: tuple = ()                     # every Needle
    by_text: dict = field(default_factory=dict)  # text -> tuple of Needles
    error: str = ""                         # set when the registry couldn't be read
    stamp: tuple = ()


_index_lock = threading.Lock()
_index_cache = BaitIndex()
_default_data_dir = None


def configure(data_dir) -> None:
    """Tell load_index() where the registry lives (called from register())."""
    global _default_data_dir
    try:
        _default_data_dir = str(data_dir) if data_dir else None
    except Exception:
        pass


def _build_index(path: Path, stamp: tuple) -> BaitIndex:
    raw = _read_registry_file(path)
    reg = _migrate(raw)[0] if raw is not None else _empty_registry()
    paths, needles, by_text = set(), [], {}
    for bait_path, entry in reg["files"].items():
        paths.add(bait_path)
        with contextlib.suppress(Exception):
            paths.add(os.path.realpath(bait_path))
        for name, value in (entry.get("values") or {}).items():
            if not isinstance(value, str) or not value:
                continue
            forms = {"raw": value, **encoded_variants(value)}
            seen = set()
            for form, text in forms.items():
                if text in seen:  # e.g. URL encoding leaves a plain value unchanged
                    continue
                seen.add(text)
                nd = Needle(text, bait_path, name, form)
                needles.append(nd)
                by_text.setdefault(text, []).append(nd)
    return BaitIndex(frozenset(paths), tuple(needles),
                     {k: tuple(v) for k, v in by_text.items()}, "", stamp)


def load_index(data_dir=None) -> BaitIndex:
    """Bait paths and watched strings, cached. Costs one stat() when the
    registry hasn't changed. Never raises: on trouble it returns the last good
    index (or an empty one) with .error set."""
    global _index_cache
    try:
        d = str(data_dir) if data_dir is not None else _default_data_dir
        if not d:
            return _index_cache
        path = registry_path(d)
        try:
            st = os.stat(path)
            stamp = (str(path), st.st_mtime_ns, st.st_size, st.st_ino)
        except FileNotFoundError:
            stamp = (str(path), None)
        cached = _index_cache
        if cached.stamp == stamp:
            return cached
        with _index_lock:
            if _index_cache.stamp == stamp:
                return _index_cache
            try:
                _index_cache = _build_index(path, stamp)
            except Exception as exc:
                _index_cache = replace(_index_cache, stamp=stamp,
                                       error=f"{exc.__class__.__name__}: {exc}")
            return _index_cache
    except Exception as exc:
        try:
            return replace(_index_cache, error=f"{exc.__class__.__name__}: {exc}")
        except Exception:
            return BaitIndex(error="index unavailable")
