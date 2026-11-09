"""customs bait: fake secrets, bait files and the registry that remembers them.

No Hermes imports here. Every function takes the plugin's data folder as an
argument, so this file can be tried by hand in a plain Python shell.

Safety rules this file follows:
- A bait file is only ever created at a path where nothing exists. Creation
  uses O_CREAT | O_EXCL, so it can never overwrite a real file or follow a
  symlink, even if something appears at that path at the same moment.
- Unplant only deletes regular files that are in the registry and still
  contain the values we wrote into them.
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
import time
import urllib.parse
from pathlib import Path

REGISTRY_NAME = "bait.json"
REGISTRY_VERSION = 1

_UPPER_DIGITS = string.ascii_uppercase + string.digits
_ALNUM = string.ascii_letters + string.digits
_B64_CHARS = string.ascii_letters + string.digits + "+/"
_AWS_ID_CHARS = string.ascii_uppercase + "234567"  # real AWS key ids use this set

FAKE_DB_HOST = "prod-db.internal"  # .internal is reserved for private networks
FAKE_DB_USER = "prod_admin"
FAKE_DB_NAME = "production"

# Bait files: (path as written, kind). Kind picks the file format.
BAIT_FILES = [
    ("~/.env.production.bak", "env"),
    ("~/.aws/credentials.bak", "aws"),
    ("~/.ssh/id_rsa_old", "ssh"),
    ("~/backup/prod-db-credentials.txt", "db"),
]

# Which watched values each kind of file contains. Unplant checks these.
FILE_VALUES = {
    "env": ["postgres_url", "aws_access_key_id", "aws_secret_access_key",
            "stripe_key", "openai_key", "github_token"],
    "aws": ["aws_access_key_id", "aws_secret_access_key"],
    "ssh": ["ssh_key_fragment"],
    "db": ["postgres_password", "postgres_url"],
}

MAX_READ = 64 * 1024  # never read more than this from a bait path


# ---------------------------------------------------------------- values

def _rand(alphabet: str, n: int) -> str:
    return "".join(secrets.choice(alphabet) for _ in range(n))


def _ssh_string(data: bytes) -> bytes:
    return struct.pack(">I", len(data)) + data


def _fake_openssh_key() -> str:
    """A block that looks like an unencrypted OpenSSH RSA key. The header is
    the real format's header; everything after it is random bytes."""
    body = (b"openssh-key-v1\x00" + _ssh_string(b"none") + _ssh_string(b"none")
            + _ssh_string(b"") + struct.pack(">I", 1)
            + secrets.token_bytes(1860))
    b64 = base64.b64encode(body).decode("ascii")
    lines = [b64[i:i + 70] for i in range(0, len(b64), 70)]
    return ("-----BEGIN OPENSSH PRIVATE KEY-----\n" + "\n".join(lines)
            + "\n-----END OPENSSH PRIVATE KEY-----\n")


def generate_values() -> tuple[dict, str]:
    """Fresh fake values, unique to this install. Returns (values, ssh_key)."""
    pw = _rand(_ALNUM, 24)
    ssh_key = _fake_openssh_key()
    # A full 70 character line from the random part of the key body. This is
    # what we watch for, since the whole key is wrapped over many lines.
    fragment = ssh_key.splitlines()[3]
    values = {
        "aws_access_key_id": "AKIA" + _rand(_AWS_ID_CHARS, 16),
        "aws_secret_access_key": _rand(_B64_CHARS, 40),
        "github_token": "ghp_" + _rand(_ALNUM, 36),
        "openai_key": "sk-proj-" + _rand(_ALNUM, 48),
        "stripe_key": "sk_live_" + _rand(_ALNUM, 24),
        "postgres_password": pw,
        "postgres_url": f"postgres://{FAKE_DB_USER}:{pw}@{FAKE_DB_HOST}:5432/{FAKE_DB_NAME}",
        "ssh_key_fragment": fragment,
    }
    return values, ssh_key


def encoded_variants(value: str) -> dict:
    raw = value.encode("utf-8")
    return {
        "base64": base64.b64encode(raw).decode("ascii"),
        "hex": raw.hex(),
        "url": urllib.parse.quote(value, safe=""),
        "reversed": value[::-1],
    }


def watch_strings(reg: dict) -> set:
    """Every string the value tripwire should look for (values plus encodings)."""
    out = set()
    for name, value in (reg.get("values") or {}).items():
        out.add(value)
        out.update((reg.get("variants") or {}).get(name, {}).values())
    return {s for s in out if s}


def bait_paths(reg: dict) -> list:
    return sorted((reg.get("files") or {}).keys())


# ---------------------------------------------------------------- file formats

def render(kind: str, v: dict, ssh_key: str) -> str:
    if kind == "env":
        return (
            "NODE_ENV=production\n"
            f"DATABASE_URL={v['postgres_url']}\n"
            f"AWS_ACCESS_KEY_ID={v['aws_access_key_id']}\n"
            f"AWS_SECRET_ACCESS_KEY={v['aws_secret_access_key']}\n"
            "AWS_DEFAULT_REGION=us-east-1\n"
            f"STRIPE_SECRET_KEY={v['stripe_key']}\n"
            f"OPENAI_API_KEY={v['openai_key']}\n"
            f"GITHUB_TOKEN={v['github_token']}\n"
        )
    if kind == "aws":
        return (
            "[default]\n"
            f"aws_access_key_id = {v['aws_access_key_id']}\n"
            f"aws_secret_access_key = {v['aws_secret_access_key']}\n"
        )
    if kind == "ssh":
        return ssh_key
    if kind == "db":
        return (
            "Production database (primary)\n"
            f"host: {FAKE_DB_HOST}\n"
            "port: 5432\n"
            f"database: {FAKE_DB_NAME}\n"
            f"username: {FAKE_DB_USER}\n"
            f"password: {v['postgres_password']}\n"
            f"url: {v['postgres_url']}\n"
        )
    raise ValueError(f"unknown bait kind {kind!r}")


# ---------------------------------------------------------------- registry

def registry_path(data_dir) -> Path:
    return Path(data_dir) / REGISTRY_NAME


@contextlib.contextmanager
def _lock(data_dir):
    """Stops two sessions planting at the same moment."""
    Path(data_dir).mkdir(parents=True, exist_ok=True)
    lock_file = Path(data_dir) / ".bait.lock"
    with open(lock_file, "a+") as fh:
        try:
            import fcntl
            fcntl.flock(fh.fileno(), fcntl.LOCK_EX)
        except Exception:
            pass  # no fcntl (not Linux): carry on without the lock
        yield


def load_registry(data_dir):
    """The registry dict, or None when there isn't one yet.
    Raises RuntimeError when the file exists but can't be read, so a damaged
    registry is never silently replaced with new values."""
    path = registry_path(data_dir)
    try:
        with open(path, encoding="utf-8") as fh:
            reg = json.load(fh)
    except FileNotFoundError:
        return None
    except (OSError, ValueError) as exc:
        raise RuntimeError(f"bait registry at {path} can't be read ({exc.__class__.__name__}). "
                           "Move it aside by hand if you want a fresh one.") from exc
    if not isinstance(reg, dict) or not isinstance(reg.get("values"), dict):
        raise RuntimeError(f"bait registry at {path} has an unexpected shape.")
    reg.setdefault("files", {})
    reg.setdefault("created_dirs", [])
    return reg


def save_registry(data_dir, reg: dict) -> None:
    path = registry_path(data_dir)
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_name(f".{path.name}.{os.getpid()}.tmp")
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            json.dump(reg, fh, indent=2)
            fh.flush()
            os.fsync(fh.fileno())
        os.chmod(tmp, 0o600)
        os.replace(tmp, path)
    except Exception:
        with contextlib.suppress(OSError):
            os.unlink(tmp)
        raise


def _new_registry() -> dict:
    values, ssh_key = generate_values()
    return {
        "version": REGISTRY_VERSION,
        "created": time.strftime("%Y-%m-%dT%H:%M:%S%z"),
        "values": values,
        "variants": {k: encoded_variants(v) for k, v in values.items()},
        "ssh_key": ssh_key,
        "files": {},          # absolute path -> {"kind", "planted"}
        "created_dirs": [],   # folders we made, removed on unplant if empty
    }


# ---------------------------------------------------------------- file checks

def _read_small(path: str):
    """Text of a regular file (not following symlinks), or None."""
    try:
        st = os.lstat(path)
        if not stat.S_ISREG(st.st_mode):
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
    entry = (reg.get("files") or {}).get(path)
    if not entry:
        return "not_ours"
    text = _read_small(path)
    if text is None:
        return "modified"
    names = FILE_VALUES.get(entry.get("kind"), [])
    vals = reg.get("values") or {}
    if names and all(vals.get(n) and vals[n] in text for n in names):
        return "ours"
    return "modified"


def _make_parents(path: Path, created: list) -> None:
    """Create missing parent folders with mode 700, remembering which we made."""
    missing = []
    p = path.parent
    while not os.path.lexists(p):
        missing.append(p)
        p = p.parent
    for d in reversed(missing):
        os.mkdir(d, 0o700)
        created.append(str(d))


def _create_exclusive(path: Path, text: str) -> None:
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


# ---------------------------------------------------------------- actions

def plant(data_dir) -> dict:
    """Plant missing bait. Returns {"created", "present", "skipped", "errors"};
    each is a list of (path, note). Safe to run any number of times."""
    report = {"created": [], "present": [], "skipped": [], "errors": []}
    with _lock(data_dir):
        reg = load_registry(data_dir)
        if reg is None:
            reg = _new_registry()
            save_registry(data_dir, reg)  # save values before any file holds them
        for raw, kind in BAIT_FILES:
            path = Path(os.path.expanduser(raw))
            key = str(path)
            try:
                if os.path.lexists(path):
                    state = file_state(reg, key)
                    if state == "ours":
                        report["present"].append((key, "already planted"))
                    elif state == "modified":
                        report["present"].append((key, "ours, but changed since planting; left alone"))
                    else:
                        report["skipped"].append((key, "a file that isn't ours is already here; not touched"))
                    continue
                made = []
                _make_parents(path, made)
                reg["created_dirs"].extend(d for d in made if d not in reg["created_dirs"])
                _create_exclusive(path, render(kind, reg["values"], reg["ssh_key"]))
                reg["files"][key] = {"kind": kind, "planted": time.strftime("%Y-%m-%dT%H:%M:%S%z")}
                save_registry(data_dir, reg)
                report["created"].append((key, ""))
            except FileExistsError:
                report["skipped"].append((key, "something appeared here while planting; not touched"))
            except Exception as exc:
                report["errors"].append((key, f"{exc.__class__.__name__}: {exc}"))
        save_registry(data_dir, reg)
    return report


def status(data_dir) -> dict:
    """Never includes secret values."""
    reg = load_registry(data_dir)
    if reg is None:
        return {"planted": False, "registry": str(registry_path(data_dir)), "files": []}
    rows = []
    known = set(reg["files"])
    for raw, _kind in BAIT_FILES:
        key = os.path.expanduser(raw)
        rows.append((key, file_state(reg, key)))
        known.discard(key)
    for key in sorted(known):  # registry entries no longer in BAIT_FILES
        rows.append((key, file_state(reg, key)))
    return {
        "planted": True,
        "registry": str(registry_path(data_dir)),
        "created": reg.get("created", "?"),
        "files": rows,
        "value_count": len(reg["values"]),
        "watch_count": len(watch_strings(reg)),
    }


def unplant(data_dir) -> dict:
    """Delete our bait files that still hold our values, then clear the registry.
    Returns {"deleted", "kept", "missing", "dirs_removed", "registry_cleared"}."""
    report = {"deleted": [], "kept": [], "missing": [], "dirs_removed": [], "registry_cleared": False}
    with _lock(data_dir):
        reg = load_registry(data_dir)
        if reg is None:
            return report
        for key in sorted(reg["files"]):
            state = file_state(reg, key)
            if state == "missing":
                report["missing"].append((key, "already gone"))
            elif state == "ours":
                try:
                    os.unlink(key)
                    report["deleted"].append((key, ""))
                except OSError as exc:
                    report["kept"].append((key, f"could not delete: {exc.__class__.__name__}"))
            else:
                report["kept"].append((key, "contents changed since planting; check it by hand"))
        # Remove folders we created, deepest first, only if now empty.
        for d in sorted(reg.get("created_dirs", []), key=len, reverse=True):
            with contextlib.suppress(OSError):
                os.rmdir(d)  # fails (and is skipped) unless empty
                report["dirs_removed"].append(d)
        os.unlink(registry_path(data_dir))
        report["registry_cleared"] = True
    return report
