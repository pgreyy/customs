"""customs integrity: is each registered decoy still what customs planted?

Read only. It looks at the registry and at each bait file (lstat and a capped
read, never following a symlink) and reports. It never recreates, overwrites,
moves or deletes anything.

States, per registered decoy:
  intact                  a regular file holding every fake value customs put in it
  missing                 nothing at the path
  modified                a regular file still holding some, but not all, of its fake values
  replaced                something else is at the path: a symlink, a folder or other
                          non-regular file, or a file holding none of its fake values
  registry-inconsistent   the registry entry itself is unusable (no values, an unknown
                          type, a path outside your home folder) or the tripwire isn't
                          watching that path
  unreadable              the file is there but couldn't be read, so it couldn't be checked
"""
from __future__ import annotations

import os
import stat

from . import bait

STATES = ("intact", "missing", "modified", "replaced", "registry-inconsistent", "unreadable")
LABELS = {
    "intact": "intact",
    "missing": "MISSING",
    "modified": "MODIFIED (some fake values gone)",
    "replaced": "REPLACED (not the file customs planted)",
    "registry-inconsistent": "REGISTRY INCONSISTENT",
    "unreadable": "UNREADABLE (couldn't check)",
}


def _entry_problem(path, entry, home) -> str:
    if not isinstance(entry, dict):
        return "the registry entry isn't a record"
    if not isinstance(path, str) or not os.path.isabs(path):
        return "the registry path isn't absolute"
    if not bait._under(os.path.normpath(path), home):
        return "the registry path is outside your home folder"
    if entry.get("type") not in bait.TYPES:
        return f"unknown bait type {entry.get('type')!r}"
    values = entry.get("values")
    if not isinstance(values, dict) or not values or not all(isinstance(v, str) and v for v in values.values()):
        return "the registry entry has no fake values to check against"
    return ""


def check_file(path: str, entry: dict, home: str, watched=None):
    """(state, note) for one registry entry. Never raises."""
    try:
        problem = _entry_problem(path, entry, home)
        if problem:
            return "registry-inconsistent", problem
        if watched is not None and path not in watched:
            return "registry-inconsistent", "registered but the tripwire isn't watching it"
        try:
            st = os.lstat(path)
        except FileNotFoundError:
            return "missing", ""
        except OSError as exc:
            return "unreadable", exc.__class__.__name__
        if stat.S_ISLNK(st.st_mode):
            return "replaced", "now a symlink"
        if not stat.S_ISREG(st.st_mode):
            return "replaced", "no longer a regular file"
        text = bait._read_small(path)
        if text is None:
            return "unreadable", "couldn't read it"
        values = list(entry["values"].values())
        present = sum(1 for v in values if v in text)
        if present == len(values):
            return "intact", ""
        if present == 0:
            return "replaced", "holds none of its fake values"
        return "modified", f"{present} of {len(values)} fake values left"
    except Exception as exc:
        return "unreadable", exc.__class__.__name__


def audit(data_dir, home=None) -> dict:
    """Report for every registered decoy. Never raises, never writes."""
    home = os.path.normpath(home or os.path.expanduser("~"))
    rep = {"registry_error": "", "index_error": "", "rows": [], "counts": {}, "total": 0,
           "intact": 0, "warnings": []}
    try:
        reg = bait.load_registry(data_dir)
    except Exception as exc:
        rep["registry_error"] = str(exc)
        rep["warnings"].append("The bait registry can't be read, so no decoy could be checked.")
        return rep
    index = bait.load_index(data_dir)
    rep["index_error"] = index.error or ""
    watched = index.paths if not index.error else None
    for path, entry in sorted((reg.get("files") or {}).items()):
        state, note = check_file(path, entry, home, watched)
        etype = entry.get("type", "?") if isinstance(entry, dict) else "?"
        origin = entry.get("origin", "?") if isinstance(entry, dict) else "?"
        rep["rows"].append((path, etype, origin, state, note))
        rep["counts"][state] = rep["counts"].get(state, 0) + 1
    rep["total"] = len(rep["rows"])
    rep["intact"] = rep["counts"].get("intact", 0)
    if rep["index_error"]:
        rep["warnings"].append("The tripwire couldn't reload the registry and is using its last good list.")
    if rep["total"] and rep["intact"] < rep["total"]:
        rep["warnings"].append(
            f"Coverage degraded: {rep['total']} registered decoys, {rep['intact']} intact. "
            "Nothing was changed; re-plant or unplant by hand if you want to.")
    return rep
