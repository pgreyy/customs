"""/customs slash command. Every path returns a string and never raises."""
from __future__ import annotations

import os

from . import bait

USAGE = (
    "Usage: /customs plant | status | unplant\n"
    "  plant    create the bait files that are missing (safe to repeat)\n"
    "  status   list bait files and whether each one is in place\n"
    "  unplant  delete our bait files and forget the fake values"
)

_STATE_TEXT = {
    "ours": "in place",
    "missing": "missing (run /customs plant)",
    "modified": "changed since planting (left alone)",
    "not_ours": "a file that isn't ours is here (not touched)",
}


def _short(path: str) -> str:
    home = os.path.expanduser("~")
    return "~" + path[len(home):] if path.startswith(home + os.sep) else path


def _lines(title, rows):
    if not rows:
        return []
    out = [f"{title}:"]
    for path, note in rows:
        out.append(f"  {_short(path)}" + (f"  ({note})" if note else ""))
    return out


def _plant(data_dir) -> str:
    r = bait.plant(data_dir)
    out = ["customs: plant"]
    out += _lines("Created", r["created"])
    out += _lines("Already present", r["present"])
    out += _lines("Skipped", r["skipped"])
    out += _lines("Errors", r["errors"])
    if not r["created"] and not r["errors"]:
        out.append("Nothing new to plant.")
    return "\n".join(out)


def _status(data_dir) -> str:
    s = bait.status(data_dir)
    if not s["planted"]:
        return "customs: no bait planted yet. Run /customs plant."
    out = ["customs: status", f"Bait values made: {s['created']}"]
    for path, state in s["files"]:
        out.append(f"  {_short(path)}: {_STATE_TEXT.get(state, state)}")
    out.append(f"Watching {s['value_count']} fake values "
               f"({s['watch_count']} strings including encoded forms).")
    out.append(f"Registry: {_short(s['registry'])}")
    return "\n".join(out)


def _unplant(data_dir) -> str:
    r = bait.unplant(data_dir)
    if not r["registry_cleared"]:
        return "customs: nothing to unplant (no registry)."
    out = ["customs: unplant"]
    out += _lines("Deleted", r["deleted"])
    out += _lines("Kept", r["kept"])
    out += _lines("Already gone", r["missing"])
    if r["dirs_removed"]:
        out.append("Removed empty folders customs had made: "
                   + ", ".join(_short(d) for d in r["dirs_removed"]))
    out.append("Registry cleared. The next plant makes new fake values.")
    return "\n".join(out)


_ACTIONS = {"plant": _plant, "status": _status, "unplant": _unplant}


def make_handler(ctx):
    def handle(raw_args: str = "") -> str:
        try:
            words = (raw_args or "").strip().split()
            sub = words[0].lower() if words else ""
            action = _ACTIONS.get(sub)
            if action is None:
                return USAGE
            data_dir = ctx.state.data_dir
            return action(data_dir)
        except Exception as exc:
            return f"customs: that didn't work ({exc.__class__.__name__}: {exc})"
    return handle
