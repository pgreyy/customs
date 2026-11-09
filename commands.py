"""/customs slash command. Every path returns a string and never raises."""
from __future__ import annotations

import os
import shlex

from . import alerts, bait

USAGE = (
    "Usage:\n"
    "  /customs plant              plant the default set (one bait file of each type)\n"
    "  /customs plant <N>          plant N bait files with random names and folders\n"
    "  /customs blend <N> [--preview]\n"
    "                              plant N bait files that fit your own folders;\n"
    "                              --preview only shows the plan\n"
    "  /customs add <path> [--type T]\n"
    "                              plant one bait file at a path you choose\n"
    "  /customs status             what's planted and whether each file is still there\n"
    "  /customs unplant [path]     remove one bait file, or all of them\n"
    "  /customs incidents [N]      the last N tripwire incidents (default 10), newest first\n"
    "  /customs unlock             end lockdown for this session\n"
    f"Types: {', '.join(bait.TYPES)}. At most {bait.MAX_BAIT} bait files in total."
)

_STATE_TEXT = {
    "ours": "in place",
    "missing": "MISSING",
    "modified": "changed since planting",
    "not_ours": "not ours",
}


def _short(path: str) -> str:
    home = os.path.expanduser("~")
    return "~" + path[len(home):] if path.startswith(home + os.sep) else path


def _say(msg: str) -> str:
    home = os.path.expanduser("~")
    return "customs: " + msg.replace(home + os.sep, "~" + os.sep)


def _int(word: str):
    try:
        return int(word)
    except (TypeError, ValueError):
        return None


def _list(title, rows):
    if not rows:
        return []
    out = [f"{title} ({len(rows)}):"]
    for row in rows:
        if isinstance(row, str):
            out.append(f"  {_short(row)}")
        else:
            path, note = row[0], row[1]
            out.append(f"  {_short(path)}  [{note}]")
    return out


def _failed(rows):
    if not rows:
        return []
    return [f"Couldn't plant ({len(rows)}):"] + [f"  {a}: {b}" for a, b in rows]


def _plant(data_dir, args) -> str:
    if not args:
        r = bait.plant_default(data_dir)
        if r["refused"]:
            return _say(r["refused"])
        out = ["customs: plant (default set)"]
        out += _list("Created", r["created"])
        out += _list("Already in place", r["present"])
        out += _failed(r["failed"])
        if not r["created"] and not r["failed"]:
            out.append("Nothing new to plant.")
        return "\n".join(out)
    n = _int(args[0])
    if n is None or len(args) > 1:
        return "customs: use /customs plant or /customs plant <N>, where N is a number."
    if n > bait.MAX_BAIT:
        return f"customs: {n} is over the limit of {bait.MAX_BAIT} bait files."
    r = bait.plant_random(data_dir, n)
    if r["refused"]:
        return _say(r["refused"])
    out = [f"customs: plant {n}"]
    out += _list("Created", r["created"])
    out += _failed(r["failed"])
    return "\n".join(out)


def _blend(data_dir, args) -> str:
    preview = "--preview" in args
    rest = [a for a in args if a != "--preview"]
    n = _int(rest[0]) if len(rest) == 1 else None
    if n is None:
        return "customs: use /customs blend <N> [--preview], where N is a number."
    if n > bait.MAX_BAIT:
        return f"customs: {n} is over the limit of {bait.MAX_BAIT} bait files."
    r = bait.blend(data_dir, n, preview)
    if r["refused"]:
        return _say(r["refused"])
    out = [f"customs: blend {n}" + (" (preview, nothing created)" if preview else ""),
           f"Looked at {r['folders']} likely folders (names only)."]
    if preview:
        out += _list("Would plant", [(p, f"{t}, {why}") for p, t, why in r["planned"]])
        if r["planned"]:
            out.append("The real run picks again at random, so its spots can differ.")
    else:
        out += _list("Created", r["created"])
        out += _failed(r["failed"])
    if len(r["planned"]) < n:
        out.append(f"Only found {len(r['planned'])} safe spot(s) for {n}.")
    if r["skipped"]:
        out.append("Spots skipped: " + "; ".join(
            f"{k} ({v})" for k, v in sorted(r["skipped"].items(), key=lambda kv: -kv[1])))
    return "\n".join(out)


def _add(data_dir, args) -> str:
    btype = None
    if "--type" in args:
        i = args.index("--type")
        if i + 1 >= len(args):
            return "customs: --type needs a value: " + ", ".join(bait.TYPES)
        btype = args[i + 1].lower()
        args = args[:i] + args[i + 2:]
    if len(args) != 1:
        return "customs: use /customs add <path> [--type T]. Quote paths with spaces."
    r = bait.add(data_dir, args[0], btype)
    if r["refused"]:
        return _say(r["refused"])
    path, t = r["created"]
    return f"customs: planted {_short(path)} ({bait.TYPE_LABELS.get(t, t)})."


def _status(data_dir, _args) -> str:
    s = bait.status(data_dir)
    if not s["total"]:
        return "customs: no bait planted. Run /customs plant."
    counts = ", ".join(f"{bait.TYPE_LABELS.get(t, t)} {c}" for t, c in sorted(s["counts"].items()))
    missing = sum(1 for r in s["rows"] if r[3] == "missing")
    out = [f"customs: {s['total']} of {s['cap']} bait files. {counts}."]
    if missing:
        out.append(f"{missing} missing (deleted outside customs).")
    for path, t, origin, state in s["rows"]:
        out.append(f"  {_short(path)}  [{t}, {origin}]  {_STATE_TEXT.get(state, state)}")
    out.append(f"Registry: {_short(s['registry'])}")
    return "\n".join(out)


def _unplant(data_dir, args) -> str:
    if len(args) > 1:
        return "customs: use /customs unplant or /customs unplant <path>. Quote paths with spaces."
    r = bait.unplant(data_dir, args[0] if args else None)
    if r["refused"]:
        return _say(r["refused"])
    out = ["customs: unplant"]
    out += _list("Deleted", r["deleted"])
    out += _list("Kept", r["kept"])
    out += _list("Already gone", r["missing"])
    if r["dirs_removed"]:
        out.append("Removed empty folders customs had made: "
                   + ", ".join(_short(d) for d in r["dirs_removed"]))
    if len(out) == 1:
        out.append("Nothing to remove.")
    return "\n".join(out)


def _incidents(data_dir, args) -> str:
    n = _int(args[0]) if args else 10
    if n is None or n < 1 or len(args) > 1:
        return "customs: use /customs incidents or /customs incidents <N>."
    rows = alerts.read_incidents(data_dir, min(n, 500))
    if not rows:
        return "customs: no incidents recorded."
    out = [f"customs: last {len(rows)} incident(s), newest first"]
    for r in rows:
        when = str(r.get("time", "?")).replace("T", " ")[:19]
        out.append(f"{when}  {str(r.get('decision', '?')).upper():7}  {r.get('tool_name', '?')}"
                   f"  rule={r.get('rule', '?')}  bait={_short(str(r.get('bait_path', '')))}")
        prev = str(r.get("preview", "")).replace("\n", " ")
        if prev:
            out.append(f"    {prev}")
        out.append(f"    source: {r.get('source') or 'not recorded'}")
    return "\n".join(out)


_ACTIONS = {"plant": _plant, "blend": _blend, "add": _add, "status": _status,
            "unplant": _unplant, "incidents": _incidents}


def _session_ids(kwargs) -> list:
    return [v for v in (kwargs.get("session_id"), kwargs.get("session_key"))
            if isinstance(v, str) and v]


def _lockdown_lines(runtime, ids) -> list:
    if runtime is None:
        return []
    try:
        enabled = runtime.settings()["lockdown"]
        info = next((runtime.lockdown.info(i) for i in ids if runtime.lockdown.info(i)), None)
        line = "Lockdown setting: " + ("on" if enabled else "off") + ". This session: "
        if info:
            line += (f"LOCKED (rule {info.get('rule', '?')}); network actions need approval. "
                     "Run /customs unlock to end it.")
        else:
            line += "not locked."
        others = runtime.lockdown.count() - (1 if info else 0)
        if others > 0:
            line += f" Other locked sessions: {others}."
        return [line]
    except Exception:
        return []


def _unlock(runtime, ids) -> str:
    if runtime is None:
        return "customs: lockdown isn't available."
    if not ids:
        return "customs: couldn't tell which session this is, so nothing was unlocked."
    done = runtime.lockdown.unlock(*ids)
    if done:
        return "customs: lockdown ended for this session. Network actions run normally again."
    return "customs: this session isn't locked."


def make_handler(ctx, runtime=None):
    def handle(raw_args: str = "", **kwargs) -> str:
        try:
            try:
                words = shlex.split(raw_args or "")
            except ValueError:
                words = (raw_args or "").split()
            sub = words[0].lower() if words else ""
            ids = _session_ids(kwargs)
            if sub == "unlock":
                return _unlock(runtime, ids)
            action = _ACTIONS.get(sub)
            if action is None:
                return USAGE
            data_dir = ctx.state.data_dir
            bait.configure(data_dir)
            out = action(data_dir, words[1:])
            if sub == "status":
                out = "\n".join([out] + _lockdown_lines(runtime, ids))
            return out
        except Exception as exc:
            return f"customs: that didn't work ({exc.__class__.__name__}: {exc})"
    return handle
