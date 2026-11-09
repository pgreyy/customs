"""customs: a tripwire and a quarantine for your Hermes agent.

Wiring only. The logic lives in bait.py (bait files and the index),
detect.py (does a tool call touch bait?), alerts.py (incident and error logs)
and commands.py (/customs).

pre_tool_call fails closed in Hermes: if it crashes or hangs, every tool call
is blocked. So every hook here catches its own errors, logs them to
errors.log, and lets the call through.
"""
import os
import threading

from . import alerts, bait, detect

_CTX = None
_DATA_DIR = None
_HOME = os.path.normpath(os.path.expanduser("~"))

# Last folder each session's terminal cd'd into, so "cd ~/x" then "cat y"
# is understood. Small and in memory only.
_LAST_CD = {}
_LAST_CD_MAX = 200
_LAST_CD_LOCK = threading.Lock()


def _session_cwd() -> str:
    try:
        cwd = _CTX.session_cwd() if _CTX is not None else ""
    except Exception:
        cwd = ""
    if isinstance(cwd, str) and cwd.startswith("/"):
        return os.path.normpath(cwd)
    return _HOME


def _remember_cd(session_id, command, ctx_info) -> None:
    targets = detect.cd_targets(command, ctx_info)
    if not targets or not session_id:
        return
    with _LAST_CD_LOCK:
        if len(_LAST_CD) >= _LAST_CD_MAX and session_id not in _LAST_CD:
            _LAST_CD.pop(next(iter(_LAST_CD)))
        _LAST_CD[session_id] = targets[-1]


def on_pre_tool_call(tool_name=None, args=None, **kwargs):
    try:
        index = bait.load_index()
        if not index.paths:
            return None
        session_id = kwargs.get("session_id") or ""
        last = _LAST_CD.get(session_id) if session_id else None
        ctx_info = detect.Context(cwd=_session_cwd(), home=_HOME,
                                  extra_bases=(last,) if last else ())
        decision = detect.check_tool_call(tool_name, args, index.paths, ctx_info)
        if decision is None:
            if tool_name == "terminal" and isinstance(args, dict):
                _remember_cd(session_id, args.get("command") or "", ctx_info)
            return None
        try:
            alerts.record_incident(_DATA_DIR, session_id=session_id, tool_name=tool_name,
                                   decision=decision, needles=index.by_text.keys())
        except Exception as exc:
            alerts.log_error(_DATA_DIR, "record_incident", exc)
        if decision.action == "block":
            return {"action": "block", "message": detect.BLOCK_MESSAGE}
        return {"action": "approve", "message": detect.APPROVE_MESSAGE}
    except Exception as exc:
        alerts.log_error(_DATA_DIR, "pre_tool_call", exc)
        return None


def on_post_tool_call(tool_name=None, args=None, result=None, **kwargs):
    # Phase 4 (provenance) and Phase 5 (quarantine) go here. Observer only.
    return None


def on_llm_request(**kwargs):
    # Phase 3 (bait value tripwire) goes here. None leaves the request unchanged.
    return None


def register(ctx):
    global _CTX, _DATA_DIR
    _CTX = ctx
    try:
        _DATA_DIR = str(ctx.state.data_dir)
        bait.configure(_DATA_DIR)
    except Exception:
        _DATA_DIR = None
    ctx.register_hook("pre_tool_call", on_pre_tool_call)
    ctx.register_hook("post_tool_call", on_post_tool_call)
    ctx.register_middleware("llm_request", on_llm_request)
    try:
        from .commands import make_handler
        ctx.register_command(
            "customs",
            make_handler(ctx),
            description="customs: plant fake secrets, see tripwire incidents",
            args_hint="plant [N] | blend N [--preview] | add <path> | status | "
                      "unplant [path] | incidents [N]",
        )
    except Exception as exc:
        alerts.log_error(_DATA_DIR, "register_command", exc)
    try:
        bait.load_index()   # warm the cache so the first tool call is fast
        _session_cwd()      # and the session-cwd imports
    except Exception:
        pass
