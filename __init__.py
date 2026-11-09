"""customs: a tripwire and a quarantine for your Hermes agent.

Wiring only. The logic lives in bait.py (bait files and the index),
detect.py (does a tool call touch a bait path?), valuescan.py (does a text
hold a fake value?), alerts.py (incident and error logs) and commands.py.

pre_tool_call fails closed in Hermes: if it crashes or hangs, every tool call
is blocked. So every hook here catches its own errors, logs them to
errors.log, and returns None (lets things through unchanged).
"""
import json
import os
import threading

from . import alerts, bait, detect, valuescan

RESULT_NOTICE = ("customs: this output contained protected credentials and was redacted. "
                 "The user has been alerted.")

_CTX = None
_DATA_DIR = None
_HOME = os.path.normpath(os.path.expanduser("~"))

# Last folder each session's terminal cd'd into, so "cd ~/x" then "cat y"
# is understood. Small and in memory only.
_LAST_CD = {}
_LAST_CD_MAX = 200
_LAST_CD_LOCK = threading.Lock()

# value-to-provider incidents already recorded. Once a value is in the
# conversation, every later model request carries it; record it once.
_REPORTED = set()
_REPORTED_MAX = 2000


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


def _preview(tool_name, args) -> str:
    """What the call looked like: the command, code, path or URL, else the args."""
    a = detect._as_dict(args)
    for key in ("command", "code", "path", "url", "urls", "query"):
        v = a.get(key)
        if isinstance(v, str) and v:
            return v[:4000]
        if isinstance(v, list) and v:
            return " ".join(str(x) for x in v)[:4000]
    try:
        return json.dumps(a, default=str)[:4000]
    except Exception:
        return str(tool_name or "")


def _record(index, session_id, tool_name, decision, extra=None) -> None:
    """Write an incident. The preview is cleaned twice: partial/encoded fake
    values (valuescan), then exact forms and real-secret shapes (alerts)."""
    try:
        tab = valuescan.table(index)
        clean = valuescan.redact(decision.preview or "", tab)[0]
        decision = detect.Decision(decision.action, decision.rule, decision.bait_path, clean)
        alerts.record_incident(_DATA_DIR, session_id=session_id, tool_name=tool_name,
                               decision=decision, needles=index.by_text.keys(), extra=extra)
    except Exception as exc:
        alerts.log_error(_DATA_DIR, "record_incident", exc)


def _value_names(hits) -> str:
    return ",".join(sorted({name for _p, name in hits}))


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
        extra = None
        if decision is None:
            # Phase 3: a fake value (plain, partial or encoded) in any argument.
            strings = []
            valuescan.collect_strings(detect._as_dict(args), strings)
            tab = valuescan.table(index)
            budget, hits = valuescan.MAX_SCAN, set()
            for _c, _k, text in strings:
                if budget <= 0:
                    break
                part = text[:budget]
                budget -= len(part)
                hits |= valuescan.find(part, tab).hits
                if hits:
                    break
            if hits:
                decision = detect.Decision("block", "value-in-args", sorted(hits)[0][0],
                                           _preview(tool_name, args))
                extra = {"value_name": _value_names(hits)}
        if decision is None:
            if tool_name == "terminal" and isinstance(args, dict):
                _remember_cd(session_id, args.get("command") or "", ctx_info)
            return None
        _record(index, session_id, tool_name, decision, extra)
        if decision.action == "block":
            return {"action": "block", "message": detect.BLOCK_MESSAGE}
        return {"action": "approve", "message": detect.APPROVE_MESSAGE}
    except Exception as exc:
        alerts.log_error(_DATA_DIR, "pre_tool_call", exc)
        return None


def on_post_tool_call(tool_name=None, args=None, result=None, **kwargs):
    # Phase 4 (provenance) and Phase 5 (quarantine) go here. Observer only.
    return None


def on_transform_tool_result(tool_name=None, args=None, result=None, **kwargs):
    """Redact fake values from a tool result before the model sees it."""
    try:
        if not isinstance(result, str) or not result:
            return None
        index = bait.load_index()
        if not index.needles:
            return None
        new, hits = valuescan.redact(result, valuescan.table(index))
        if not hits:
            return None
        decision = detect.Decision("redact", "value-in-result", sorted(hits)[0][0],
                                   _preview(tool_name, args))
        _record(index, kwargs.get("session_id") or "", tool_name, decision,
                {"value_name": _value_names(hits), "action_taken": "redacted"})
        return new.rstrip("\n") + "\n" + RESULT_NOTICE
    except Exception as exc:
        alerts.log_error(_DATA_DIR, "transform_tool_result", exc)
        return None


def on_llm_request(**kwargs):
    """Redact fake values from the request before it goes to the model provider."""
    try:
        request = kwargs.get("request")
        if not isinstance(request, dict):
            return None
        index = bait.load_index()
        if not index.needles:
            return None
        tab = valuescan.table(index)
        strings = []
        # "tools" is the tool schema list: static, large, not conversation.
        valuescan.collect_strings(request, strings, skip_top_keys=("tools",))
        repl, hits = valuescan.redact_strings(strings, tab)
        if not hits:
            return None
        new_request = valuescan.copy_with(request, repl)
        session_id = str(kwargs.get("session_id") or "")
        fresh = sorted(h for h in hits if (session_id, h) not in _REPORTED)
        if fresh:
            if len(_REPORTED) > _REPORTED_MAX:
                _REPORTED.clear()
            _REPORTED.update((session_id, h) for h in fresh)
            decision = detect.Decision("redact", "value-to-provider", fresh[0][0],
                                       f"model request ({kwargs.get('provider') or 'provider'})")
            _record(index, session_id, "llm_request", decision,
                    {"value_name": _value_names(fresh), "action_taken": "redacted"})
        return {"request": new_request, "source": "customs",
                "reason": "redacted protected credentials"}
    except Exception as exc:
        alerts.log_error(_DATA_DIR, "llm_request", exc)
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
    ctx.register_hook("transform_tool_result", on_transform_tool_result)
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
        valuescan.table(bait.load_index())  # warm the caches so the first call is fast
        _session_cwd()
    except Exception:
        pass
