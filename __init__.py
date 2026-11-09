"""customs: a tripwire and a quarantine for your Hermes agent.

Wiring only. The logic lives in bait.py (bait files and the index),
detect.py (does a tool call touch a bait path? is it a network action?),
valuescan.py (does a text hold a fake value?), provenance.py (what untrusted
things the session read), lockdown.py, alerts.py (incident log, chat and push
alerts) and commands.py.

pre_tool_call fails closed in Hermes: if it crashes or hangs, every tool call
is blocked. So every hook here catches its own errors, logs them to
errors.log, and returns None (lets things through unchanged). Anything slow
(posting alerts, pushes) runs on background threads.
"""
import json
import os
import threading
import time
from types import SimpleNamespace

from . import alerts, bait, correlate, detect, events, lockdown, provenance, valuescan

RESULT_NOTICE = ("customs: this output contained protected credentials and was redacted. "
                 "The user has been alerted.")

_CTX = None
_DATA_DIR = None
_HOME = os.path.normpath(os.path.expanduser("~"))

PROV = provenance.Provenance()
LOCK = lockdown.Lockdown()
NOTIFIER = alerts.Notifier(lambda: _DATA_DIR)
EVENTS = events.EventLog()

_OUTCOME = {"block": "blocked", "approve": "escalated to approval", "redact": "redacted, call allowed"}

# Approval requests waiting for the user's answer: (session_id, tool_call_id) -> incident id.
_PENDING = {}
_PENDING_MAX = 500
_PENDING_LOCK = threading.Lock()
# What Hermes reports from a person (post_approval_response "choice"). Anything
# else (timeout, cancelled, an automatic decision) is not recorded as a user decision.
_USER_CHOICE = {"once": "user approved", "session": "user approved", "always": "user approved",
                "deny": "user denied"}
_SEVERITY = {"block": "high", "approve": "medium", "redact": "medium"}

# Last folder each session's terminal cd'd into, so "cd ~/x" then "cat y"
# is understood. Small and in memory only.
_LAST_CD = {}
_LAST_CD_MAX = 200
_LAST_CD_LOCK = threading.Lock()

# value-to-provider incidents already recorded. Once a value is in the
# conversation, every later model request carries it; record it once.
_REPORTED = set()
_REPORTED_MAX = 2000

_SETTINGS = {"at": 0.0, "lockdown": True, "alert_target": ""}
_SETTINGS_TTL = 10.0
_UNTRUSTED_TOOL = {}


def _settings() -> dict:
    """Plugin settings, re-read at most every 10 seconds."""
    now = time.time()
    if now - _SETTINGS["at"] < _SETTINGS_TTL:
        return _SETTINGS
    _SETTINGS["at"] = now
    try:
        lock = _CTX.get_config("lockdown", True)
        if isinstance(lock, str):
            lock = lock.strip().lower() not in ("false", "0", "no", "off")
        _SETTINGS["lockdown"] = bool(lock)
        target = _CTX.get_config("alert_target", "")
        _SETTINGS["alert_target"] = target.strip() if isinstance(target, str) else ""
    except Exception as exc:
        alerts.log_error(_DATA_DIR, "settings", exc)
    return _SETTINGS


def _untrusted_tool(name) -> bool:
    """MCP tools and tools that don't ship with Hermes (their output is outside content)."""
    if not name:
        return False
    if name in _UNTRUSTED_TOOL:
        return _UNTRUSTED_TOOL[name]
    untrusted = name.startswith("mcp_")
    if not untrusted:
        try:
            from tools.registry import registry
            entry = registry.get_entry(name)
            if entry is not None:
                mod = getattr(entry.handler, "__module__", "") or ""
                untrusted = not mod.startswith(("tools.", "model_tools", "agent.", "hermes_cli."))
        except Exception:
            pass
    if len(_UNTRUSTED_TOOL) < 1000:
        _UNTRUSTED_TOOL[name] = untrusted
    return untrusted


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


def _log_events(session_id, tool_name, evs):
    """(events before this call, seqs of this call's events). Never raises and
    never affects a decision: it runs after the tripwire has decided."""
    try:
        before = EVENTS.recent(session_id, 8) if session_id else []
        evs = [e for e in (evs or []) if e]
        return before, EVENTS.add(session_id, tool_name, evs)
    except Exception as exc:
        alerts.log_error(_DATA_DIR, "event log", exc)
        return [], []


def _call_events(tool_name, args, decision, index) -> list:
    try:
        evs = events.classify_call(tool_name, args, _HOME)
        if decision is not None and (decision.bait_path in index.paths or decision.rule.startswith("value-")):
            evs.append((events.BAIT_HIT, events.label(decision.bait_path or decision.rule, _HOME), True))
        return evs
    except Exception as exc:
        alerts.log_error(_DATA_DIR, "event classify", exc)
        return []


CHAIN_MESSAGE = ("customs: this call would send data out, and earlier steps in this session looked like "
                 "searching for and packaging credentials. They may be unrelated. Approve only if you "
                 "expected this.")


def _chain_check(index, session_id, tool_name, args, before, cur, call_id=""):
    """Alert only, fail open: an approval request when this outbound call
    completes a strong chain of earlier steps, else None. Never blocks."""
    try:
        if not session_id or not cur:
            return None
        finding = correlate.evaluate(EVENTS.since_consumed(session_id), cur)
        if finding is None:
            return None
        EVENTS.consume(session_id, finding.last_seq)  # one finding per chain
        decision = detect.Decision("approve", "attack-chain", "", _preview(tool_name, args))
        _record(index, session_id, tool_name, decision,
                {"chain": [events.describe(e) for e in finding.events], "chain_reason": finding.reason},
                before=before, severity="high", call_id=call_id)
        return {"action": "approve", "message": CHAIN_MESSAGE}
    except Exception as exc:
        alerts.log_error(_DATA_DIR, "chain check", exc)
        return None


def _forensics(session_id, decision, before, severity=None) -> dict:
    """The structured part of an incident report. Never raises."""
    try:
        sid = session_id or ""
        locked = LOCK.is_locked(sid) or (decision.action == "block" and _settings()["lockdown"] and bool(sid))
        return {"outcome": _OUTCOME.get(decision.action, decision.action),
                "severity": severity or _SEVERITY.get(decision.action, "medium"),
                "lockdown_active": bool(locked),
                "before": [events.describe(e) for e in (before or [])]}
    except Exception as exc:
        alerts.log_error(_DATA_DIR, "forensics", exc)
        return {}


def _record(index, session_id, tool_name, decision, extra=None, before=None, severity=None,
            call_id="") -> None:
    """Write the incident, lock the session on a block, and send alerts.
    The preview is masked twice: partial/encoded fake values (valuescan), then
    exact forms and real-secret shapes (alerts). Alerts use only the entry."""
    try:
        tab = valuescan.table(index)
        raw_preview = decision.preview or ""
        clean = valuescan.redact(raw_preview, tab)[0]
        decision = detect.Decision(decision.action, decision.rule, decision.bait_path, clean,
                                   decision.script_path)
        extra = dict(extra or {})
        if decision.rule.startswith("script"):
            # Only blame a remote source the script is plausibly linked to.
            extra["source"] = PROV.source_for_script(session_id, decision.script_path, _HOME)
            if decision.script_path:
                extra["script"] = decision.script_path
        elif decision.rule == "pipe-to-shell":
            urls = provenance.urls_in(raw_preview)
            extra["source"] = alerts.redact(urls[0], long_runs=False) if urls \
                else PROV.latest(session_id)
        else:
            extra["source"] = PROV.latest(session_id)
        for k, v in _forensics(session_id, decision, before, severity).items():
            extra.setdefault(k, v)
        entry = alerts.record_incident(_DATA_DIR, session_id=session_id, tool_name=tool_name,
                                       decision=decision, needles=index.by_text.keys(), extra=extra)
    except Exception as exc:
        alerts.log_error(_DATA_DIR, "record_incident", exc)
        return
    try:
        if decision.action == "approve" and session_id and call_id and entry.get("id"):
            with _PENDING_LOCK:
                if len(_PENDING) >= _PENDING_MAX:
                    _PENDING.pop(next(iter(_PENDING)))
                _PENDING[(str(session_id), str(call_id))] = entry["id"]
    except Exception as exc:
        alerts.log_error(_DATA_DIR, "pending approval", exc)
    try:
        settings = _settings()
        if decision.action == "block" and settings["lockdown"]:
            LOCK.lock(session_id, decision.rule, decision.bait_path)
        text = alerts.alert_text(entry)
        NOTIFIER.chat(_CTX, text)
        NOTIFIER.push(_CTX, session_id, text, settings["alert_target"])
    except Exception as exc:
        alerts.log_error(_DATA_DIR, "alerts", exc)


def _value_names(hits) -> str:
    return ",".join(sorted({name for _p, name in hits}))


def on_pre_tool_call(tool_name=None, args=None, **kwargs):
    try:
        session_id = kwargs.get("session_id") or ""
        index = bait.load_index()
        decision, extra, ctx_info = None, None, None
        if index.paths:
            last = _LAST_CD.get(session_id) if session_id else None
            ctx_info = detect.Context(cwd=_session_cwd(), home=_HOME,
                                      extra_bases=(last,) if last else ())
            decision = detect.check_tool_call(tool_name, args, index.paths, ctx_info)
            if decision is None:
                # A fake value (plain, partial or encoded) in any argument.
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
        # The decision above is final. Logging what this call does comes after it.
        before, _cur = _log_events(session_id, tool_name, _call_events(tool_name, args, decision, index))
        if decision is not None:
            _record(index, session_id, tool_name, decision, extra, before=before,
                    call_id=kwargs.get("tool_call_id") or "")
            if decision.action == "block":
                return {"action": "block", "message": detect.BLOCK_MESSAGE}
            return {"action": "approve", "message": detect.approve_message(decision.rule)}
        # Lockdown: after a block, network actions in this session need approval.
        if LOCK.is_locked(session_id) and _settings()["lockdown"] and \
                detect.is_network_action(tool_name, args, _untrusted_tool(tool_name)):
            return {"action": "approve", "message": lockdown.MESSAGE}
        if ctx_info is not None and tool_name == "terminal" and isinstance(args, dict):
            _remember_cd(session_id, args.get("command") or "", ctx_info)
        # Correlation can only ask for approval, and only when nothing above decided.
        return _chain_check(index, session_id, tool_name, args, before, _cur,
                            call_id=kwargs.get("tool_call_id") or "")
    except Exception as exc:
        alerts.log_error(_DATA_DIR, "pre_tool_call", exc)
        return None


def on_post_tool_call(tool_name=None, args=None, result=None, **kwargs):
    """Observer only: remember untrusted sources this session read."""
    try:
        session_id = kwargs.get("session_id") or ""
        if not session_id or kwargs.get("status") == "blocked":
            return None
        sources = provenance.sources_for(tool_name, args, result, home=_HOME, cwd=_session_cwd(),
                                         untrusted_tool=_untrusted_tool(tool_name))
        if sources:
            failed = provenance.call_failed(kwargs.get("status"), result)
            if not failed:  # only a call that actually read something can be a likely source
                PROV.add(session_id, tool_name, [alerts.redact(s, long_runs=False) for s in sources],
                         kwargs.get("tool_call_id") or "", kwargs.get("turn_id") or "")
            _log_events(session_id, tool_name, [events.untrusted_read_event(sources, _HOME, failed=failed)])
        writes = provenance.parse_writes(tool_name, args, home=_HOME, cwd=_session_cwd())
        if writes:
            PROV.note_writes(session_id,
                             [(p, alerts.redact(u, long_runs=False) if u else None) for p, u in writes],
                             kwargs.get("turn_id") or "")
        if tool_name == "terminal" and isinstance(args, dict):
            clone = provenance.parse_git_clone(args.get("command") or "", _HOME, _session_cwd())
            if clone:
                PROV.note_clone(session_id, alerts.redact(clone[0], long_runs=False), clone[1])
    except Exception as exc:
        alerts.log_error(_DATA_DIR, "post_tool_call", exc)
    return None


def on_post_approval_response(**kwargs):
    """Observer only: if Hermes reports a person's answer to one of customs'
    approval requests, note it on that incident. Never guesses."""
    try:
        if kwargs.get("decided_by"):  # an automatic decision, not the user's
            return None
        answer = _USER_CHOICE.get(str(kwargs.get("choice") or ""))
        key = (str(kwargs.get("session_id") or ""), str(kwargs.get("tool_call_id") or ""))
        if not answer or not all(key) or not str(kwargs.get("description") or "").startswith("customs"):
            return None
        with _PENDING_LOCK:
            incident_id = _PENDING.pop(key, None)
        if incident_id:
            alerts.record_decision(_DATA_DIR, incident_id, answer)
    except Exception as exc:
        alerts.log_error(_DATA_DIR, "post_approval_response", exc)
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
        sid = kwargs.get("session_id") or ""
        before, _cur = _log_events(sid, tool_name, [(events.BAIT_HIT, "value in result: " + _value_names(hits), True)])
        _record(index, sid, tool_name, decision,
                {"value_name": _value_names(hits), "action_taken": "redacted"}, before=before)
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
            before, _cur = _log_events(session_id, "llm_request",
                                       [(events.BAIT_HIT, "value in model request: " + _value_names(fresh), True)])
            _record(index, session_id, "llm_request", decision,
                    {"value_name": _value_names(fresh), "action_taken": "redacted"}, before=before)
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
        PROV.load(_DATA_DIR)
        LOCK.load(_DATA_DIR)
    except Exception:
        _DATA_DIR = None
    ctx.register_hook("pre_tool_call", on_pre_tool_call)
    ctx.register_hook("post_tool_call", on_post_tool_call)
    ctx.register_hook("transform_tool_result", on_transform_tool_result)
    ctx.register_hook("post_approval_response", on_post_approval_response)
    ctx.register_middleware("llm_request", on_llm_request)
    try:
        from .commands import make_handler
        runtime = SimpleNamespace(
            lockdown=LOCK, settings=_settings, provenance=PROV)
        ctx.register_command(
            "customs",
            make_handler(ctx, runtime),
            description="customs: plant fake secrets, see tripwire incidents",
            args_hint="plant [N] | blend N [--preview] | add <path> | status | "
                      "unplant [path] | incidents [N] | export [N] | unlock | check",
        )
    except Exception as exc:
        alerts.log_error(_DATA_DIR, "register_command", exc)
    try:
        valuescan.table(bait.load_index())  # warm the caches so the first call is fast
        _session_cwd()
    except Exception:
        pass
