"""customs, Phase 0 probe.

Writes down exactly what Hermes passes to our hooks, so the real
plugin is built on real data instead of guesses.
"""
import json
import time
from pathlib import Path

LOG = Path(__file__).parent / "probe.log"


def _write(event, data):
    # Never let logging crash anything.
    try:
        line = {"time": time.strftime("%H:%M:%S"), "event": event, **data}
        with LOG.open("a", encoding="utf-8") as f:
            f.write(json.dumps(line, default=str) + "\n")
    except Exception:
        pass


def _short(value, limit=800):
    try:
        text = value if isinstance(value, str) else json.dumps(value, default=str)
    except Exception:
        text = repr(value)
    return text[:limit]


def on_pre_tool_call(tool_name=None, args=None, **kwargs):
    # Runs BEFORE every tool call. If this crashes, Hermes blocks the tool,
    # so everything sits inside try/except.
    try:
        _write("pre_tool_call", {
            "tool": tool_name,
            "args": _short(args),
            "other_fields": sorted(kwargs),
        })
        # Test switch: anything mentioning this word gets blocked on purpose.
        if "customs-block-test" in _short(args, 100000):
            return {"action": "block", "message": "customs probe: blocked a test call on purpose."}
    except Exception as exc:
        _write("probe_error", {"where": "pre_tool_call", "error": repr(exc)})
    return None


def on_post_tool_call(tool_name=None, args=None, result=None, **kwargs):
    # Runs AFTER every tool call. Only watches, never changes anything.
    try:
        _write("post_tool_call", {
            "tool": tool_name,
            "status": kwargs.get("status"),
            "result": _short(result, 400),
        })
    except Exception:
        pass


def on_llm_request(**kwargs):
    # Runs before each request to the AI model. We only record its shape.
    try:
        request = kwargs.get("request") or {}
        _write("llm_request", {
            "request_keys": sorted(request),
            "other_fields": sorted(k for k in kwargs if k not in ("request", "original_request")),
            "message_count": len(request.get("messages") or request.get("input") or []),
        })
    except Exception:
        pass
    return None  # None means: leave the request unchanged


def register(ctx):
    ctx.register_hook("pre_tool_call", on_pre_tool_call)
    ctx.register_hook("post_tool_call", on_post_tool_call)
    ctx.register_middleware("llm_request", on_llm_request)
    try:
        from . import bait
        bait.configure(ctx.state.data_dir)  # where load_index() finds the registry
    except Exception as exc:
        _write("probe_error", {"where": "bait.configure", "error": repr(exc)})
    try:
        from .commands import make_handler
        ctx.register_command(
            "customs",
            make_handler(ctx),
            description="customs: plant fake secrets and check on them",
            args_hint="plant [N] | blend N [--preview] | add <path> | status | unplant [path]",
        )
    except Exception as exc:
        _write("probe_error", {"where": "register_command", "error": repr(exc)})