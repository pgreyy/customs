"""customs correlate: spot a chain of steps worth a human look. Alert only.

Pure Python, no Hermes imports, deterministic. It reads the session event log
(events.py) and answers one question for a call that would send data out:
did this session, within the window, also search for credentials and then
package or encode something? If the combination is strong, the caller asks
the user to approve the call. It never blocks: the bait tripwire is the only
hard block. A finding says the steps were seen together, never that one
caused another.

A finding needs all of:
  1. the current call is an outbound attempt (an upload, a raw socket, a send);
  2. earlier in the window, a credential-recon or bait-hit event;
  3. after that, packaging that is clearly about credentials: a staging or
     encoding step that itself names a credential location, or an upload that
     names one, or both a staging step and a non-compression encoding step.
Single signals (an upload, a credential read, an archive) never match on their
own, and plain compression (gzip, xz...) never counts as encoding here.
"""
from __future__ import annotations

from dataclasses import dataclass, field

from . import events as ev

WINDOW_SECONDS = 30 * 60
_COMPRESSORS = ("gzip", "bzip2", "xz", "zstd")


@dataclass
class Finding:
    events: list = field(default_factory=list)  # the steps, oldest first
    last_seq: int = 0
    reason: str = ""


def _is_compression(e: dict) -> bool:
    return e["type"] == ev.ENCODING and str(e.get("label", "")).split(" ")[0] in _COMPRESSORS


def evaluate(events: list, current_seqs, window: float = WINDOW_SECONDS):
    """A Finding or None. events: dicts from EventLog (oldest first);
    current_seqs: the seqs of the call being decided."""
    current = set(current_seqs or ())
    if not events or not current:
        return None
    outs = [e for e in events if e["seq"] in current and e["type"] == ev.OUTBOUND]
    if not outs:
        return None
    out = outs[0]
    last = max(e["seq"] for e in events if e["seq"] in current)
    recent = [e for e in events if e["seq"] <= last and out["t"] - e["t"] <= window]
    recon = next((e for e in recent if e["type"] in (ev.RECON, ev.BAIT_HIT) and e["seq"] < out["seq"]), None)
    if recon is None:
        return None
    after = [e for e in recent if recon["seq"] < e["seq"] < out["seq"]]
    staging = [e for e in after if e["type"] == ev.STAGING]
    encoding = [e for e in after if e["type"] == ev.ENCODING and not _is_compression(e)]
    cred_packaging = [e for e in staging + encoding if e.get("cred")]
    if cred_packaging:
        reason = "credential search, then packaging that names a credential location, then an upload"
    elif out.get("cred"):
        reason = "credential search, then an upload that names a credential location"
    elif staging and encoding:
        reason = "credential search, then archiving and encoding, then an upload"
    else:
        return None
    untrusted = [e for e in recent if e["type"] == ev.UNTRUSTED_READ and e["seq"] < recon["seq"]]
    steps = untrusted[-1:] + [recon] + sorted({e["seq"]: e for e in staging + encoding}.values(),
                                              key=lambda e: e["seq"])[:4] + [out]
    return Finding(events=steps, last_seq=last, reason=reason)
