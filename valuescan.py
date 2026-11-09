"""customs valuescan: does a text hold a fake bait value, plain or encoded?

Pure functions, no Hermes imports.

How it matches: every 16-character window of every fake value goes into a
dict (built once per registry change). A text is scanned by sliding a
16-character window over it and looking each slice up. Any hit means a fake
value, or at least 16 characters of one, is present.

To stay fast, windows only slide over runs of characters a fake value can be
made of ([A-Za-z0-9+/_-], 16 or more in a row); ordinary prose has few. The
text is also scanned in decoded views: URL-decoded, reversed, and every
base64/base64url run (20+ chars) and hex run (32+ chars) decoded. Decoding
the whole run means a value at any alignment inside an encoded blob is found.
"""
from __future__ import annotations

import base64
import binascii
import re
import urllib.parse
from dataclasses import dataclass, field

WINDOW = 16
MAX_SCAN = 2 * 1024 * 1024      # characters scanned per call
MAX_RUN = 256 * 1024            # longer runs are treated as binary blobs (images) and skipped
REPLACEMENT = "[customs: protected]"

# Values that are mostly fixed text; windows from them could match ordinary
# text. Their random part is watched as its own value (postgres_password).
SKIP_WINDOW_NAMES = {"postgres_url"}

_RUN_RE = re.compile(r"[A-Za-z0-9+/_\-]{16,}")
_B64_RE = re.compile(r"[A-Za-z0-9+/_\-]{20,}={0,2}")
_HEX_RE = re.compile(r"[0-9a-fA-F]{32,}")
_URLSAFE = str.maketrans("-_", "+/")


@dataclass
class Found:
    hits: set = field(default_factory=set)      # {(bait path, value name)}
    spans: list = field(default_factory=list)   # [(start, end)] in the text to replace
    url_hit: bool = False                       # found only in the URL-decoded view

    def __bool__(self):
        return bool(self.hits)


class _Table:
    def __init__(self, needles):
        self.windows = {}
        self.forms = []  # every stored encoded/plain form, for exact replacement
        for n in needles:
            if len(n.text) >= 12:
                self.forms.append(n.text)
            if n.form != "raw" or n.name in SKIP_WINDOW_NAMES or len(n.text) < WINDOW:
                continue
            key = (n.path, n.name)
            for i in range(len(n.text) - WINDOW + 1):
                w = n.text[i:i + WINDOW]
                prev = self.windows.get(w)
                if prev is None:
                    self.windows[w] = (key,)
                elif key not in prev:
                    self.windows[w] = prev + (key,)
        self.forms = sorted(set(self.forms), key=len, reverse=True)


_cache = [None, None]


def table(index) -> _Table:
    """Window table for a bait.BaitIndex, rebuilt only when the index changes."""
    if _cache[0] is not index.needles:
        _cache[1] = _Table(index.needles)
        _cache[0] = index.needles
    return _cache[1]


# ---------------------------------------------------------------- scanning

def _scan_runs(text: str, windows: dict, hits: set, spans=None) -> None:
    for m in _RUN_RE.finditer(text):
        run = m.group()
        if len(run) > MAX_RUN:
            continue
        base = m.start()
        for i in range(len(run) - WINDOW + 1):
            k = windows.get(run[i:i + WINDOW])
            if k:
                hits.update(k)
                if spans is not None:
                    spans.append((base + i, base + i + WINDOW))


def _b64_decodes(run: str):
    s = run.rstrip("=").translate(_URLSAFE)
    for off in range(4):  # the run may start a few characters before the real base64
        part = s[off:]
        if len(part) % 4 == 1:
            part = part[:-1]
        try:
            yield base64.b64decode(part + "=" * (-len(part) % 4)).decode("latin-1")
        except (binascii.Error, ValueError):
            continue


def _hex_decodes(run: str):
    for off in range(2):
        part = run[off:]
        part = part[: len(part) - (len(part) % 2)]
        try:
            yield bytes.fromhex(part).decode("latin-1")
        except ValueError:
            continue


def find(text: str, tab: _Table) -> Found:
    out = Found()
    if not text or not tab.windows:
        return out
    text = text[:MAX_SCAN]
    if "\x00" in text[:4096]:
        return out  # binary
    w = tab.windows
    # plain
    _scan_runs(text, w, out.hits, out.spans)
    # reversed
    rev_spans = []
    _scan_runs(text[::-1], w, out.hits, rev_spans)
    n = len(text)
    out.spans.extend((n - b, n - a) for a, b in rev_spans)
    # base64 / base64url runs, decoded whole
    for m in _B64_RE.finditer(text):
        run = m.group()
        if len(run) > MAX_RUN:
            continue
        for dec in _b64_decodes(run):
            probe = set()
            _scan_runs(dec, w, probe)
            if probe:
                out.hits.update(probe)
                out.spans.append(m.span())
                break
    # hex runs
    for m in _HEX_RE.finditer(text):
        run = m.group()
        if len(run) > MAX_RUN:
            continue
        for dec in _hex_decodes(run):
            probe = set()
            _scan_runs(dec, w, probe)
            if probe:
                out.hits.update(probe)
                out.spans.append(m.span())
                break
    # URL-decoded
    if "%" in text:
        dec = urllib.parse.unquote(text)
        if dec != text:
            probe = set()
            _scan_runs(dec, w, probe)
            new = probe - out.hits
            if probe:
                out.hits.update(probe)
                out.url_hit = out.url_hit or bool(new)
    return out


# ---------------------------------------------------------------- redaction

def _merge(spans):
    spans = sorted(spans)
    merged = []
    for a, b in spans:
        if merged and a <= merged[-1][1]:
            merged[-1][1] = max(merged[-1][1], b)
        else:
            merged.append([a, b])
    return merged


def redact(text: str, tab: _Table):
    """(new text, hits). Replaces every found value, partial value or encoded
    blob holding one with REPLACEMENT. If something is still found after that
    (for example inside URL-encoding), the whole text is replaced."""
    found = find(text, tab)
    if not found:
        return text, set()
    hits = set(found.hits)
    pieces, pos = [], 0
    for a, b in _merge(found.spans):
        pieces.append(text[pos:a])
        pieces.append(REPLACEMENT)
        pos = b
    pieces.append(text[pos:])
    new = "".join(pieces)
    for form in tab.forms:  # exact stored forms (URL-encoded, hex, ...) left over
        if form in new:
            new = new.replace(form, REPLACEMENT)
    again = find(new, tab)
    if again:
        hits |= again.hits
        return REPLACEMENT, hits
    return new, hits


def collect_strings(obj, out: list, depth: int = 0, skip_top_keys=()):
    """Every string in nested dicts/lists, in order, as (container, key, text)."""
    if depth > 40:
        return
    if isinstance(obj, dict):
        for k, v in obj.items():
            if depth == 0 and k in skip_top_keys:
                continue
            if isinstance(v, str):
                out.append((obj, k, v))
            else:
                collect_strings(v, out, depth + 1)
    elif isinstance(obj, list):
        for i, v in enumerate(obj):
            if isinstance(v, str):
                out.append((obj, i, v))
            else:
                collect_strings(v, out, depth + 1)


def redact_strings(strings, tab: _Table, budget: int = MAX_SCAN):
    """strings: [(container, key, text)] oldest first. Scans newest first until
    the budget runs out. Returns ({(id(container), key): new text}, hits)."""
    repl, hits = {}, set()
    for container, key, text in reversed(strings):
        if budget <= 0:
            break
        budget -= min(len(text), MAX_SCAN)
        new, h = redact(text, tab)
        if h:
            repl[(id(container), key)] = new
            hits |= h
    return repl, hits


def copy_with(obj, repl: dict, depth: int = 0):
    """Copy of nested dicts/lists with the strings in repl swapped in. Other
    objects are kept as they are."""
    if depth > 40:
        return obj
    if isinstance(obj, dict):
        return {k: (repl[(id(obj), k)] if (id(obj), k) in repl else copy_with(v, repl, depth + 1))
                for k, v in obj.items()}
    if isinstance(obj, list):
        return [(repl[(id(obj), i)] if (id(obj), i) in repl else copy_with(v, repl, depth + 1))
                for i, v in enumerate(obj)]
    return obj
