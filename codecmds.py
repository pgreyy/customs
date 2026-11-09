"""customs codecmds: shell commands that Python code is about to run.

Pure Python, no Hermes imports. Used for execute_code and browser_exec, whose
`code` is Python. It parses the code with `ast` (never runs it) and returns the
command lines passed to subprocess, os.system and similar calls, so the same
script inspection and pipe-into-a-shell check as the terminal can look at them.

What it finds:
  - a string argument:              os.system("bash x.sh"), subprocess.run("...", shell=True)
  - a list or tuple argument:       subprocess.run(["bash", "x.sh"])
  - os.exec*/spawn* argument lists: os.execlp("bash", "bash", "x.sh")
  - a variable assigned a string or list earlier in the code
  - f-strings, with each {...} part replaced by a placeholder
Anything built at run time beyond that is not seen. If the code doesn't parse,
quoted strings that contain a space are used instead.
"""
from __future__ import annotations

import ast
import re

MAX_CODE = 65536
MAX_COMMANDS = 20

# Calls that run a command. Module attribute calls (subprocess.run, os.system...)
# are matched when the module is subprocess, os, asyncio or pty, under any alias.
_MODULES = {"subprocess", "os", "asyncio", "pty", "commands"}
_FUNCS = {
    "system", "popen", "run", "call", "check_call", "check_output", "Popen", "getoutput",
    "getstatusoutput", "create_subprocess_shell", "create_subprocess_exec", "spawn",
    "execv", "execve", "execvp", "execvpe", "execl", "execle", "execlp", "execlpe",
    "spawnv", "spawnve", "spawnvp", "spawnvpe", "spawnl", "spawnle", "spawnlp", "spawnlpe",
    "posix_spawn", "posix_spawnp",
}
# Bare names that are unambiguous after `from subprocess import ...` / `from os import ...`.
_BARE = {"Popen", "check_output", "check_call", "getoutput", "getstatusoutput", "system", "popen"}
_ARG_LIST_FUNCS = {"execv", "execve", "execvp", "execvpe", "spawnv", "spawnve", "spawnvp", "spawnvpe",
                   "posix_spawn", "posix_spawnp"}
_VARARG_FUNCS = {"execl", "execle", "execlp", "execlpe", "spawnl", "spawnle", "spawnlp", "spawnlpe"}

_QUOTED_RE = re.compile(r"""("([^"\\\n]|\\.){3,}"|'([^'\\\n]|\\.){3,}')""")


def _text(node, names) -> str | None:
    """A command string from a node: a string, a list/tuple of strings, an f-string,
    or a name assigned one of those earlier. None when it can't be read."""
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return node.value
    if isinstance(node, ast.JoinedStr):
        parts = []
        for v in node.values:
            if isinstance(v, ast.Constant) and isinstance(v.value, str):
                parts.append(v.value)
            elif isinstance(v, ast.FormattedValue) and isinstance(v.value, ast.Name) and v.value.id in names:
                parts.append(names[v.value.id])
            else:
                parts.append("X")
        return "".join(parts)
    if isinstance(node, (ast.List, ast.Tuple)):
        words = [_text(e, names) for e in node.elts]
        words = [w if w is not None else "X" for w in words]
        return " ".join(words) if words else None
    if isinstance(node, ast.Name) and node.id in names:
        return names[node.id]
    return None


def _call_name(func, aliases):
    """(module, function) for a call target, or (None, None)."""
    if isinstance(func, ast.Attribute) and isinstance(func.value, ast.Name):
        mod = aliases.get(func.value.id, func.value.id)
        if mod in _MODULES and func.attr in _FUNCS:
            return mod, func.attr
    if isinstance(func, ast.Name):
        target = aliases.get(func.id)
        if target and "." in target:
            mod, fn = target.rsplit(".", 1)
            if mod in _MODULES and fn in _FUNCS:
                return mod, fn
        if func.id in _BARE:
            return "", func.id
    return None, None


def _from_ast(tree) -> list:
    aliases, names, out = {}, {}, []
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for a in node.names:
                aliases[a.asname or a.name] = a.name
        elif isinstance(node, ast.ImportFrom) and node.module:
            for a in node.names:
                aliases[a.asname or a.name] = f"{node.module}.{a.name}"
        elif isinstance(node, ast.Assign) and len(node.targets) == 1 and isinstance(node.targets[0], ast.Name):
            t = _text(node.value, names)
            if t is not None:
                names[node.targets[0].id] = t
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        mod, fn = _call_name(node.func, aliases)
        if fn is None:
            continue
        cmd = None
        if fn in _VARARG_FUNCS:
            words = [_text(a, names) for a in node.args[1:]]
            cmd = " ".join(w if w is not None else "X" for w in words) or None
        elif fn in _ARG_LIST_FUNCS and len(node.args) >= 2:
            cmd = _text(node.args[1], names)
        elif node.args:
            cmd = _text(node.args[0], names)
        if cmd is None:
            for kw in node.keywords:
                if kw.arg in ("args", "cmd", "command"):
                    cmd = _text(kw.value, names)
        if cmd and cmd.strip():
            out.append(cmd.strip())
        if len(out) >= MAX_COMMANDS:
            break
    return out


def commands_in_code(code: str) -> list:
    """Command lines the Python code passes to subprocess, os.system and the like.
    Never raises."""
    try:
        text = (code or "")[:MAX_CODE]
        try:
            tree = ast.parse(text)
        except (SyntaxError, ValueError):
            tree = None
        if tree is not None:
            return _from_ast(tree)
        out = []
        for m in _QUOTED_RE.finditer(text):
            s = m.group(0)[1:-1]
            if any(c.isspace() for c in s):
                out.append(s)
            if len(out) >= MAX_COMMANDS:
                break
        return out
    except Exception:
        return []
