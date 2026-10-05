"""Recognise a command that starts another shell or interpreter.

``bash -c '...'``, ``sh -c``, ``powershell -Command "..."``, ``pwsh -c`` and
``cmd /c`` carry a script as an argument; :func:`inspect` extracts it so the
caller can parse it recursively.  Nothing is executed.
"""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass

from ember_armor.ledger.shell.core import (
    BASH_SHELLS,
    INTERPRETERS,
    POWERSHELLS,
    UNKNOWN_DIR,
    program_name,
)

_PS_ALIASES = {
    "c": "command",
    "e": "encodedcommand",
    "ec": "encodedcommand",
    "enc": "encodedcommand",
    "f": "file",
    "ex": "executionpolicy",
    "ep": "executionpolicy",
    "w": "windowstyle",
    "wd": "workingdirectory",
    "v": "version",
}
_PS_OPTIONS = (
    "command",
    "encodedcommand",
    "executionpolicy",
    "file",
    "noprofile",
    "noninteractive",
    "nologo",
    "noexit",
    "windowstyle",
    "inputformat",
    "outputformat",
    "workingdirectory",
    "version",
    "configurationname",
    "settingsfile",
    "custompipename",
    "sta",
    "mta",
    "login",
    "interactive",
)
_PS_VALUE_OPTIONS = frozenset(
    {
        "executionpolicy",
        "windowstyle",
        "inputformat",
        "outputformat",
        "workingdirectory",
        "version",
        "configurationname",
        "settingsfile",
        "custompipename",
    }
)
_INLINE_CODE_FLAGS = frozenset(
    {"-c", "-e", "-E", "-m", "-p", "-r", "--eval", "--print", "-V", "--version", "-h"}
)


@dataclass(frozen=True, eq=False, repr=False)
class Nested:
    """How a command hands a script to another shell.

    ``kind`` is ``script`` (literal text in ``script``, starting at argument
    ``index``), ``stdin`` (the script arrives on standard input), ``file``
    (a script file is run) or ``encoded`` (an encoded command that could not
    be decoded).  ``shell`` is empty for a non-shell interpreter.  ``chdir``
    is the directory the shell is told to start in (``pwsh
    -WorkingDirectory dir``), empty when it starts where its parent is.
    """

    shell: str
    kind: str
    script: str = ""
    index: int = 0
    chdir: str = ""


def join_arguments(args: Sequence[str], quote: str) -> str:
    """Rebuild a script from several arguments, re-quoting ones with spaces."""
    if len(args) == 1:
        return args[0]
    doubled = quote * 2
    return " ".join(
        f"{quote}{a.replace(quote, doubled)}{quote}" if " " in a else a for a in args
    )


def _bash(argv: Sequence[str]) -> Nested:
    i, stdin = 1, False
    while i < len(argv):
        arg = argv[i]
        if arg == "--":
            script_file = not stdin and i + 1 < len(argv)
            return Nested("bash", "file" if script_file else "stdin")
        if arg == "-":
            return Nested("bash", "stdin")
        if arg.startswith("--"):
            i += 2 if arg in ("--rcfile", "--init-file") else 1
        elif len(arg) > 1 and arg[0] in "-+":
            cluster = arg[1:]
            if arg[0] == "-" and "c" in cluster:
                if i + 1 < len(argv):
                    return Nested("bash", "script", argv[i + 1], i + 1)
                return Nested("bash", "stdin")
            stdin = stdin or "s" in cluster
            i += 2 if cluster.endswith(("o", "O")) else 1
        else:
            return Nested("bash", "stdin" if stdin else "file")
    return Nested("bash", "stdin")


def _ps_option(arg: str) -> str | None:
    """Full name of a powershell.exe option, or ``None`` if not an option."""
    if len(arg) < 2 or arg[0] not in "-/":
        return None
    name = arg[1:].lower()
    if name in _PS_ALIASES:
        return _PS_ALIASES[name]
    return next((opt for opt in _PS_OPTIONS if opt.startswith(name)), "")


def _decode(encoded: str) -> str | None:
    import base64
    import binascii

    try:
        return base64.b64decode(encoded, validate=True).decode("utf-16-le")
    except (binascii.Error, UnicodeDecodeError, ValueError):
        return None


def _powershell(argv: Sequence[str]) -> Nested:
    i = 1
    chdir = ""
    while i < len(argv):
        option = _ps_option(argv[i])
        if option is None or option == "command":
            start = i if option is None else i + 1
            rest = list(argv[start:])
            if not rest or rest == ["-"]:
                return Nested("powershell", "stdin")
            if option is None and rest[0].lower().endswith(".ps1"):
                return Nested("powershell", "file")
            joined = join_arguments(rest, "'")
            return Nested("powershell", "script", joined, start, chdir)
        if option == "file":
            return Nested("powershell", "file")
        if option == "encodedcommand":
            script = _decode(argv[i + 1]) if i + 1 < len(argv) else None
            if script is None:
                return Nested("powershell", "encoded")
            return Nested("powershell", "script", script, len(argv), chdir)
        if option == "workingdirectory":
            # Without a value the directory is not the parent's, and not known.
            chdir = argv[i + 1] if i + 1 < len(argv) else UNKNOWN_DIR
        i += 2 if option in _PS_VALUE_OPTIONS else 1
    return Nested("powershell", "stdin")


def _cmd(argv: Sequence[str]) -> Nested | None:
    for i, arg in enumerate(argv[1:], start=1):
        if arg.lower().lstrip("/") in ("c", "k") and arg.startswith("/"):
            rest = argv[i + 1 :]
            if not rest:
                return None
            return Nested("cmd", "script", join_arguments(rest, '"'), i + 1)
    return None


def _inline_code(arg: str) -> bool:
    """True for a flag that carries the code or module (``-c``, ``-mjson.tool``)."""
    attached = arg[:2] in ("-c", "-e", "-m") and not arg.startswith("--")
    return attached or arg in _INLINE_CODE_FLAGS


def _interpreter(argv: Sequence[str]) -> Nested | None:
    args = argv[1:]
    if any(_inline_code(a) for a in args):
        return None
    if any(not a.startswith("-") for a in args):
        return None
    return Nested("", "stdin")


def inspect(argv: Sequence[str]) -> Nested | None:
    """Describe the nested shell started by *argv*, if it starts one.

    Parameters
    ----------
    argv:
        Argument vector of one simple command, wrappers already removed.

    Returns
    -------
    Nested | None
        ``None`` when the command is not a shell or interpreter invocation.
    """
    if not argv:
        return None
    program = program_name(argv[0])
    if program in BASH_SHELLS:
        return _bash(argv)
    if program in POWERSHELLS:
        return _powershell(argv)
    if program == "cmd":
        return _cmd(argv)
    if program in INTERPRETERS:
        return _interpreter(argv)
    return None
