"""Reading flags and operands out of a parsed argument vector.

Three flag conventions are understood:

- POSIX programs (in any shell): ``-rf`` contains ``-r`` and ``-f``,
  ``--flag=value`` carries ``--flag``, and everything after ``--`` is an
  operand.
- PowerShell cmdlets: parameter names are case-insensitive, may be
  abbreviated to a prefix (``-Rec`` for ``-Recurse``) and may carry an
  attached value (``-Confirm:$false``).
- Slash flags (``/s``, ``/q``): case-insensitive; the MSYS-escaped form
  ``//s`` is accepted.
"""

from __future__ import annotations

import re
from collections.abc import Collection, Sequence

from ember_armor.ledger.shell.core import SimpleCommand

_CMDLET_RE = re.compile(r"[A-Za-z]+-[A-Za-z]+")


def is_cmdlet(command: SimpleCommand) -> bool:
    """True for a PowerShell ``Verb-Noun`` cmdlet (after alias mapping)."""
    return (
        command.shell == "powershell"
        and bool(command.argv)
        and _CMDLET_RE.fullmatch(command.argv[0]) is not None
    )


def option_args(command: SimpleCommand) -> Sequence[str]:
    """Arguments in which flags may appear (those before a bare ``--``)."""
    args = command.argv[1:]
    if is_cmdlet(command) or "--" not in args:
        return args
    return args[: args.index("--")]


def has_flag(command: SimpleCommand, flag: str) -> bool:
    """True when *command* carries *flag* under its flag convention."""
    args = option_args(command)
    if is_cmdlet(command):
        wanted = flag.lower()
        names = (arg.partition(":")[0].lower() for arg in args)
        return any(
            len(name) > 1 and name[0] == "-" and wanted.startswith(name)
            for name in names
        )
    if flag.startswith("/"):
        wanted = flag.lstrip("/").lower()
        return any(
            arg.startswith("/") and arg.lstrip("/").lower() == wanted for arg in args
        )
    short = len(flag) == 2 and flag[0] == "-" and flag[1] != "-"
    for arg in args:
        if arg == flag or (flag.startswith("--") and arg.startswith(f"{flag}=")):
            return True
        clustered = len(arg) > 2 and arg[0] == "-" and arg[1] != "-"
        if short and clustered and flag[1] in arg[1:]:
            return True
    return False


def operand_positions(
    command: SimpleCommand,
    value_flags: Collection[str] = (),
    *,
    slash_flags: bool = False,
) -> list[int]:
    """Indexes in ``argv`` of the non-flag arguments of a native command.

    Parameters
    ----------
    command:
        The parsed simple command.
    value_flags:
        Flags that consume the following argument (``-C dir``), which is then
        not an operand.
    slash_flags:
        Treat ``/x`` arguments as flags (``cmd.exe`` built-ins).
    """
    found: list[int] = []
    argv = command.argv
    i, only_operands = 1, False
    while i < len(argv):
        arg = argv[i]
        if only_operands:
            found.append(i)
        elif arg == "--":
            only_operands = True
        elif arg in value_flags:
            i += 1
        elif (arg.startswith("-") and len(arg) > 1) or (
            slash_flags and arg.startswith("/")
        ):
            pass
        else:
            found.append(i)
        i += 1
    return found


def operands(
    command: SimpleCommand,
    value_flags: Collection[str] = (),
    *,
    slash_flags: bool = False,
) -> list[str]:
    """Non-flag arguments of a native (non-cmdlet) command, in order.

    Takes the parameters of :func:`operand_positions`.
    """
    positions = operand_positions(command, value_flags, slash_flags=slash_flags)
    return [command.argv[i] for i in positions]
