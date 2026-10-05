"""Programs that run another command given in their arguments.

``sudo``, ``env``, ``timeout``, ``xargs``, package runners (``npx``,
``pnpm dlx``, ``uvx``, ``uv run``), container exec and ``wsl`` are removed so
that the wrapped command is the one the rules see.  Shared by the Bash and
PowerShell parsers; nothing is executed.
"""

from __future__ import annotations

import re
from collections.abc import Sequence
from dataclasses import dataclass

from ember_armor.ledger.shell.core import UNKNOWN_DIR, program_name

#: More stacked wrappers than this is a parse error, not a silent pass.
MAX_WRAPPERS = 32
_ENV_ASSIGN_RE = re.compile(r"([A-Za-z_]\w*)=")


@dataclass(frozen=True, eq=False, repr=False)
class Wrapper:
    """A program that runs another command given in its arguments.

    ``value_flags`` take a value; ``leads`` are the subcommands that make
    the program a wrapper (``pnpm dlx``, ``docker compose exec``); ``skip``
    positionals stand before the wrapped command (a duration, a container);
    ``versioned`` runners accept ``name@version`` for the command.  When
    ``only_flags`` is set, any other flag means the program is doing
    something else (``wsl --shutdown``).  ``dir_flags`` name the directory
    the wrapped command starts in (``env -C dir``); with ``dir_unknown``
    such a flag only says that the directory is not the shell's.
    """

    value_flags: frozenset[str] = frozenset()
    skip: int = 0
    leads: tuple[tuple[str, ...], ...] = ()
    versioned: bool = False
    only_flags: frozenset[str] | None = None
    dir_flags: frozenset[str] = frozenset()
    dir_unknown: bool = False


@dataclass(frozen=True, eq=False, repr=False)
class Unwrapped:
    """Where the wrapped command starts.

    ``program`` replaces the command word when a runner named a version
    (``vercel@latest``); ``capped`` is set when more than
    :data:`MAX_WRAPPERS` were stacked; ``assigned`` are the variables an
    ``env`` wrapper set; ``names`` are the wrappers removed, outermost first;
    ``chdir`` are the directories they start the command in, outermost first
    (:data:`~ember_armor.ledger.shell.core.UNKNOWN_DIR` for one that cannot
    be known).
    """

    start: int = 0
    program: str | None = None
    capped: bool = False
    assigned: tuple[str, ...] = ()
    names: tuple[str, ...] = ()
    chdir: tuple[str, ...] = ()


_CONTAINER_FLAGS = frozenset(
    {"-f", "--file", "-p", "--project-name", "--profile", "--env-file", "-e",
     "--env", "-u", "--user", "-w", "--workdir", "-H", "--host", "--context",
     "-c", "--index"}
)  # fmt: skip
_CONTAINER = Wrapper(_CONTAINER_FLAGS, 1, (("exec",), ("compose", "exec")))
_SUDO = Wrapper(
    frozenset({"-u", "-g", "-h", "-p", "-C", "-D", "-R", "-T", "-r", "-t", "--user",
               "--group", "--host", "--prompt", "--chdir", "--integrity",
               "--loglevel"}),
    dir_flags=frozenset({"-D", "--chdir"}),
)  # fmt: skip
_WSL_VALUES = frozenset(
    {"-d", "--distribution", "-u", "--user", "--cd", "--shell-type"}
)
WRAPPERS: dict[str, Wrapper] = {
    "sudo": _SUDO,
    "gsudo": _SUDO,
    "doas": Wrapper(frozenset({"-u", "-C"})),
    "env": Wrapper(
        frozenset({"-u", "-C", "--unset", "--chdir"}),
        dir_flags=frozenset({"-C", "--chdir"}),
    ),
    "nohup": Wrapper(),
    "time": Wrapper(frozenset({"-f", "-o"})),
    "nice": Wrapper(frozenset({"-n"})),
    "ionice": Wrapper(frozenset({"-c", "-n", "-p"})),
    "timeout": Wrapper(frozenset({"-s", "-k", "--signal", "--kill-after"}), 1),
    "stdbuf": Wrapper(frozenset({"-i", "-o", "-e"})),
    "command": Wrapper(),
    "builtin": Wrapper(),
    "exec": Wrapper(frozenset({"-a"})),
    "xargs": Wrapper(
        frozenset({"-I", "-n", "-P", "-L", "-d", "-E", "-s", "-a", "--max-args",
                   "--max-procs", "--delimiter"})
    ),
    "setsid": Wrapper(),
    "winpty": Wrapper(),
    "busybox": Wrapper(),
    "wsl": Wrapper(
        _WSL_VALUES,
        only_flags=_WSL_VALUES | {"-e", "--exec"},
        dir_flags=frozenset({"--cd"}),
    ),
    "npx": Wrapper(frozenset({"-p", "--package"}), versioned=True),
    "bunx": Wrapper(versioned=True),
    "uvx": Wrapper(frozenset({"--from", "--with", "-p", "--python"}), versioned=True),
    "uv": Wrapper(
        frozenset({"--with", "-p", "--python", "--project", "--directory",
                   "--env-file", "--group", "--extra", "--package"}),
        leads=(("run",),),
        dir_flags=frozenset({"--directory"}),
    ),
    # Where ``npm exec`` starts the command under ``--prefix`` is npm's own
    # business: the directory is only known not to be the shell's.
    "npm": Wrapper(
        frozenset({"--prefix", "-C", "-w", "--workspace", "-p", "--package"}),
        leads=(("exec",), ("x",)),
        versioned=True,
        dir_flags=frozenset({"--prefix", "-C"}),
        dir_unknown=True,
    ),
    "pnpm": Wrapper(
        frozenset({"-C", "--dir", "-F", "--filter"}),
        leads=(("dlx",), ("exec",)),
        versioned=True,
        dir_flags=frozenset({"-C", "--dir"}),
    ),
    "yarn": Wrapper(
        frozenset({"--cwd"}),
        leads=(("dlx",), ("exec",)),
        versioned=True,
        dir_flags=frozenset({"--cwd"}),
    ),
    "bun": Wrapper(leads=(("x",),), versioned=True),
    "pipx": Wrapper(
        frozenset({"--spec", "--python"}), leads=(("run",),), versioned=True
    ),
    "docker": _CONTAINER,
    "podman": _CONTAINER,
    "docker-compose": Wrapper(_CONTAINER_FLAGS, 1, (("exec",),)),
}  # fmt: skip


def _directory(texts: Sequence[str], at: int, spec: Wrapper) -> list[str]:
    """The directory the wrapper's flag at *at* starts the command in, if any.

    ``-C dir``, ``--chdir dir``, ``--chdir=dir`` and ``-Cdir``.
    """
    text = texts[at]
    flag, attached, value = text.partition("=")
    if text in spec.dir_flags:
        value = texts[at + 1] if at + 1 < len(texts) else ""
    elif not (attached and flag in spec.dir_flags):
        if text.startswith("--") or text[:2] not in spec.dir_flags:
            return []
        value = text[2:]
    return [UNKNOWN_DIR if spec.dir_unknown or not value else value]


def _wrapped_at(
    texts: Sequence[str],
    start: int,
    spec: Wrapper,
    assigned: list[str],
    chdir: list[str],
) -> int | None:
    """Index of the command a wrapper at *start* runs, or ``None`` if none."""
    wrapper = program_name(texts[start])
    env = wrapper in ("env", "sudo", "gsudo")  # they take NAME=value first
    lead: tuple[str, ...] = ()
    pending = bool(spec.leads)
    skip = spec.skip
    names: list[str] = []
    moves: list[str] = []
    i = start + 1
    found: int | None = None
    while i < len(texts):
        text = texts[i]
        setting = _ENV_ASSIGN_RE.match(text) if env else None
        if text == "--":
            found = None if pending else i + 1 + skip
            break
        if setting is not None:
            names.append(setting.group(1))
            i += 1
        elif text.startswith("-") and text != "-":
            if spec.only_flags is not None and text not in spec.only_flags:
                return None
            if wrapper == "env" and text in ("-u", "--unset"):
                names += texts[i + 1 : i + 2]
            moves += _directory(texts, i, spec)
            i += 2 if text in spec.value_flags else 1
        elif pending:
            lead += (text,)
            if not any(known[: len(lead)] == lead for known in spec.leads):
                return None
            pending = lead not in spec.leads
            i += 1
        else:
            found = i + skip
            break
    if found is not None and found < len(texts):
        assigned += names
        chdir += moves
        return found
    return None


def unwrap(texts: Sequence[str], literal: Sequence[bool]) -> Unwrapped:
    """Find the command behind ``sudo``-like wrappers.

    Parameters
    ----------
    texts:
        The words of one simple command.
    literal:
        For each word, whether its program name is literal text (a wrapper
        named through an expansion is not followed).
    """
    start = 0
    program: str | None = None
    assigned: list[str] = []
    names: list[str] = []
    chdir: list[str] = []
    for _ in range(MAX_WRAPPERS):
        if start >= len(texts):
            break
        name = program_name(program or texts[start])
        spec = WRAPPERS.get(name)
        if spec is None or not literal[start]:
            break
        if name == "command" and any(
            text in ("-v", "-V") for text in texts[start + 1 : start + 3]
        ):
            break
        inner = _wrapped_at(texts, start, spec, assigned, chdir)
        if inner is None:
            break
        start, program = inner, None
        names.append(name)
        version = texts[start].find("@", 1) if spec.versioned else -1
        if version > 0:
            program = texts[start][:version]
    else:
        capped = start < len(texts) and program_name(texts[start]) in WRAPPERS
        return Unwrapped(
            start, program, capped, tuple(assigned), tuple(names), tuple(chdir)
        )
    return Unwrapped(start, program, False, tuple(assigned), tuple(names), tuple(chdir))
