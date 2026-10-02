"""Implications between rule predicates that hold for every possible call.

``ember-gate lint`` treats command and path predicates as boolean atoms.
The functions here say when one atom certainly implies another ("a path
under ``a/b`` is under ``a``").  They answer ``False`` whenever that is not
certain, and a missed implication only makes lint report less.  Nothing
here needs the solver or touches the filesystem.
"""

from __future__ import annotations

from collections.abc import Sequence

from ember_armor.ledger.model import CommandPred, PathPred
from ember_armor.ledger.paths import is_under, resolve_pattern

#: Paths that stand in for directories lint cannot know start with this.
_UNKNOWN = "/\x00"
_CWD = f"{_UNKNOWN}cwd"
_WILDCARDS = "*?["


def resolved(
    pattern: str, base: str | None, *, windows: bool, bare: bool = False
) -> str | None:
    """A rule's path pattern in comparable form, or ``None`` if there is none.

    The engine resolves a relative pattern against the rule's *base*, or
    against the working directory of the call when the rule has none; lint
    stands a placeholder in for that directory.  Patterns that use ``~`` or
    a variable are kept as written under a root of their own, so they
    compare only with each other and only for the same base.  A pattern with
    a ``..`` segment is not comparable at all.
    """
    text = pattern.replace("\\", "/") if windows else pattern
    if ".." in text.split("/"):
        return None
    if text.startswith("~") or "$" in text or "%" in text:
        root = base.encode("utf-8").hex() if base else "cwd"
        return f"{_UNKNOWN}var-{root}/{text.strip('/')}"
    return resolve_pattern(pattern, base or _CWD, windows=windows, bare_anywhere=bare)


def directory_inside(inner: str | None, outer: str | None, *, windows: bool) -> bool:
    """True when every path matching *inner* is certainly under *outer*.

    Both are patterns from :func:`resolved`.  A pattern with wildcards is
    only compared when both start with ``**/``, or when the two are equal.
    A pattern below the working directory, the home directory or a variable
    is somewhere lint does not know: it is inside a fixed directory only
    when that directory is ``/`` on POSIX, where everything is.
    """
    if inner is None or outer is None:
        return False
    if inner == outer:
        return True
    if inner.startswith("**/") and outer.startswith("**/"):
        inner = inner[3:]
    if any(char in inner for char in _WILDCARDS):
        return False
    if inner.startswith(_UNKNOWN) and not outer.startswith(("**/", _UNKNOWN)):
        return outer == "/" and not windows
    return is_under(inner, outer, windows=windows)


def _within(inner: Sequence[str], outer: Sequence[str], fold: bool) -> bool:
    """True when every name of *inner* is one of *outer*."""
    if set(inner) <= set(outer):
        return True
    return fold and {n.lower() for n in inner} <= {n.lower() for n in outer}


def command_implies(a: CommandPred, b: CommandPred) -> bool:
    """True when every simple command matching *a* certainly matches *b*."""
    fold = a.shell == "powershell"
    if b.shell != "any" and a.shell != b.shell:
        return False
    if b.program and not (a.program and _within(a.program, b.program, fold)):
        return False
    leading = a.subcommand[: len(b.subcommand)]
    if len(leading) < len(b.subcommand) or not all(
        _within([mine], [theirs], fold)
        for mine, theirs in zip(leading, b.subcommand, strict=True)
    ):
        return False
    if b.flags_any and not (
        (a.flags_any and set(a.flags_any) <= set(b.flags_any))
        or set(a.flags_all) & set(b.flags_any)
    ):
        return False
    if not all(f in a.flags_all or a.flags_any == (f,) for f in b.flags_all):
        return False
    # *a* must rule out at least what *b* rules out.  The argument fields
    # look at what follows the subcommand, so they compare for the same one.
    if not set(b.flags_none) <= set(a.flags_none):
        return False
    same_arguments = a.subcommand == b.subcommand
    if b.args_none_glob and not (
        same_arguments and set(b.args_none_glob) <= set(a.args_none_glob)
    ):
        return False
    if b.args_regex is not None and not (
        same_arguments and a.args_regex == b.args_regex
    ):
        return False
    return not b.args_any_glob or (
        bool(a.args_any_glob) and set(a.args_any_glob) <= set(b.args_any_glob)
    )


def path_implies(
    a: PathPred,
    base_a: str | None,
    b: PathPred,
    base_b: str | None,
    *,
    windows: bool,
) -> bool:
    """True when every path matching *a* certainly matches *b*.

    *base_a* and *base_b* are the directories the two rules resolve their
    relative patterns against (``Rule.base``).
    """
    if b.op != "any" and a.op != b.op:
        return False
    if b.recursive is not None and a.recursive != b.recursive:
        return False

    def texts(
        patterns: Sequence[str], base: str | None, bare: bool = False
    ) -> list[str | None]:
        return [resolved(p, base, windows=windows, bare=bare) for p in patterns]

    def inside(inner: str | None, outers: Sequence[str | None]) -> bool:
        return any(directory_inside(inner, o, windows=windows) for o in outers)

    a_under, a_glob = texts(a.under, base_a), texts(a.glob, base_a, True)
    b_under, b_glob = texts(b.under, base_b), texts(b.glob, base_b, True)
    if b_under and not any(
        group and all(inside(pattern, b_under) for pattern in group)
        for group in (a_under, a_glob)
    ):
        return False
    a_excluded = texts(a.not_under, base_a)
    if not all(inside(n, a_excluded) for n in texts(b.not_under, base_b)):
        return False
    a_spared = texts(a.not_glob, base_a, True)
    b_spared = texts(b.not_glob, base_b, True)
    if not all(g is not None and g in a_spared for g in b_spared):
        return False
    return not b_glob or (
        bool(a_glob) and all(g is not None and g in b_glob for g in a_glob)
    )
