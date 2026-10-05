"""Nearest enclosing git repository of a directory (``applies.repo_root``).

The one place where judging a call reads the filesystem.  The lookup walks
up from a directory and asks, for each directory on the way, whether it
holds a ``.git`` entry (a directory, or the file a worktree or a submodule
has there).  It makes ``lstat`` calls only: no file is opened and no ``git``
process is started.  The engine loads this module the first time a rule or
an exception with ``repo_root`` has to be judged, and not before.
"""

from __future__ import annotations

import errno
import os
from collections.abc import Callable

from ember_armor.ledger.paths import UNKNOWN_DIR

#: ``finder(directory)``: the root of the nearest enclosing repository of a
#: normalised directory, ``None`` when there is none, ``UNKNOWN_DIR`` when
#: it was not looked for.  Raises :class:`OSError` when the lookup fails.
Finder = Callable[[str], str | None]
#: Errors that mean "nothing by that name can be there".
_ABSENT = (errno.ENOENT, errno.ENOTDIR, errno.EINVAL, errno.ENAMETOOLONG)


def parent(directory: str) -> str | None:
    """The directory above a normalised *directory*; ``None`` for a root."""
    if directory.endswith("/"):
        return None  # "/", "C:/" or "//host/share/"
    head = directory.rsplit("/", 1)[0]
    if not head:
        return "/"
    return f"{head}/" if len(head) == 2 and head[1] == ":" else head


def has_git(directory: str) -> bool:
    """True when *directory* holds a ``.git`` entry.

    Raises
    ------
    OSError
        If the filesystem will not say (permission denied, an input/output
        error).  A name that cannot exist is simply not there.
    """
    try:
        os.lstat(f"{directory.rstrip('/')}/.git")
    except (FileNotFoundError, NotADirectoryError, ValueError):
        return False
    except OSError as exc:
        if exc.errno in _ABSENT:
            return False
        raise
    return True


def find_root(directory: str, probe: Callable[[str], bool] = has_git) -> str | None:
    """Root of the nearest git repository at or above *directory*.

    A directory that does not exist is looked up from its nearest existing
    ancestor, because every missing level simply holds no ``.git``.  A
    network or device path (two leading separators) and a path with an
    unresolved variable are not looked up at all: the answer is
    :data:`~ember_armor.ledger.paths.UNKNOWN_DIR`.

    Parameters
    ----------
    directory:
        A normalised path (see :mod:`ember_armor.ledger.paths`).
    probe:
        ``probe(directory)`` saying whether the directory holds ``.git``.

    Raises
    ------
    OSError
        If a probe fails.
    """
    if directory.startswith("//") or "$" in directory or directory == UNKNOWN_DIR:
        return UNKNOWN_DIR
    current: str | None = directory
    while current is not None:
        if probe(current):
            return current
        current = parent(current)
    return None


def finder(windows: bool) -> Finder:
    """The lookup on the real filesystem for one path flavour.

    With the Windows flavour only a path on a drive is looked up.  Anything
    else (``/srv/app`` inside WSL) names no directory this machine's
    filesystem can be asked about.
    """
    if not windows:
        return find_root

    def find(directory: str) -> str | None:
        on_drive = directory[1:3] == ":/" and directory[:1].isalpha()
        return find_root(directory) if on_drive else UNKNOWN_DIR

    return find
