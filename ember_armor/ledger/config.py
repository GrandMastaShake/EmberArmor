"""Gate configuration: where the ledger lives and which mode the gate runs in.

Everything is read from an environment mapping passed in by the caller, so
tests never touch the real home directory.  ``EMBER_HOME`` replaces
``~/.ember``.

``config.json`` in the Ember home may hold ``mode`` (``observe``, ``remind``
or ``enforce``), ``builtin`` (``false`` switches the built-in pack off),
``disposable`` (directory patterns the built-in delete rules leave alone, in
addition to the pack's own list), ``shell_tools`` (tools whose input
carries a shell command, see :func:`shell_tools`), ``exceptions`` (the
owner's exceptions to rules, see :func:`rule_exceptions`) and
``remind_interval_minutes`` (see :func:`remind_interval`).  Anything else is
an error: a misspelt setting must not be read as "not set".
"""

from __future__ import annotations

import json
from collections.abc import Mapping
from pathlib import Path

TYPE_CHECKING = False
if TYPE_CHECKING:
    from datetime import date
    from typing import Any

    from ember_armor.ledger.exceptions import RuleException

MODES = ("observe", "remind", "enforce")
SHELLS = ("bash", "powershell", "cmd", "native")
#: Minutes before the same rule is reminded again in one session.
REMIND_INTERVAL_MINUTES = 15.0
_SETTINGS = (
    "mode",
    "builtin",
    "disposable",
    "shell_tools",
    "exceptions",
    "remind_interval_minutes",
)
_EXPECTED_MODES = "expected observe, remind or enforce"
_SHELL_TOOL_KEYS = ("shell", "field", "cwd")
_FALSE_WORDS = frozenset({"0", "false", "no", "off"})


class ConfigError(ValueError):
    """The gate configuration is unreadable or invalid."""


def ember_home(env: Mapping[str, str]) -> Path:
    """Directory holding the user ledger, configuration and audit log."""
    override = env.get("EMBER_HOME")
    return Path(override) if override else Path.home() / ".ember"


def _validate(config: Any, path: Path) -> dict[str, Any]:
    if not isinstance(config, dict):
        raise ConfigError(f"{path} must contain a JSON object")
    unknown = sorted(set(config) - set(_SETTINGS))
    if unknown:
        raise ConfigError(
            f"{path}: unknown setting(s) {', '.join(unknown)} "
            f"(known: {', '.join(_SETTINGS)})"
        )
    if "mode" in config and config["mode"] not in MODES:
        raise ConfigError(
            f"{path}: unknown gate mode {config['mode']!r} ({_EXPECTED_MODES})"
        )
    if not isinstance(config.get("builtin", True), bool):
        raise ConfigError(f"{path}: 'builtin' must be true or false")
    patterns = config.get("disposable", [])
    if not isinstance(patterns, list) or not all(
        isinstance(pattern, str) and pattern for pattern in patterns
    ):
        raise ConfigError(f"{path}: 'disposable' must be a list of path patterns")
    _validate_shell_tools(config.get("shell_tools", {}), path)
    _exceptions(config.get("exceptions", []), path)
    if "remind_interval_minutes" in config:
        _minutes(
            config["remind_interval_minutes"], f"{path}: 'remind_interval_minutes'"
        )
    return config


def _minutes(value: Any, where: str) -> float:
    """A reminder interval: a finite number of minutes, zero or more."""
    number = isinstance(value, int | float) and not isinstance(value, bool)
    if not number or not 0 <= value < float("inf"):
        raise ConfigError(f"{where} must be a number of minutes, 0 or more")
    return float(value)


def _exceptions(items: Any, path: Path) -> list[RuleException]:
    """The validated ``exceptions`` setting.

    The rule model is loaded only when there is an exception to check.
    """
    where = f"{path}: 'exceptions'"
    if not isinstance(items, list):
        raise ConfigError(f"{where} must be a list of exception objects")
    if not items:
        return []
    from ember_armor.ledger.model import LedgerError, parse_exception

    try:
        return [
            parse_exception(item, f"{where}[{index}]")
            for index, item in enumerate(items)
        ]
    except LedgerError as exc:
        raise ConfigError(str(exc)) from exc


def _validate_shell_tools(tools: Any, path: Path) -> None:
    where = f"{path}: 'shell_tools'"
    if not isinstance(tools, dict):
        raise ConfigError(f"{where} must map tool names to objects")
    for name, entry in tools.items():
        if not name or not isinstance(entry, dict):
            raise ConfigError(f"{where}: {name!r} must be an object with a 'shell'")
        unknown = sorted(set(entry) - set(_SHELL_TOOL_KEYS))
        if unknown:
            raise ConfigError(
                f"{where}: {name!r} has unknown key(s) {', '.join(unknown)} "
                f"(known: {', '.join(_SHELL_TOOL_KEYS)})"
            )
        if entry.get("shell") not in SHELLS:
            raise ConfigError(
                f"{where}: {name!r} needs 'shell', one of {', '.join(SHELLS)}"
            )
        for key in ("field", "cwd"):
            if not isinstance(entry.get(key, "x"), str) or entry.get(key) == "":
                raise ConfigError(f"{where}: {name!r}: '{key}' must be a field name")


def read_config(env: Mapping[str, str]) -> dict[str, Any]:
    """Validated contents of ``config.json`` in the Ember home (``{}`` if absent).

    A UTF-8 byte order mark is accepted, as written by Windows editors.

    Raises
    ------
    ConfigError
        If the file cannot be read or decoded, is not a JSON object, or
        holds an unknown setting or a value of the wrong type.
    """
    path = ember_home(env) / "config.json"
    try:
        text = path.read_text(encoding="utf-8-sig")
    except FileNotFoundError:
        return {}
    except (OSError, ValueError) as exc:
        raise ConfigError(f"cannot read {path}: {exc}") from exc
    try:
        config = json.loads(text)
    except (ValueError, RecursionError) as exc:
        raise ConfigError(f"{path} is not valid JSON: {exc}") from exc
    return _validate(config, path)


def gate_mode(env: Mapping[str, str]) -> str:
    """``observe``, ``remind`` or ``enforce``.

    Taken from ``EMBER_GATE_MODE``, else ``config.json``, else ``observe``.

    Raises
    ------
    ConfigError
        If a mode is configured but is not one of the three known values.
    """
    mode = env.get("EMBER_GATE_MODE") or read_config(env).get("mode") or "observe"
    if mode not in MODES:
        raise ConfigError(f"unknown gate mode {mode!r} ({_EXPECTED_MODES})")
    return str(mode)


def remind_interval(env: Mapping[str, str]) -> float:
    """Seconds before the same rule is reminded again in one session.

    Taken from ``EMBER_GATE_REMIND_INTERVAL`` (minutes), else
    ``remind_interval_minutes`` in ``config.json``, else 15 minutes.  Zero
    means every time.

    Raises
    ------
    ConfigError
        If the value is not a finite number of minutes, zero or more.
    """
    raw = env.get("EMBER_GATE_REMIND_INTERVAL")
    if raw:
        try:
            given: Any = float(raw)
        except ValueError:
            given = None
        return 60 * _minutes(given, "EMBER_GATE_REMIND_INTERVAL")
    configured = read_config(env).get("remind_interval_minutes")
    return 60 * (REMIND_INTERVAL_MINUTES if configured is None else float(configured))


def builtin_enabled(env: Mapping[str, str]) -> bool:
    """False when the built-in pack was disabled by the user.

    ``EMBER_GATE_BUILTIN=0`` or ``"builtin": false`` in ``config.json``.  A
    project ledger cannot disable it.
    """
    flag = env.get("EMBER_GATE_BUILTIN")
    if flag is not None:
        return flag.strip().lower() not in _FALSE_WORDS
    return bool(read_config(env).get("builtin", True))


def shell_tools(env: Mapping[str, str]) -> dict[str, dict[str, str]]:
    """The user's shell-carrying tools (``shell_tools`` in ``config.json``).

    Maps a tool name or glob to ``shell`` (``bash``, ``powershell``, ``cmd``
    or ``native``: PowerShell on Windows, Bash elsewhere), ``field`` (the
    input field that holds the command, ``command`` when left out) and
    optionally ``cwd`` (the input field that names the directory the command
    starts in).  The command of such a tool is parsed like that of the
    native shell tools.
    """
    return dict(read_config(env).get("shell_tools", {}))


def rule_exceptions(
    env: Mapping[str, str], today: date | None = None
) -> tuple[RuleException, ...]:
    """The owner's exceptions to rules (``exceptions`` in ``config.json``).

    Each is ``{"rule": id or glob, "reason": text}`` with at least one of
    ``cwd_under``, ``repo_root`` and ``when``, and optionally ``tools`` and
    ``expires``.  A rule that fires on a command an exception covers is
    dropped for that command, and the use is recorded.  Only this file can
    hold exceptions: a ledger, and so a repository, cannot.

    Parameters
    ----------
    env:
        Environment mapping selecting the Ember home.
    today:
        Leave out the exceptions that expired before this date; ``None``
        returns them all.

    Raises
    ------
    ConfigError
        If the configuration cannot be read or an exception is malformed.
    """
    path = ember_home(env) / "config.json"
    found = _exceptions(read_config(env).get("exceptions", []), path)
    return tuple(
        exception
        for exception in found
        if today is None or exception.expires is None or today <= exception.expires
    )


def disposable_patterns(env: Mapping[str, str]) -> tuple[str, ...]:
    """The user's own disposable directories (``disposable`` in ``config.json``).

    Only the user's configuration can name them; a project ledger cannot, so
    a repository cannot widen what the built-in delete rules let through.
    """
    return tuple(read_config(env).get("disposable", ()))
