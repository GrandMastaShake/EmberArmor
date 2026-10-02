"""Gate configuration: where the ledger lives and which mode the gate runs in.

Everything is read from an environment mapping passed in by the caller, so
tests never touch the real home directory.  ``EMBER_HOME`` replaces
``~/.ember``.
"""

from __future__ import annotations

import json
from collections.abc import Mapping
from pathlib import Path
from typing import Any

MODES = ("observe", "enforce")
_FALSE_WORDS = frozenset({"0", "false", "no", "off"})


class ConfigError(ValueError):
    """The gate configuration is unreadable or invalid."""


def ember_home(env: Mapping[str, str]) -> Path:
    """Directory holding the user ledger, configuration and audit log."""
    override = env.get("EMBER_HOME")
    return Path(override) if override else Path.home() / ".ember"


def read_config(env: Mapping[str, str]) -> dict[str, Any]:
    """Contents of ``config.json`` in the Ember home, or ``{}`` if absent."""
    path = ember_home(env) / "config.json"
    try:
        text = path.read_text(encoding="utf-8")
    except FileNotFoundError:
        return {}
    except OSError as exc:
        raise ConfigError(f"cannot read {path}: {exc}") from exc
    try:
        config = json.loads(text)
    except json.JSONDecodeError as exc:
        raise ConfigError(f"{path} is not valid JSON: {exc}") from exc
    if not isinstance(config, dict):
        raise ConfigError(f"{path} must contain a JSON object")
    return config


def gate_mode(env: Mapping[str, str]) -> str:
    """``observe`` or ``enforce``.

    Taken from ``EMBER_GATE_MODE``, else ``config.json``, else ``observe``.

    Raises
    ------
    ConfigError
        If a mode is configured but is not one of the two known values.
    """
    mode = env.get("EMBER_GATE_MODE") or read_config(env).get("mode") or "observe"
    if mode not in MODES:
        raise ConfigError(f"unknown gate mode {mode!r} (expected observe or enforce)")
    return str(mode)


def builtin_enabled(env: Mapping[str, str]) -> bool:
    """False when the built-in pack was disabled by the user.

    ``EMBER_GATE_BUILTIN=0`` or ``"builtin": false`` in ``config.json``.  A
    project ledger cannot disable it.
    """
    flag = env.get("EMBER_GATE_BUILTIN")
    if flag is not None:
        return flag.strip().lower() not in _FALSE_WORDS
    return read_config(env).get("builtin", True) is not False
