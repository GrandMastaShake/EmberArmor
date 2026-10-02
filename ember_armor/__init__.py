"""EmberArmor v2 — AI Behavioral Safety Infrastructure."""

from __future__ import annotations

from typing import Any

__version__ = "0.2.0"

__all__ = ["create_app", "__version__"]


def __getattr__(name: str) -> Any:
    """Import the web application only when ``create_app`` is asked for.

    ``ember_armor.api.main`` pulls in the settings singleton, which exits the
    process when secrets are missing.  The constraint-ledger gate
    (``ember_armor.ledger``) must be importable without it.
    """
    if name == "create_app":
        from ember_armor.api.main import create_app

        return create_app
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
