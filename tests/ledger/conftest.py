"""Fixtures for the constraint-ledger tests."""

from __future__ import annotations

from pathlib import Path

import pytest


@pytest.fixture
def gate_env(tmp_path: Path) -> dict[str, str]:
    """Environment that keeps the gate inside ``tmp_path``.

    ``EMBER_LEDGER`` points at a (not yet existing) file so neither the real
    user ledger nor any project ledger above the temporary directory is read.
    """
    return {
        "EMBER_HOME": str(tmp_path / "ember-home"),
        "EMBER_LEDGER": str(tmp_path / "ledger.json"),
        "HOME": "/home/dev",
    }
