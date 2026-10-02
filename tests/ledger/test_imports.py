"""The gate's hot path must stay light and must not start the web application.

``ember_armor.core.config`` exits the process when secrets are missing, so
importing the ledger in a fresh interpreter *without* those secrets is the
real check that nothing on the hot path pulls it in.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys

import pytest

HEAVY = (
    "pydantic",
    "pydantic_settings",
    "fastapi",
    "starlette",
    "structlog",
    "z3",
    "uvicorn",
    "httpx",
)

PROBE = """
import importlib, json, sys
importlib.import_module({module!r})
loaded = sorted(
    name for name in {heavy!r}
    if any(m == name or m.startswith(name + ".") for m in sys.modules)
)
web = sorted(m for m in sys.modules if m.startswith("ember_armor.")
             and not m.startswith("ember_armor.ledger"))
print(json.dumps({{"heavy": loaded, "web": web}}))
"""


def probe(module: str) -> dict[str, list[str]]:
    env = {k: v for k, v in os.environ.items() if not k.startswith("EMBER_")}
    done = subprocess.run(
        [sys.executable, "-c", PROBE.format(module=module, heavy=HEAVY)],
        capture_output=True,
        text=True,
        env=env,
        timeout=60,
        check=False,
    )
    assert done.returncode == 0, done.stderr
    return json.loads(done.stdout)


@pytest.mark.parametrize(
    "module",
    [
        "ember_armor.ledger.hook",
        "ember_armor.ledger",
        "ember_armor.ledger.cli",
        "ember_armor.ledger.gate",
        "ember_armor.ledger.lint",
        "ember_armor.ledger.replay",
        "ember_armor",
    ],
)
def test_fresh_interpreter_stays_on_the_standard_library(module: str) -> None:
    assert probe(module) == {"heavy": [], "web": []}


def test_create_app_is_still_importable() -> None:
    import ember_armor
    from ember_armor import create_app
    from ember_armor.api.main import create_app as real

    assert create_app is real
    assert ember_armor.create_app is real
    assert ember_armor.__version__ == "0.2.0"
    assert set(ember_armor.__all__) == {"create_app", "__version__"}


def test_unknown_attribute_raises() -> None:
    import ember_armor

    with pytest.raises(AttributeError, match="no attribute 'nope'"):
        _ = ember_armor.nope
