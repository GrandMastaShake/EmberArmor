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
        "ember_armor.ledger.remind",
        "ember_armor.ledger.announce",
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


LAZY = (
    "typing",
    "fractions",
    "hashlib",
    "argparse",
    "base64",
    "ember_armor.ledger.cli",
    "ember_armor.ledger.lint",
    "ember_armor.ledger.replay",
    "ember_armor.ledger.remind",
    "ember_armor.ledger.announce",
    "ember_armor.ledger.repo",
    "ember_armor.ledger.shell.bash",
    "ember_armor.ledger.shell.powershell",
    "ember_armor.ledger.shell.cmd",
    "ember_armor.ledger.shellpaths",
)
LAZY_PROBE = """
import json, sys
import ember_armor.ledger.hook
before = sorted(m for m in {lazy!r} if m in sys.modules)
from ember_armor.ledger.facts import extract
extract({{"tool_name": "Bash", "cwd": "/w", "tool_input": {{"command": "ls"}}}})
after = sorted(m for m in {lazy!r} if m in sys.modules)
print(json.dumps({{"before": before, "after": after}}))
"""


def test_the_hook_path_loads_only_what_the_call_needs() -> None:
    env = {k: v for k, v in os.environ.items() if not k.startswith("EMBER_")}
    done = subprocess.run(
        [sys.executable, "-c", LAZY_PROBE.format(lazy=LAZY)],
        capture_output=True,
        text=True,
        env=env,
        timeout=60,
        check=False,
    )
    assert done.returncode == 0, done.stderr
    loaded = json.loads(done.stdout)
    assert loaded["before"] == []
    # A Bash call needs the Bash parser and the path tables, nothing else.
    assert loaded["after"] == [
        "ember_armor.ledger.shell.bash",
        "ember_armor.ledger.shellpaths",
    ]
