"""Time the EmberArmor command hook against the resident gate (HTTP hook).

Run with the interpreter that has ember-armor installed, the one your
settings.json hook uses:

    python tests/bench/bench_resident.py            # 30 runs a case
    python tests/bench/bench_resident.py --runs 50

Nothing here touches your real Ember home: a throwaway home is made in the
temp directory with ``mode: remind``, ``EMBER_LEDGER`` points at an empty
ledger there (so no project-ledger walk), and the resident gate it starts
uses that home's own resident.json and port, and is stopped at the end.
The built-in pack is on, as in real use.

Cases, each timed with time.perf_counter() around the whole call:
  bare      python -I -c pass                         (interpreter floor)
  command   the printed command hook (HOOK_ARGS), event JSON on stdin
  resident  one fresh HTTP connection per call, POST /hook with the token
Payloads: ``git status`` (no rule fires) and ``git push --force origin
master`` (built-in builtin.git.force-push is reminded; a fresh session_id per
call so the 15-minute reminder limit never suppresses it). Every output is
checked: the reminder case must name the rule, the no-rule case must not.
"""

from __future__ import annotations

import argparse
import json
import platform
import statistics
import subprocess
import sys
import tempfile
import time
import uuid
from http.client import HTTPConnection
from pathlib import Path

from ember_armor.ledger import resident
from ember_armor.ledger.cli import HOOK_ARGS

RULE = "builtin.git.force-push"
PAYLOADS = {"no-rule": "git status", "reminder": "git push --force origin master"}


def body(cwd: str, command: str) -> bytes:
    return json.dumps({
        "session_id": f"bench-{uuid.uuid4().hex}",
        "transcript_path": "",
        "cwd": cwd,
        "hook_event_name": "PreToolUse",
        "tool_name": "Bash",
        "tool_input": {"command": command},
    }).encode("utf-8")


def check(case: str, out: str) -> None:
    named = RULE in out
    if case == "reminder" and not named:
        raise SystemExit(f"reminder case printed no reminder for {RULE}: {out[:300]!r}")
    if case == "no-rule" and named:
        raise SystemExit(f"no-rule case unexpectedly named {RULE}")


def stats(ms: list[float]) -> dict[str, float]:
    s = sorted(ms)
    p95 = s[min(len(s) - 1, round(0.95 * (len(s) - 1)))]
    return {"n": len(s), "median": round(statistics.median(s), 1),
            "p95": round(p95, 1), "min": round(s[0], 1), "max": round(s[-1], 1)}


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--runs", type=int, default=30)
    args = ap.parse_args()

    tmp = Path(tempfile.mkdtemp(prefix="ember-bench-"))
    home, work = tmp / "home", tmp / "work"
    home.mkdir(); work.mkdir()
    (home / "config.json").write_text(json.dumps({"mode": "remind"}), encoding="utf-8")
    (tmp / "ledger.json").write_text(json.dumps({"version": 1, "rules": []}), encoding="utf-8")
    env = {"EMBER_HOME": str(home), "EMBER_LEDGER": str(tmp / "ledger.json")}
    import os
    full_env = {**os.environ, **env}
    full_env.pop("EMBER_GATE_MODE", None)

    results: dict[str, dict[str, float]] = {}

    # Interpreter floor.
    ms = []
    for _ in range(args.runs):
        t = time.perf_counter()
        subprocess.run([sys.executable, "-I", "-c", "pass"], check=True)
        ms.append((time.perf_counter() - t) * 1000)
    results["bare"] = stats(ms)

    # Command hook, started as the installer prints it.
    for case, command in PAYLOADS.items():
        ms = []
        for i in range(args.runs + 1):
            b = body(str(work), command)
            t = time.perf_counter()
            p = subprocess.run([sys.executable, *HOOK_ARGS], input=b,
                               capture_output=True, env=full_env, check=False)
            dt = (time.perf_counter() - t) * 1000
            check(case, p.stdout.decode("utf-8", "replace"))
            if i:  # first call discarded (cold file cache)
                ms.append(dt)
        results[f"command/{case}"] = stats(ms)

    # Resident gate on the throwaway home.
    where = resident.address(env, create=True)
    state = resident.ensure(full_env, python=sys.executable, wait=15.0)
    if state != "running":
        raise SystemExit(f"resident gate did not come up: {state}")
    try:
        for case, command in PAYLOADS.items():
            ms = []
            for i in range(args.runs + 1):
                b = body(str(work), command)
                t = time.perf_counter()
                c = HTTPConnection(resident.HOST, where.port, timeout=20)
                c.request("POST", "/hook", body=b, headers={
                    resident.TOKEN_HEADER: where.token,
                    "Content-Type": "application/json"})
                r = c.getresponse(); out = r.read().decode("utf-8", "replace"); c.close()
                dt = (time.perf_counter() - t) * 1000
                if r.status != 200:
                    raise SystemExit(f"resident answered {r.status}")
                check(case, out)
                if i:
                    ms.append(dt)
            results[f"resident/{case}"] = stats(ms)
    finally:
        resident.stop(where)

    report = {
        "date": time.strftime("%Y-%m-%d"),
        "python": platform.python_version(),
        "platform": platform.platform(),
        "runs_per_case": args.runs,
        "results_ms": results,
        "home": str(home),
    }
    print(json.dumps(report, indent=2))
    print("\nmarkdown:")
    for k, v in results.items():
        print(f"- {k}: median {v['median']} ms, p95 {v['p95']} ms, "
              f"min {v['min']} ms, max {v['max']} ms (n={v['n']})")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
