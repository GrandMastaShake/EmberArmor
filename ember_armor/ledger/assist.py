"""Ask a model to draft the rules the literal shapes could not.

``ember-gate draft --model`` sends each sentence that
:mod:`ember_armor.ledger.draft` could not place to a model, with the
ledger's rule contract and the reason the literal drafter passed, and asks
for a rule or a reason, plus one call the rule must fire on and one it must
not.  The answer is data: the rule is parsed by the ledger's own parser,
run through the engine on both examples, given the sentence as its text,
and stored unconfirmed like any other draft.  Only the sentence and the
contract leave the machine, under the owner's own Anthropic credentials.

The gate itself never calls a model; this is an offline step.  The SDK
(``anthropic``, the ``draft`` extra) is imported lazily, inside
:func:`asker`, so nothing else in the ledger depends on it.
"""

from __future__ import annotations

import json
import os
from collections.abc import Mapping
from typing import Any

from pydantic import BaseModel, Field

from ember_armor.ledger.draft import Asker, Example, Reply, Statement

DEFAULT_MODEL = "claude-opus-5-5"
#: Models that take the server-side refusal fallback on the Claude API.
_FALLBACK_MODELS = ("claude-opus", "claude-fable", "claude-sonnet-5-5")

SYSTEM = (
    "You translate one standing order a person typed into a coding-agent session "
    "into one rule for EmberArmor's constraint ledger, or say why there is none. "
    "The rule must be literal: it fires where the sentence says and nowhere else. "
    "If the sentence is about conduct, style or judgement rather than a command, "
    "a file or a directory, answer with no rule.\n"
    "\n"
    "A rule is a JSON object:\n"
    '{"id": "<lowercase slug, letters, digits and dashes>", "effect": "ask" | '
    '"warn", "when": <predicate>} or with "require": <predicate> instead of '
    '"when" (the rule then fires when the predicate is FALSE: an obligation). '
    'Optional "applies": {"tools": [tool names or globs], "cwd_under": '
    '[directories], "cwd_not_under": [directories], "repo_root": [directories]}. '
    'Never use the effect "deny": the owner raises it when confirming. Do not '
    'write "text" or "source"; they are filled from the sentence.\n'
    "\n"
    "Predicates (a closed set; unknown types or fields are an error):\n"
    '- {"type": "command", "program": "git", "subcommand": ["push"], "flags_any": '
    '["-f", "--force"], "flags_all": [...], "flags_none": [...], "args_any_glob": '
    '["*.pem"], "args_none_glob": [...], "args_regex": "...", "shell": "any"}: '
    "one simple command of the shell input; every field given must hold for the "
    'same command. "program" compares without path or .exe. "subcommand" is the '
    "leading non-flag words.\n"
    '- {"type": "path", "op": "read" | "write" | "delete" | "any", "glob": '
    '["**/data/**", "**/.env"], "under": [dirs], "not_under": [dirs], '
    '"not_within": [dirs], "recursive": true}: one path the call reads, writes or '
    "deletes, from file tools (Read, Write, Edit) and from recognised shell "
    'commands and redirections. A relative glob like "**/x" matches in any '
    "directory.\n"
    '- {"type": "assigns", "name": ["AWS_*"]}: the shell input sets such a '
    "variable.\n"
    '- {"type": "dynamic_shell"}: the shell input cannot be read as literal '
    "commands.\n"
    '- {"type": "text_regex", "field": "command", "pattern": "..."}: a regular '
    "expression over one input field. Last resort only.\n"
    '- {"type": "all" | "any", "of": [predicates]}, {"type": "not", "of": '
    "predicate}.\n"
    '- {"type": "not_preceded_by", "predicate": P}: no earlier call of this '
    'session matched P (for "run A before B": when = all(B, not_preceded_by(A))).\n'
    '- {"type": "count_exceeds", "predicate": P, "max": N, "within_seconds": S}: '
    "more than N earlier matching calls.\n"
    "\n"
    'Example calls, for your two checks, are JSON objects {"tool": "Bash", '
    '"input": {"command": "git push --force"}} or {"tool": "Write", "input": '
    '{"file_path": "/work/app/data/x.json", "content": ""}} or {"tool": "Read", '
    '"input": {"file_path": "..."}}; "cwd" is optional and defaults to a neutral '
    "project directory.\n"
    "\n"
    "Answer with these fields only:\n"
    '- rule_json: the rule as a JSON string, or "" when there is no rule.\n'
    "- reason: one sentence: what the rule checks, or why there is none.\n"
    "- fires_on_json: an example call, as a JSON string, that the rule must fire "
    'on ("" when no rule).\n'
    "- quiet_on_json: a nearby example call, as a JSON string, that the rule must "
    'NOT fire on ("" when no rule).\n'
    "\n"
    "Be strict with yourself: invent no path, program or flag the sentence does "
    'not name or plainly imply; prefer "command" and "path" predicates; give '
    '"warn" to an order that says what to do and "ask" to one that says what not '
    "to do"
)


class ModelReply(BaseModel):
    """What the model answers, as flat strings the schema can carry."""

    rule_json: str = Field(description="the rule as a JSON string, or empty")
    reason: str = Field(description="what the rule checks, or why there is none")
    fires_on_json: str = Field(description="an example call the rule fires on, as JSON")
    quiet_on_json: str = Field(description="an example call the rule stays quiet on")


class AssistUnavailableError(RuntimeError):
    """The Anthropic SDK is not installed, so no model can be asked."""


def question(statement: Statement, why: str) -> str:
    """The user turn for one statement."""
    lines = [
        "Sentence, as typed:",
        statement.text,
        "",
        f"The literal drafter passed because: {why or 'it fit no shape'}.",
        "Translate it, or answer with no rule.",
    ]
    return "\n".join(lines)


def _object(text: str) -> dict[str, Any] | None:
    try:
        value = json.loads(text) if text.strip() else None
    except json.JSONDecodeError:
        return None
    return value if isinstance(value, dict) else None


def _example(text: str) -> Example | None:
    data = _object(text)
    if data is None:
        return None
    tool, given = data.get("tool"), data.get("input")
    if not isinstance(tool, str) or not isinstance(given, Mapping):
        return None
    cwd = data.get("cwd")
    return Example(tool, dict(given), cwd if isinstance(cwd, str) else "")


def reply_from(parsed: ModelReply, model: str) -> Reply:
    """A :class:`Reply` from the model's fields; unreadable parts become reasons."""
    if not parsed.rule_json.strip():
        return Reply(None, parsed.reason.strip() or "no rule", model=model)
    rule = _object(parsed.rule_json)
    if rule is None:
        return Reply(None, "its rule was not a JSON object", model=model)
    return Reply(
        rule,
        parsed.reason.strip(),
        fires_on=_example(parsed.fires_on_json),
        quiet_on=_example(parsed.quiet_on_json),
        model=model,
    )


def user_environment_key() -> str | None:
    r"""``ANTHROPIC_API_KEY`` from the Windows user environment, or ``None``.

    A key set in the user's environment after a shell or an app started is
    not in that process's environment yet; the SDK then finds nothing.  On
    Windows the value is read from the registry (``HKCU\Environment``), as
    the SDK would have read it from the environment.  It is never printed.
    """
    if os.name != "nt":
        return None
    try:
        import winreg

        with winreg.OpenKey(winreg.HKEY_CURRENT_USER, "Environment") as key:
            value = winreg.QueryValueEx(key, "ANTHROPIC_API_KEY")[0]
    except OSError:
        return None
    return value if isinstance(value, str) and value else None


def asker(
    model: str = DEFAULT_MODEL,
    *,
    limit: int = 100,
    effort: str = "medium",
    client: Any | None = None,
) -> Asker:
    """An :data:`~ember_armor.ledger.draft.Asker` that asks the Anthropic API.

    *limit* caps the number of calls one run may make; past it every
    statement is answered "not asked".  *client* is for tests; by default
    ``anthropic.Anthropic()`` resolves credentials from the environment,
    and on Windows from the user environment when the process has none
    (see :func:`user_environment_key`).

    Raises
    ------
    AssistUnavailableError
        If the ``anthropic`` package is not installed.
    """
    try:
        import anthropic
    except ImportError as exc:
        raise AssistUnavailableError(
            "Asking a model needs the Anthropic SDK, which is not installed. "
            'Install the optional extra: pip install "ember-armor[draft]"'
        ) from exc
    if client is None:
        given = os.environ.get("ANTHROPIC_API_KEY") or os.environ.get(
            "ANTHROPIC_AUTH_TOKEN"
        )
        fallback = None if given else user_environment_key()
        client = (
            anthropic.Anthropic(api_key=fallback) if fallback else anthropic.Anthropic()
        )
    api = client
    config: Any = {"effort": effort}
    calls = 0
    extra: dict[str, Any] = {}
    if model.startswith(_FALLBACK_MODELS):
        extra = {"betas": ["server-side-fallback-2026-07-01"], "fallbacks": "default"}

    def ask(statement: Statement, why: str) -> Reply:
        nonlocal calls
        if calls >= limit:
            return Reply(
                None,
                f"not asked: the limit of {limit} model call(s) was reached",
                model=model,
            )
        calls += 1
        try:
            response = api.beta.messages.parse(
                model=model,
                max_tokens=16000,
                system=SYSTEM,
                messages=[{"role": "user", "content": question(statement, why)}],
                output_format=ModelReply,
                output_config=config,
                **extra,
            )
        except anthropic.AuthenticationError:
            return Reply(
                None, "not asked: the API rejected the credentials", model=model
            )
        except anthropic.RateLimitError:
            return Reply(
                None, "not asked: the API is rate-limiting this run", model=model
            )
        except anthropic.APIStatusError as exc:
            return Reply(
                None, f"not asked: the API answered {exc.status_code}", model=model
            )
        except anthropic.APIConnectionError:
            return Reply(None, "not asked: the API could not be reached", model=model)
        if response.stop_reason == "refusal":
            return Reply(None, "the model declined to answer", model=model)
        parsed = response.parsed_output
        if parsed is None:
            return Reply(None, "the model's answer could not be read", model=model)
        return reply_from(parsed, model)

    return ask
