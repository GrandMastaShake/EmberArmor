"""``ember-gate draft --model``: the model side, with the API stubbed.

No request leaves these tests.  The Anthropic client is a stand-in whose
``beta.messages.parse`` returns what a test says, or raises what a test
says, so what is tested is how an answer becomes a reply and how a failure
becomes a reason.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

anthropic = pytest.importorskip("anthropic")

from ember_armor.ledger import cli  # noqa: E402
from ember_armor.ledger.assist import (  # noqa: E402
    SYSTEM,
    AssistUnavailableError,
    ModelReply,
    asker,
    question,
    reply_from,
)
from ember_armor.ledger.draft import Example, Statement  # noqa: E402
from tests.ledger.helpers import write_ledger  # noqa: E402

STATEMENT = Statement(
    "Never push to main.", "never", "never", "s1", "2026-10-01T10:00:00Z", "t"
)
RULE = {
    "id": "push-to-main",
    "effect": "ask",
    "when": {
        "type": "command",
        "program": "git",
        "subcommand": ["push"],
        "args_any_glob": ["main"],
    },
}
FIRES = {"tool": "Bash", "input": {"command": "git push origin main"}}
QUIET = {
    "tool": "Bash",
    "input": {"command": "git push origin feature"},
    "cwd": "/srv/x",
}


class _Response:
    def __init__(
        self, parsed: ModelReply | None, stop_reason: str = "end_turn"
    ) -> None:
        self.parsed_output = parsed
        self.stop_reason = stop_reason


class _Parse:
    """Stands in for ``client.beta.messages.parse``."""

    def __init__(self, answer: Any) -> None:
        self.answer = answer
        self.calls: list[dict[str, Any]] = []

    def __call__(self, **kwargs: Any) -> Any:
        self.calls.append(kwargs)
        if isinstance(self.answer, BaseException):
            raise self.answer
        return self.answer


class _Client:
    def __init__(self, parse: _Parse) -> None:
        self.beta = type("Beta", (), {})()
        self.beta.messages = type("Messages", (), {})()
        self.beta.messages.parse = parse


def answer(**fields: str) -> ModelReply:
    given = {"rule_json": "", "reason": "", "fires_on_json": "", "quiet_on_json": ""}
    given.update(fields)
    return ModelReply(**given)


# ---------------------------------------------------------------------------
# From the model's fields to a reply
# ---------------------------------------------------------------------------
def test_a_full_answer_becomes_a_reply_with_both_examples() -> None:
    parsed = answer(
        rule_json=json.dumps(RULE),
        reason="pushes to main",
        fires_on_json=json.dumps(FIRES),
        quiet_on_json=json.dumps(QUIET),
    )
    reply = reply_from(parsed, "m1")
    assert reply.rule == RULE
    assert reply.reason == "pushes to main"
    assert reply.fires_on == Example("Bash", {"command": "git push origin main"})
    assert reply.quiet_on == Example(
        "Bash", {"command": "git push origin feature"}, "/srv/x"
    )
    assert reply.model == "m1"


def test_no_rule_is_a_reason() -> None:
    reply = reply_from(answer(reason="it is about conduct"), "m1")
    assert (reply.rule, reply.reason) == (None, "it is about conduct")


@pytest.mark.parametrize(
    ("fields", "expect"),
    [
        ({"rule_json": "{not json"}, "not a JSON object"),
        ({"rule_json": "[1, 2]"}, "not a JSON object"),
    ],
)
def test_an_unreadable_rule_is_a_reason(fields: dict[str, str], expect: str) -> None:
    reply = reply_from(answer(**fields), "m1")
    assert reply.rule is None
    assert expect in reply.reason


def test_an_unreadable_example_is_dropped_not_fatal() -> None:
    parsed = answer(
        rule_json=json.dumps(RULE),
        fires_on_json="nonsense",
        quiet_on_json='{"tool": 3}',
    )
    reply = reply_from(parsed, "m1")
    assert reply.rule == RULE
    assert (reply.fires_on, reply.quiet_on) == (None, None)


def test_the_question_carries_the_sentence_and_the_reason() -> None:
    text = question(STATEMENT, "names no command or path")
    assert "Never push to main." in text
    assert "names no command or path" in text


def test_the_contract_names_every_predicate_type() -> None:
    for kind in (
        "command", "path", "assigns", "dynamic_shell", "text_regex",
        "all", "any", "not", "not_preceded_by", "count_exceeds",
    ):  # fmt: skip
        assert f'"type": "{kind}"' in SYSTEM or f'"{kind}"' in SYSTEM


# ---------------------------------------------------------------------------
# The asker
# ---------------------------------------------------------------------------
def test_the_asker_sends_the_contract_and_reads_the_answer() -> None:
    parse = _Parse(
        _Response(
            answer(
                rule_json=json.dumps(RULE),
                reason="pushes to main",
                fires_on_json=json.dumps(FIRES),
                quiet_on_json=json.dumps(QUIET),
            )
        )
    )
    ask = asker("claude-opus-5-5", client=_Client(parse))
    reply = ask(STATEMENT, "names no command")
    assert reply.rule == RULE
    [sent] = parse.calls
    assert sent["model"] == "claude-opus-5-5"
    assert sent["system"] == SYSTEM
    assert sent["output_format"] is ModelReply
    assert sent["output_config"] == {"effort": "medium"}
    assert sent["fallbacks"] == "default"
    assert sent["betas"] == ["server-side-fallback-2026-07-01"]
    assert "Never push to main." in sent["messages"][0]["content"]


def test_a_model_without_the_fallback_gets_none() -> None:
    parse = _Parse(_Response(answer(reason="none")))
    ask = asker("claude-haiku-5-5", client=_Client(parse))
    ask(STATEMENT, "x")
    [sent] = parse.calls
    assert "fallbacks" not in sent and "betas" not in sent


def test_the_limit_caps_the_calls() -> None:
    parse = _Parse(_Response(answer(reason="none")))
    ask = asker("claude-opus-5-5", limit=2, client=_Client(parse))
    replies = [ask(STATEMENT, "x") for _ in range(4)]
    assert len(parse.calls) == 2
    assert "limit of 2 model call(s)" in replies[3].reason


def test_a_refusal_is_a_reason() -> None:
    parse = _Parse(_Response(None, stop_reason="refusal"))
    reply = asker(client=_Client(parse))(STATEMENT, "x")
    assert reply.rule is None
    assert "declined" in reply.reason


def test_an_unparsed_answer_is_a_reason() -> None:
    parse = _Parse(_Response(None))
    reply = asker(client=_Client(parse))(STATEMENT, "x")
    assert "could not be read" in reply.reason


def test_api_failures_become_reasons_not_crashes() -> None:
    import httpx2

    request = httpx2.Request("POST", "https://api.anthropic.com/v1/messages")
    response = httpx2.Response(401, request=request)
    cases = [
        (
            anthropic.AuthenticationError("no", response=response, body=None),
            "credentials",
        ),
        (
            anthropic.RateLimitError(
                "slow", response=httpx2.Response(429, request=request), body=None
            ),
            "rate-limiting",
        ),
        (
            anthropic.InternalServerError(
                "down", response=httpx2.Response(503, request=request), body=None
            ),
            "answered 503",
        ),
        (anthropic.APIConnectionError(request=request), "could not be reached"),
    ]
    for error, expect in cases:
        reply = asker(client=_Client(_Parse(error)))(STATEMENT, "x")
        assert reply.rule is None
        assert expect in reply.reason, (error, reply.reason)


def test_without_the_sdk_the_asker_says_so(monkeypatch: pytest.MonkeyPatch) -> None:
    import sys

    monkeypatch.setitem(sys.modules, "anthropic", None)
    with pytest.raises(AssistUnavailableError, match="draft"):
        asker()


# ---------------------------------------------------------------------------
# The command
# ---------------------------------------------------------------------------
@pytest.fixture
def cli_env(
    gate_env: dict[str, str], monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> dict[str, str]:
    for name in ("EMBER_GATE_MODE", "EMBER_GATE_BUILTIN"):
        monkeypatch.delenv(name, raising=False)
    for name, value in gate_env.items():
        monkeypatch.setenv(name, value)
    monkeypatch.chdir(tmp_path)
    return gate_env


def test_cli_model_without_the_sdk_exits_one(
    cli_env: dict[str, str],
    capsys: pytest.CaptureFixture[str],
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    import sys

    monkeypatch.setitem(sys.modules, "anthropic", None)
    path = tmp_path / "t.jsonl"
    path.write_text("", encoding="utf-8")
    write_ledger(tmp_path / "ledger.json")
    assert cli.main(["draft", str(path), "--model"]) == 1
    assert "not installed" in capsys.readouterr().err
