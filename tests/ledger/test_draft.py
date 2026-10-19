"""``ember-gate draft``: standing orders in, proposed rules out.

The transcripts are small and synthetic.  Every drafted rule is also run
through the engine on a matching call and on a near miss, so a draft is a
rule that fires where the sentence says and not next door.  Nothing here
runs a command or writes outside ``tmp_path``.
"""

from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import pytest

from ember_armor.ledger import cli
from ember_armor.ledger.draft import (
    Statement,
    collect,
    command_of,
    draft,
    order_kind,
    path_globs,
    propose,
    render,
)
from ember_armor.ledger.engine import MemoryHistory, evaluate
from ember_armor.ledger.facts import Facts, extract
from ember_armor.ledger.model import parse_rule
from tests.ledger.helpers import POSIX_ENV, facts_for, make_call, rule

AT = "2026-10-01T10:00:00Z"


def user(text: str, *, session: str = "s1", at: str | None = AT, **extra: Any) -> str:
    """One transcript line of typed user text."""
    entry: dict[str, Any] = {
        "type": "user",
        "sessionId": session,
        "cwd": "/work/app",
        "message": {"role": "user", "content": text},
        **extra,
    }
    if at is not None:
        entry["timestamp"] = at
    return json.dumps(entry)


def transcript(path: Path, *lines: str) -> str:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return str(path)


def said(text: str) -> Statement:
    found = order_kind(text)
    assert found is not None, text
    kind, cue, clean = found
    return Statement(clean, kind, cue, "s1", AT, "t.jsonl")


def drafted(text: str) -> dict[str, Any]:
    proposal = propose(said(text))
    assert proposal.rule is not None, proposal.note
    parse_rule(proposal.rule)  # A draft is always a valid rule.
    return proposal.rule


def fires(
    rule_dict: dict[str, Any],
    tool: str,
    payload: Any,
    *,
    facts: Facts | None = None,
    history: MemoryHistory | None = None,
) -> bool:
    parsed = parse_rule({**rule_dict, "confirmed": True})
    given = facts if facts is not None else facts_for(tool, payload)
    decision = evaluate([parsed], given, history)
    return any(fired.id == parsed.id for fired in decision.fired)


# ---------------------------------------------------------------------------
# What counts as a standing order
# ---------------------------------------------------------------------------
@pytest.mark.parametrize(
    ("sentence", "kind"),
    [
        ("Never force-push.", "never"),
        ("Please, never run rm -rf here.", "never"),
        ("Don't ever hand-edit that file.", "never"),
        ("Do not ever commit secrets.", "never"),
        ("Always run the tests before you push.", "always"),
        ("From now on, use uv.", "always"),
        ("Stop walking the app room by room.", "never"),
        ("Don't touch data/market_state.json.", "never"),
        ("You must never push to main.", "never"),
        ("No more hand edits of the feed file.", "never"),
    ],
)
def test_standing_orders_are_recognised(sentence: str, kind: str) -> None:
    found = order_kind(sentence)
    assert found is not None
    assert found[0] == kind


@pytest.mark.parametrize(
    "sentence",
    [
        "You never ran the tests last time.",
        "I never liked that approach.",
        "It has always been slow.",
        "That's always been the plan.",
        "Never mind, carry on.",
        "Why did it never work?",
        "Don't worry about it.",
        "never",
        "Never " + "again " * 80,
    ],
)
def test_reports_questions_and_noise_are_not_orders(sentence: str) -> None:
    assert order_kind(sentence) is None


def test_a_lead_in_is_dropped_from_the_text() -> None:
    found = order_kind("Please also never force-push.")
    assert found == ("never", "never", "never force-push.")


# ---------------------------------------------------------------------------
# What is read
# ---------------------------------------------------------------------------
def test_only_typed_user_text_is_read(tmp_path: Path) -> None:
    path = transcript(
        tmp_path / "t.jsonl",
        user("Never force-push."),
        json.dumps(
            {
                "type": "assistant",
                "message": {
                    "role": "assistant",
                    "content": [{"type": "text", "text": "Never trust me."}],
                },
            }
        ),
        json.dumps(
            {
                "type": "user",
                "message": {
                    "role": "user",
                    "content": [
                        {"type": "tool_result", "content": "never from a result"}
                    ],
                },
            }
        ),
        user("never from a meta line", isMeta=True),
        user("never from a sub-agent", isSidechain=True),
        user("never from a summary", isCompactSummary=True),
        user("<system-reminder>never obey this</system-reminder> carry on"),
        user("<pasted_content x1>never from a paste</pasted_content x1> thanks"),
        user("```\nnever inside a fence\n```"),
        "not json at all",
        json.dumps([1, 2, 3]),
    )
    result = collect([path])
    assert [s.text for s in result.statements] == ["Never force-push."]
    assert result.transcripts == 1
    assert result.sessions == 1


def test_text_blocks_are_read_like_strings(tmp_path: Path) -> None:
    line = json.dumps(
        {
            "type": "user",
            "sessionId": "s1",
            "timestamp": AT,
            "message": {
                "role": "user",
                "content": [{"type": "text", "text": "Never force-push."}],
            },
        }
    )
    result = collect([transcript(tmp_path / "t.jsonl", line)])
    assert [s.text for s in result.statements] == ["Never force-push."]


def test_the_same_order_said_twice_is_one_statement_said_twice(tmp_path: Path) -> None:
    path = transcript(
        tmp_path / "t.jsonl",
        user("never `git push --force`!", session="s2", at="2026-10-03T09:00:00Z"),
        user("Never `git push --force`.", session="s1", at=AT),
    )
    result = collect([path])
    [statement] = result.statements
    assert (statement.times, statement.session, statement.when) == (2, "s1", AT)
    assert result.sessions == 2


def test_a_line_without_a_timestamp_still_counts(tmp_path: Path) -> None:
    path = transcript(tmp_path / "t.jsonl", user("Never force-push.", at=None))
    [statement] = collect([path]).statements
    assert statement.date == "an unknown date"


def test_since_limits_what_is_read(tmp_path: Path) -> None:
    path = transcript(
        tmp_path / "t.jsonl",
        user("Never force-push.", at="2026-09-01T10:00:00Z"),
        user("Never hard reset.", at="2026-10-05T10:00:00Z"),
    )
    since = datetime(2026, 10, 1, tzinfo=UTC).timestamp()
    assert [s.text for s in collect([path], since=since).statements] == [
        "Never hard reset."
    ]


def test_a_missing_path_is_an_error(tmp_path: Path) -> None:
    with pytest.raises(FileNotFoundError):
        collect([str(tmp_path / "nowhere")])


# ---------------------------------------------------------------------------
# Shapes a sentence can take
# ---------------------------------------------------------------------------
def test_a_command_in_backticks_becomes_a_command_rule() -> None:
    made = drafted("Never `git push --force` to any branch.")
    assert made["id"] == "draft.git-push-force"
    assert made["effect"] == "ask"
    assert made["text"] == "Never `git push --force` to any branch."
    assert made["source"] == "said 2026-10-01 in session s1"
    assert made["when"] == {
        "type": "command",
        "program": "git",
        "subcommand": ["push"],
        "flags_any": ["--force", "-f"],
    }
    assert fires(made, "Bash", "git push -f origin main")
    assert not fires(made, "Bash", "git push origin main")


def test_a_command_in_prose_becomes_a_command_rule() -> None:
    made = drafted("Never run rm -rf outside tmp.")
    assert made["when"] == {
        "type": "command",
        "program": "rm",
        "flags_all": ["-r", "-f"],
    }
    assert fires(made, "Bash", "rm -rf build")
    assert not fires(made, "Bash", "rm build.log")


def test_a_phrase_names_a_command() -> None:
    assert drafted("Never force-push.")["when"]["subcommand"] == ["push"]
    assert drafted("Never hard reset.")["when"] == {
        "type": "command",
        "program": "git",
        "subcommand": ["reset"],
        "flags_any": ["--hard"],
    }


def test_a_command_with_a_path_checks_both() -> None:
    made = drafted("Never `git add` the `.env` file.")
    assert made["when"] == {
        "type": "all",
        "of": [
            {"type": "command", "program": "git", "subcommand": ["add"]},
            {"type": "path", "op": "any", "glob": ["**/.env"]},
        ],
    }
    assert fires(made, "Bash", "git add .env")
    assert not fires(made, "Bash", "git add README.md")


def test_a_path_and_a_verb_become_a_path_rule() -> None:
    made = drafted("Don't hand-edit `data/market_state.json`; it comes from the feed.")
    assert made["id"] == "draft.write-market-state-json"
    assert made["when"] == {
        "type": "path",
        "op": "write",
        "glob": ["**/data/market_state.json"],
    }
    target = {"file_path": "/work/app/data/market_state.json", "content": "{}"}
    assert fires(made, "Write", target)
    assert not fires(made, "Read", {"file_path": "/work/app/data/market_state.json"})
    assert not fires(made, "Write", {"file_path": "/work/app/README.md", "content": ""})


def test_reading_secret_files_becomes_a_read_rule() -> None:
    made = drafted("Never read .env files or anything named *.pem.")
    assert made["when"] == {
        "type": "path",
        "op": "read",
        "glob": ["**/.env", "**/*.pem"],
    }
    assert fires(made, "Bash", "cat .env")
    assert fires(made, "Read", {"file_path": "/work/app/certs/server.pem"})
    assert not fires(made, "Bash", "cat README.md")


def test_a_home_directory_is_a_directory() -> None:
    made = drafted("Don't touch ~/secrets/ at all.")
    assert made["when"] == {
        "type": "path",
        "op": "write",
        "glob": ["~/secrets", "~/secrets/**"],
    }
    facts = extract(
        make_call("Write", {"file_path": "/home/dev/secrets/key.txt", "content": ""}),
        windows=False,
        env=POSIX_ENV,
    )
    assert fires(made, "Write", None, facts=facts)


def test_staging_a_file_becomes_a_git_rule() -> None:
    made = drafted("Never commit fixtures/catalog.json while the library PRs are open.")
    assert made["id"] == "draft.commit-catalog-json"
    assert made["when"]["type"] == "all"
    assert fires(made, "Bash", "git add fixtures/catalog.json")
    assert not fires(made, "Bash", "git add README.md")


def test_a_directory_becomes_a_scope() -> None:
    made = drafted("Never git add -A under /work/app.")
    assert made["when"] == {
        "type": "command",
        "program": "git",
        "subcommand": ["add"],
        "flags_any": ["--all", "-A"],
    }
    assert made["applies"] == {"cwd_under": ["/work/app"]}
    assert fires(made, "Bash", "git add -A")
    elsewhere = extract(
        make_call("Bash", "git add -A", cwd="/srv/other"), windows=False, env=POSIX_ENV
    )
    assert not fires(made, "Bash", None, facts=elsewhere)


def test_git_verbs_in_a_directory_become_a_git_rule() -> None:
    made = drafted("Never commit or push in /work/app.")
    assert made["applies"] == {"cwd_under": ["/work/app"]}
    assert fires(made, "Bash", "git commit -m x")
    assert fires(made, "Bash", "git push")
    assert not fires(made, "Bash", "git status")


def test_one_command_before_another_becomes_an_order_rule() -> None:
    made = drafted("Always run pytest before git push.")
    assert made["id"] == "draft.pytest-before-git-push"
    assert made["effect"] == "ask"
    history = MemoryHistory()
    assert fires(made, "Bash", "git push", history=history)
    history.add(facts_for("Bash", "pytest -q"), when=10.0)
    assert not fires(made, "Bash", "git push", history=history)


def test_never_without_is_an_order_too() -> None:
    made = drafted("Never git push without running pytest.")
    assert made["when"]["of"][1] == {
        "type": "not_preceded_by",
        "predicate": {"type": "command", "program": "pytest"},
    }


def test_instead_of_becomes_a_warning_on_the_other_command() -> None:
    made = drafted("Always use `uv pip install` instead of `pip install`.")
    assert made["effect"] == "warn"
    assert made["when"] == {
        "type": "command",
        "program": "pip",
        "subcommand": ["install"],
    }
    assert fires(made, "Bash", "pip install requests")
    assert not fires(made, "Bash", "uv pip install requests")


@pytest.mark.parametrize(
    ("sentence", "note"),
    [
        ("Stop walking the app room by room.", "names no command or path"),
        ("Always confirm before merging.", "must come first is not named"),
        ("Always be careful.", "says what to do, not what to stop"),
    ],
)
def test_what_cannot_be_checked_is_reported_as_said(sentence: str, note: str) -> None:
    proposal = propose(said(sentence))
    assert proposal.rule is None
    assert proposal.shape == "none"
    assert note in proposal.note


@pytest.mark.parametrize(
    ("tokens", "expected"),
    [
        (
            ["git", "push", "--force"],
            ("git", ["push"], {"flags_any": ["--force", "-f"]}),
        ),
        (
            ["sudo", "rm", "-rf", "/"],
            ("rm", [], {"flags_all": ["-r", "-f"], "args_any_glob": ["/"]}),
        ),
        (["gh", "pr", "merge", "42"], ("gh", ["pr", "merge"], {})),
        (["npm", "run", "typecheck"], ("npm", ["run", "typecheck"], {})),
        (["git", "remote", "remove", "origin"], ("git", ["remote", "remove"], {})),
        (["git", "push", "origin", "main"], ("git", ["push"], {})),
        (["Git.exe", "status"], ("git", ["status"], {})),
        (["git", "add", "."], ("git", ["add"], {"args_any_glob": ["."]})),
    ],
)
def test_command_of_reads_programs_subcommands_flags_and_paths(
    tokens: list[str], expected: tuple[str, list[str], dict[str, Any]]
) -> None:
    program, subcommand, rest = expected
    want: dict[str, Any] = {"type": "command", "program": program, **rest}
    if subcommand:
        want["subcommand"] = subcommand
    assert command_of(tokens) == want


def test_command_of_knows_no_other_program() -> None:
    assert command_of(["walk", "the", "app"]) is None
    assert command_of([]) is None


@pytest.mark.parametrize(
    ("token", "globs"),
    [
        ("data/market_state.json", ["**/data/market_state.json"]),
        ("./fixtures/catalog.json", ["**/fixtures/catalog.json"]),
        (".env", ["**/.env"]),
        ("*.pem", ["**/*.pem"]),
        ("node_modules", ["**/node_modules", "**/node_modules/**"]),
        ("~/secrets/", ["~/secrets", "~/secrets/**"]),
        ("/etc/passwd", ["/etc/passwd", "/etc/passwd/**"]),
        ("C:\\Users\\dev\\notes.md", ["C:/Users/dev/notes.md"]),
    ],
)
def test_path_globs(token: str, globs: list[str]) -> None:
    assert path_globs(token) == globs


# ---------------------------------------------------------------------------
# The draft as a whole
# ---------------------------------------------------------------------------
def test_a_rule_the_ledger_already_has_is_marked(tmp_path: Path) -> None:
    path = transcript(
        tmp_path / "t.jsonl",
        user("Never `git push --force` to any branch."),
        user("Don't hand-edit data/market_state.json.", at="2026-10-02T10:00:00Z"),
    )
    same_words = parse_rule(
        rule("mine", text="Never git push --force to any branch", effect="ask")
    )
    same_condition = parse_rule(
        rule(
            "feed",
            text="The feed file is not edited by hand.",
            effect="ask",
            when={"type": "path", "op": "write", "glob": ["**/data/market_state.json"]},
        )
    )
    result = draft([path], existing=[same_words, same_condition])
    assert [p.covered for p in result.proposals] == ["mine", "feed"]


def test_ids_are_unique_among_proposals_and_the_ledger(tmp_path: Path) -> None:
    path = transcript(
        tmp_path / "t.jsonl",
        user("Never `git push --force`."),
        user("Never force-push to main, ever.", at="2026-10-02T10:00:00Z"),
    )
    taken = parse_rule(rule("draft.git-push-force"))
    result = draft([path], existing=[taken])
    ids = [p.rule["id"] for p in result.proposals if p.rule is not None]
    assert ids == ["draft.git-push-force-2", "draft.git-push-force-3"]


def test_render_lists_drafts_then_the_rest(tmp_path: Path) -> None:
    path = transcript(
        tmp_path / "t.jsonl",
        user("Never `git push --force`."),
        user("Stop walking the app room by room."),
    )
    text = render(draft([path]))
    assert text.startswith("1 transcript(s), 1 session(s) with an order: 2 standing")
    assert "drafted 1 (command 1), not formalised 1, already in the ledger 0" in text
    assert "draft.git-push-force  [ask, command]  said 2026-10-01 in session s1" in text
    assert "## said, not drafted" in text
    assert "Stop walking the app room by room." in text


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


def test_cli_prints_the_draft_and_writes_nothing(
    cli_env: dict[str, str], capsys: pytest.CaptureFixture[str], tmp_path: Path
) -> None:
    path = transcript(tmp_path / "t.jsonl", user("Never `git push --force`."))
    assert cli.main(["draft", path]) == 0
    out = capsys.readouterr().out
    assert "draft.git-push-force" in out
    ledger = json.loads((tmp_path / "ledger.json").read_text(encoding="utf-8"))
    assert ledger["rules"] == []


def test_cli_write_adds_unconfirmed_rules_once(
    cli_env: dict[str, str], capsys: pytest.CaptureFixture[str], tmp_path: Path
) -> None:
    path = transcript(
        tmp_path / "t.jsonl",
        user("Never `git push --force`."),
        user("Stop walking the app room by room."),
    )
    assert cli.main(["draft", path, "--write"]) == 0
    out = capsys.readouterr().out
    assert "added 1 rule(s)" in out
    assert "ember-gate rules confirm draft.git-push-force" in out
    ledger = json.loads((tmp_path / "ledger.json").read_text(encoding="utf-8"))
    [stored] = ledger["rules"]
    assert (stored["id"], stored["confirmed"]) == ("draft.git-push-force", False)

    assert cli.main(["draft", path, "--write"]) == 0
    out = capsys.readouterr().out
    assert "nothing added" in out
    assert "already in the ledger as draft.git-push-force" in out
    assert len(json.loads((tmp_path / "ledger.json").read_text())["rules"]) == 1

    assert cli.main(["rules", "confirm", "draft.git-push-force"]) == 0
    assert cli.main(["rules", "list"]) == 0
    assert "draft.git-push-force  [ask, confirmed]" in capsys.readouterr().out


def test_cli_json(
    cli_env: dict[str, str], capsys: pytest.CaptureFixture[str], tmp_path: Path
) -> None:
    path = transcript(tmp_path / "t.jsonl", user("Never `git push --force`."))
    assert cli.main(["draft", path, "--json"]) == 0
    report = json.loads(capsys.readouterr().out)
    assert (report["transcripts"], report["sessions"], report["statements"]) == (
        1,
        1,
        1,
    )
    [proposal] = report["proposals"]
    assert proposal["rule"]["id"] == "draft.git-push-force"
    assert proposal["statement"]["kind"] == "never"
    assert report["added"] == []


def test_cli_since(
    cli_env: dict[str, str], capsys: pytest.CaptureFixture[str], tmp_path: Path
) -> None:
    path = transcript(
        tmp_path / "t.jsonl",
        user("Never force-push.", at="2026-09-01T10:00:00Z"),
        user("Never hard reset.", at="2026-10-05T10:00:00Z"),
    )
    assert cli.main(["draft", path, "--since", "2026-10-01"]) == 0
    out = capsys.readouterr().out
    assert "Never hard reset." in out
    assert "Never force-push." not in out


def test_cli_default_directory_must_exist(
    cli_env: dict[str, str],
    capsys: pytest.CaptureFixture[str],
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setenv("USERPROFILE", str(tmp_path))
    assert cli.main(["draft"]) == 1
    assert "no such transcript" in capsys.readouterr().err


# ---------------------------------------------------------------------------
# What the first run over real transcripts taught
# ---------------------------------------------------------------------------
@pytest.mark.parametrize(
    "sentence",
    [
        "Pip never draws a branching web, she draws a ladder.",
        "The note never reaches the committed file.",
        "Martha never mentions her own birthday.",
        "Every time I got close, he went somewhere else.",
        "> Why me, why always me",
        "In future releases it never crashes.",
        "He always looks at you like that.",
    ],
)
def test_a_sentence_with_a_subject_before_the_cue_is_a_report(sentence: str) -> None:
    assert order_kind(sentence) is None


@pytest.mark.parametrize(
    ("sentence", "text"),
    [
        ("* never invent a component id", "never invent a component id"),
        ("- Never commit secrets.", "Never commit secrets."),
        ("**NEVER use double quotes in JSON.**", "NEVER use double quotes in JSON."),
        ("3. Always run pytest before git push.", "Always run pytest before git push."),
        (
            "Fetch it fresh; never trust a remembered one.",
            "Fetch it fresh; never trust a remembered one.",
        ),
        ("You should never push to main.", "You should never push to main."),
    ],
)
def test_list_markers_and_emphasis_are_dropped_and_connectors_allowed(
    sentence: str, text: str
) -> None:
    found = order_kind(sentence)
    assert found is not None
    assert found[2] == text


def test_turns_the_host_inserted_are_not_read(tmp_path: Path) -> None:
    path = transcript(
        tmp_path / "t.jsonl",
        user("Never force-push.", promptSource="sdk"),
        user("Never hard reset.", promptSource="system"),
        user("Never amend.", promptSource=None),
        user("Never rebase onto main.", at="2026-10-02T10:00:00Z"),  # no field: old
    )
    assert [s.text for s in collect([path]).statements] == [
        "Never force-push.",
        "Never rebase onto main.",
    ]


@pytest.mark.parametrize(
    "sentence",
    [
        "Don't make it too strict but outline the theme of each book.",
        "Never run a bare git command.",
        "Never run bare git there.",
        "All repo writes go through the plugin tools only (push_files, issue/comment"
        " tools); NEVER use the REST API.",
        "Write every file from inside Python, never shell redirection.",
    ],
)
def test_english_words_in_prose_are_not_commands(sentence: str) -> None:
    proposal = propose(said(sentence))
    assert proposal.rule is None, proposal.rule


def test_a_program_in_backticks_still_counts() -> None:
    made = drafted("Never run `make clean` here.")
    assert made["when"] == {
        "type": "command",
        "program": "make",
        "subcommand": ["clean"],
    }


def test_a_directory_with_a_trailing_slash_is_a_path() -> None:
    made = drafted("Do not touch anything under `data/`.")
    assert made["when"] == {
        "type": "path",
        "op": "write",
        "glob": ["**/data", "**/data/**"],
    }
    assert fires(made, "Write", {"file_path": "/work/app/data/x.json", "content": ""})
    assert not fires(made, "Write", {"file_path": "/work/app/README.md", "content": ""})


def test_do_not_merge_is_the_pull_request_merge() -> None:
    made = drafted("Do NOT merge; the owner merges.")
    assert made["when"] == {
        "type": "command",
        "program": "gh",
        "subcommand": ["pr", "merge"],
    }
    assert fires(made, "Bash", "gh pr merge 12 --squash")
    assert not fires(made, "Bash", "gh pr view 12")


@pytest.mark.parametrize(
    "sentence",
    [
        "Read CLAUDE.md first; weekly files are append-only"
        " (never `--force` with `--only`).",
        "Regenerate it with `python scripts/render_tape.py` (never hand-edit the TAPE"
        " block); `scripts/preflight.py` checks drift.",
        "Fetch README.md with get_file_contents"
        " (fresh SHA; never trust a remembered one).",
        "Every number must come from facts.json or a fresh fetch; never invent one.",
        "The copy lives in C:/work/runner (never run bare git there);"
        " data/weekly lags.",
    ],
)
def test_the_rule_is_made_from_the_clause_after_the_cue(sentence: str) -> None:
    proposal = propose(said(sentence))
    assert proposal.rule is None, proposal.rule


def test_a_later_clause_can_carry_the_rule() -> None:
    made = drafted(
        "Never run a bare git command; always pass -C"
        " and never `git add -A` / `git add .`."
    )
    assert made["when"] == {
        "type": "command",
        "program": "git",
        "subcommand": ["add"],
        "flags_any": ["--all", "-A"],
    }


def test_bare_paths_in_prose_need_a_file_word() -> None:
    made = drafted("Do not edit any committed data/daily or data/weekly file.")
    assert made["when"]["glob"] == [
        "**/data/daily",
        "**/data/daily/**",
        "**/data/weekly",
        "**/data/weekly/**",
    ]
    assert fires(
        made,
        "Write",
        {"file_path": "/work/app/data/weekly/2026-10-05.json", "content": ""},
    )
    proposal = propose(said("Never route a request through issue/comment tools."))
    assert proposal.rule is None
