"""Draft ledger rules from what the owner said in Claude Code transcripts.

The gate enforces rules a person confirmed.  This module finds the standing
orders a person typed into a conversation ("never force-push", "don't touch
``data/market_state.json``", "always run pytest before git push") and
proposes each as an unconfirmed rule, with the sentence as the rule's text
and the session it was said in as its source.  Only typed user turns are
read: tool results, pasted content, host-inserted blocks and turns,
compaction summaries, sub-agent conversations and the assistant's own
words are skipped.  Nothing is written unless asked, and a drafted rule is
stored unconfirmed, so it can do no more than warn until the owner
confirms it.

A sentence becomes a rule only through a small set of shapes the gate can
check: a command (``git push --force``), a path and what is done to it
(read, write, delete, stage), one command before another, a directory the
order is about, one command in place of another.  Everything else is
reported as said, for the owner to write by hand.  The translation is
deliberately literal: a draft the owner cannot read is not a draft they can
confirm.
"""

from __future__ import annotations

import contextlib
import json
import re
from collections.abc import Iterable, Iterator, Mapping, Sequence
from dataclasses import dataclass, field, replace
from datetime import datetime
from pathlib import Path
from typing import Any

from ember_armor.ledger.model import LedgerError, Rule, parse_rule
from ember_armor.ledger.replay import transcript_files

#: Where Claude Code keeps its transcripts, below the home directory.
DEFAULT_TRANSCRIPTS = ("~", ".claude", "projects")

# ---------------------------------------------------------------------------
# What was said
# ---------------------------------------------------------------------------
#: A paired, XML-like block the host inserts into a user turn.
_TAGGED = re.compile(r"<([a-z][a-z0-9_:-]*)\b[^>]*>.*?</\1[^>]*>", re.S | re.I)
_FENCE = re.compile(r"```.*?```", re.S)
_SPLIT = re.compile(r"(?<=[.!?])\s+|\n+")
#: A list marker or emphasis in front of a sentence.
_MARKER = re.compile(r"^(?:[-*•+]+|\d+[.)])\s+|^[*_]+")
_LEAD = re.compile(
    r"^(?:(?:please|also|and|ok|okay|btw|oh|so|but|again|now|yes|yeah|alright|right)"
    r"[,.:\s]+)+",
    re.I,
)
_CUE = re.compile(
    r"\b(never|don'?t ever|do not ever|not ever|no more|always|from now on|"
    r"going forward)\b",
    re.I,
)
_NEVER_CUES = frozenset(
    {"never", "don't ever", "dont ever", "do not ever", "not ever", "no more"}
)
_STOP = re.compile(r"^(?:stop|quit)\s+\w+ing\b", re.I)
#: Verbs an order is usually about; ``don't <verb>`` at the start of a
#: sentence counts as one, a plain ``don't`` does not ("don't worry").
ACTION_VERBS = (
    "touch", "edit", "modify", "change", "write", "overwrite", "rewrite", "update",
    "patch", "delete", "remove", "wipe", "erase", "drop", "read", "cat", "open",
    "print", "dump", "source", "run", "use", "call", "commit", "push", "pull",
    "stage", "add", "install", "uninstall", "create", "make", "merge", "rebase",
    "reset", "force", "rm", "clean", "format", "truncate", "kill", "stop", "start",
    "restart", "deploy", "publish", "download", "upload", "send", "email", "post",
    "move", "rename", "copy", "execute", "launch", "spawn", "invoke", "hand-edit",
)  # fmt: skip
_DONT = re.compile(
    r"^(?:don'?t|do not)\s+(?:ever\s+)?(?:" + "|".join(ACTION_VERBS) + r")\b", re.I
)
#: Words that may stand right in front of the cue of an order.  Anything
#: else there is a subject ("the note never reaches", "Pip never draws",
#: "it has always been"), which makes the sentence a report.
_ALLOWED_BEFORE = frozenset((
    "and", "also", "but", "so", "then", "please", "you", "must", "should", "shall",
    "can", "may", "will", "to", "or", "just", "now",
))  # fmt: skip
#: What ends a clause: a cue right after one starts afresh ("fetch it fresh;
#: never trust a remembered one").
_CLAUSE = (";", ":", ",", "—", "–", "(", "-")
#: A word after the cue that makes the sentence a report, not an order.
_REPORT_AFTER = frozenset((
    "been", "seen", "worked", "happened", "had", "has", "did", "got", "was", "were",
    "is", "are", "mind", "actually", "really", "once", "before", "gonna", "going",
    "liked", "knew", "thought", "said", "told", "asked", "tried", "used", "saw",
    "ran", "made", "gave", "came", "went", "wanted", "needed", "meant",
))  # fmt: skip


def _epoch(value: Any) -> float | None:
    if isinstance(value, str):
        with contextlib.suppress(ValueError, OSError, OverflowError):
            return datetime.fromisoformat(value.replace("Z", "+00:00")).timestamp()
    return None


def order_kind(sentence: str) -> tuple[str, str, str] | None:
    """``(kind, cue, text)`` when *sentence* reads as a standing order.

    ``kind`` is ``never`` or ``always``; ``cue`` the words that say so;
    ``text`` the sentence without its lead-in ("please", "also", a list
    marker).  A question, a quotation (a line starting with ``>``), a report
    ("you never ran the tests", "the note never reaches the file", "it has
    always been slow"), "never mind" and anything very short or very long
    is not an order.
    """
    text = sentence.strip()
    if text.startswith(">"):
        return None
    text = _LEAD.sub("", _MARKER.sub("", text).strip().strip('"“”'))
    text = text.rstrip("*_")
    if not 8 <= len(text) <= 300 or "?" in text:
        return None
    lower = text.lower()
    if "never mind" in lower or "nevermind" in lower:
        return None
    if _STOP.match(text):
        return ("never", "stop", text)
    if _DONT.match(text):
        return ("never", text.split()[0].lower(), text)
    match = _CUE.search(lower)
    if match is None:
        return None
    head = lower[: match.start()].rstrip()
    if head and not head.endswith(_CLAUSE):
        last = head.split()[-1].strip(",;:")
        if last not in _ALLOWED_BEFORE and any(c.isalnum() for c in last):
            return None
    after = lower[match.end() :].split()
    if not after or after[0].strip(",.;:") in _REPORT_AFTER:
        return None
    cue = match.group(1)
    kind = "never" if cue in _NEVER_CUES else "always"
    return (kind, cue, text)


@dataclass(frozen=True)
class Statement:
    """One standing order, as typed, and where it was said."""

    text: str
    kind: str
    cue: str
    session: str
    when: str  #: ISO 8601 timestamp of the transcript line, or "".
    transcript: str
    times: int = 1  #: How often the same sentence was said, over all transcripts.

    @property
    def date(self) -> str:
        return self.when[:10] if self.when else "an unknown date"


def typed_text(entry: Mapping[str, Any]) -> str | None:
    """The text a person typed in a transcript line, or ``None``.

    Tool results, meta lines, compaction summaries, sub-agent turns and
    turns the host inserted (a notification, a continuation summary, the
    output of a slash command: ``promptSource`` other than ``sdk``) are not
    typed text.  Host-inserted blocks and fenced code are removed.
    """
    if entry.get("type") != "user":
        return None
    if entry.get("isMeta") or entry.get("isCompactSummary") or entry.get("isSidechain"):
        return None
    if "promptSource" in entry and entry.get("promptSource") != "sdk":
        return None
    message = entry.get("message")
    content = message.get("content") if isinstance(message, Mapping) else None
    if isinstance(content, str):
        text = content
    elif isinstance(content, list):
        text = "\n".join(
            str(block.get("text", ""))
            for block in content
            if isinstance(block, Mapping) and block.get("type") == "text"
        )
    else:
        return None
    text = _FENCE.sub(" ", _TAGGED.sub(" ", text))
    return text if text.strip() else None


def statements(path: Path, *, since: float | None = None) -> Iterator[Statement]:
    """Standing orders typed in one transcript, in the order they were said."""
    with path.open(encoding="utf-8", errors="replace") as handle:
        for line in handle:
            if '"user"' not in line:
                continue  # Cheap: assistant lines and attachments never qualify.
            try:
                entry = json.loads(line)
            except json.JSONDecodeError:
                continue
            if not isinstance(entry, dict):
                continue
            text = typed_text(entry)
            if text is None:
                continue
            when = entry.get("timestamp")
            when = when if isinstance(when, str) else ""
            if since is not None and (_epoch(when) or 0.0) < since:
                continue
            session = str(entry.get("sessionId") or path.stem)
            for sentence in _SPLIT.split(text):
                found = order_kind(sentence)
                if found is not None:
                    kind, cue, clean = found
                    yield Statement(clean, kind, cue, session, when, str(path))


def _key(text: str) -> str:
    """Two sentences are the same order when they match under this key."""
    return " ".join(re.sub(r"[^a-z0-9 ]+", " ", text.lower()).split())


# ---------------------------------------------------------------------------
# From a sentence to a rule
# ---------------------------------------------------------------------------
#: Programs a sentence can name.  The parser compares names without a path
#: and without ``.exe``, so these are bare names.
PROGRAMS = frozenset((
    "git", "gh", "npm", "pnpm", "npx", "yarn", "pip", "pip3", "uv", "python",
    "python3", "node", "docker", "kubectl", "terraform", "cargo", "go", "dotnet",
    "aws", "az", "gcloud", "vercel", "heroku", "flyctl", "psql", "mysql", "sqlite3",
    "make", "rm", "del", "rd", "rmdir", "remove-item", "mv", "cp", "chmod", "chown",
    "curl", "wget", "ssh", "scp", "rsync", "robocopy", "kill", "taskkill",
    "systemctl", "service", "brew", "apt", "apt-get", "choco", "winget", "pytest",
    "ruff", "mypy", "tsc", "eslint", "prettier",
))  # fmt: skip
#: Programs that are also English words: named in prose they mean nothing.
_ENGLISH = frozenset((
    "make", "go", "service", "kill", "time", "env", "exec", "cp", "mv", "rd", "del",
    "node", "python", "python3",
))  # fmt: skip
#: Programs whose first argument is a subcommand (``git push``).
SUBCOMMAND_PROGRAMS = frozenset((
    "git", "gh", "npm", "pnpm", "npx", "yarn", "pip", "pip3", "uv", "docker",
    "kubectl", "terraform", "cargo", "go", "dotnet", "aws", "az", "gcloud", "vercel",
    "heroku", "flyctl", "brew", "apt", "apt-get", "choco", "winget", "systemctl",
    "make",
))  # fmt: skip
_NPM = frozenset((
    "install", "i", "ci", "run", "publish", "uninstall", "update", "exec", "test",
    "build", "start", "audit", "link", "unpublish", "version",
))  # fmt: skip
_PACKAGES = frozenset(("install", "uninstall", "remove", "upgrade", "update", "purge"))
#: Subcommands a program is known to have, for a command written in prose.
#: ``None`` means any word may follow (``aws s3 rm``).
_KNOWN_SUB: Mapping[str, frozenset[str] | None] = {
    "git": frozenset((
        "add", "commit", "push", "pull", "fetch", "merge", "rebase", "reset",
        "checkout", "switch", "restore", "clean", "stash", "tag", "branch", "remote",
        "worktree", "submodule", "cherry-pick", "revert", "rm", "mv", "log",
        "status", "diff", "init", "clone", "am", "apply", "bisect", "config", "gc",
        "prune", "reflog", "notes", "filter-branch",
    )),
    "gh": frozenset((
        "pr", "issue", "repo", "release", "run", "workflow", "secret", "auth", "api",
        "gist",
    )),
    "npm": _NPM,
    "pnpm": _NPM,
    "yarn": _NPM,
    "npx": None,
    "pip": frozenset(("install", "uninstall", "freeze", "download")),
    "pip3": frozenset(("install", "uninstall", "freeze", "download")),
    "uv": frozenset(("pip", "run", "tool", "sync", "add", "remove", "lock", "venv")),
    "docker": frozenset((
        "run", "build", "push", "pull", "rm", "rmi", "exec", "compose", "system",
        "volume", "container", "image", "network", "stop", "kill", "prune",
    )),
    "kubectl": frozenset((
        "delete", "apply", "exec", "get", "drain", "scale", "rollout",
    )),
    "terraform": frozenset((
        "destroy", "apply", "plan", "init", "state", "taint", "import",
    )),
    "cargo": frozenset(("publish", "build", "run", "test", "install")),
    "go": frozenset(("run", "build", "test", "install", "get", "mod")),
    "dotnet": frozenset(("run", "build", "test", "publish", "tool")),
    "brew": _PACKAGES,
    "apt": _PACKAGES,
    "apt-get": _PACKAGES,
    "choco": _PACKAGES,
    "winget": _PACKAGES,
    "systemctl": frozenset(("stop", "start", "restart", "disable", "enable", "mask")),
    "vercel": frozenset(("deploy", "rm", "remove", "env")),
    "heroku": None,
    "flyctl": None,
    "aws": None,
    "az": None,
    "gcloud": None,
    "make": frozenset(),
}  # fmt: skip
#: Subcommands that take a second word (``git remote remove``, ``npm run x``).
#: ``None`` means every subcommand of the program does (``aws s3 rm``).
TWO_LEVEL: Mapping[str, frozenset[str] | None] = {
    "git": frozenset((
        "remote", "branch", "stash", "worktree", "submodule", "config", "tag",
        "notes", "bisect", "reflog",
    )),
    "gh": frozenset((
        "pr", "issue", "repo", "release", "run", "workflow", "secret", "auth", "gist",
    )),
    "npm": frozenset({"run"}),
    "pnpm": frozenset({"run"}),
    "yarn": frozenset({"run"}),
    "uv": frozenset({"pip", "tool"}),
    "docker": frozenset((
        "compose", "container", "image", "volume", "network", "system", "buildx",
    )),
    "aws": None,
    "az": None,
    "gcloud": None,
}  # fmt: skip
_WRAPPERS = frozenset({"sudo", "env", "nohup", "time", "exec"})
#: Flags that mean the same thing, so a rule about one holds for the other.
_SYNONYMS: Mapping[tuple[str, str], tuple[str, ...]] = {
    ("git", "--force"): ("-f",),
    ("git", "-f"): ("--force",),
    ("git", "--all"): ("-A",),
    ("git", "-A"): ("--all",),
    ("git", "--delete"): ("-d",),
    ("rm", "-r"): ("-R", "--recursive"),
    ("rm", "-R"): ("-r", "--recursive"),
    ("rm", "--recursive"): ("-r", "-R"),
    ("rm", "-f"): ("--force",),
    ("rm", "--force"): ("-f",),
}
#: Ways of saying a command without writing it.
_PHRASES: Sequence[tuple[re.Pattern[str], Sequence[str]]] = (
    (re.compile(r"\bforce[- ]?push(?:es|ing|ed)?\b"), ("git", "push", "--force")),
    (re.compile(r"\bhard[- ]reset\b|\breset --hard\b"), ("git", "reset", "--hard")),
    (re.compile(r"\bamend(?:ing|ed)?\b"), ("git", "commit", "--amend")),
    (re.compile(r"\brebas(?:e|ing|ed)\b"), ("git", "rebase")),
    (re.compile(r"\bmerge\b(?!\s+conflict)"), ("gh", "pr", "merge")),
)
_GERUNDS: Mapping[str, Sequence[str]] = {
    "pushing": ("git", "push"),
    "committing": ("git", "commit"),
    "merging": ("gh", "pr", "merge"),
    "rebasing": ("git", "rebase"),
    "publishing": ("npm", "publish"),
}
_SPAN = re.compile(r"`([^`\n]{2,160})`")
_TOKEN = re.compile(r"[\w./*?=:+@~\\-]+")
#: Words that end a command written in plain prose.
_PROSE_STOP = frozenset((
    "in", "under", "on", "to", "from", "without", "unless", "when", "before",
    "after", "because", "so", "and", "or", "the", "a", "an", "for", "with", "into",
    "at", "it", "them", "this", "that", "there", "here", "anywhere", "again", "ever",
    "if", "as", "while", "until", "of", "by",
))  # fmt: skip
_PATHLIKE = re.compile(
    r"(?<![\w@])("
    r"(?:~|[A-Za-z]:)?[\w.~-]*[\\/][\w.*?~\\/-]*"  # has a separator
    r"|\.?[\w-]+\.(?:json|ya?ml|md|txt|env|pem|key|js|ts|tsx|py|toml|ini|cfg|lock"
    r"|csv|html|sh|ps1|sql|db|sqlite|log)\b"  # a file name with an extension
    r"|\*\.\w+"  # a glob
    r"|\.env\b|\.git\b"
    r")"
)
#: Things with a slash that are not paths.
_NOT_PATHS = frozenset({"and/or", "w/", "w/o", "n/a", "i/o", "a/b", "r/w"})
_VERBS: Mapping[str, re.Pattern[str]] = {
    "stage": re.compile(r"\b(commit|stage|staging|push|check in|git add)\b", re.I),
    "delete": re.compile(r"\b(delete|remove|rm|wipe|erase|drop|trash)\b", re.I),
    "write": re.compile(
        r"\b(edit|modify|change|write|overwrite|rewrite|touch|hand-edit|update"
        r"|patch|alter)\b",
        re.I,
    ),
    "read": re.compile(
        r"\b(read|cat|open|print|dump|source|view|look at|display|echo|load)\b",
        re.I,
    ),
}
_SCOPE = re.compile(
    r"\b(?:in|under|inside|within)\s+`?("
    r"(?:~|[A-Za-z]:)[\\/][\w./~\\-]*|~[\w./\\-]*|/[\w./~-]+"
    r")`?",
    re.I,
)
_BEFORE = re.compile(
    r"^(?:always\s+)?(?:run\s+)?(?P<a>.+?)\s+before\s+"
    r"(?:you\s+|any\s+|a\s+|the\s+|each\s+|every\s+)?(?P<b>.+?)\.?$",
    re.I,
)
_WITHOUT = re.compile(
    r"^(?:never|don'?t ever|do not ever|don'?t|do not)\s+(?P<b>.+?)\s+without\s+"
    r"(?:first\s+)?(?:running\s+|having run\s+|a\s+)?(?P<a>.+?)\.?$",
    re.I,
)
_INSTEAD = re.compile(
    r"^(?:always\s+|from now on,?\s+|going forward,?\s+)?(?:use|run|prefer|call)\s+"
    r"(?P<x>.+?)\s*,?\s+(?:instead of|rather than|not|over|never)\s+(?P<y>.+?)\.?$",
    re.I,
)
_RUN = re.compile(r"^(?:run|running|use|using|call|calling|a|the)\s+", re.I)
#: Where the clause that follows a cue ends: the rule is made from that clause.
_CLAUSE_END = re.compile(r"[;)]|\s[\u2014\u2013]\s")
#: A word that says a bare ``a/b`` in prose is a path and not "issue/comment".
_FILE_WORDS = re.compile(
    r"\b(file|files|folder|folders|director(?:y|ies)|dir|path|paths|under|inside"
    r"|within|tree)\b",
    re.I,
)
_GIT_VERBS = ("add", "commit", "push")
_GIT_ADD: dict[str, Any] = {"type": "command", "program": "git", "subcommand": ["add"]}


def _tokens(text: str) -> list[str]:
    return _TOKEN.findall(text.strip().strip("`"))


def command_of(tokens: Sequence[str], *, strict: bool = False) -> dict[str, Any] | None:
    """A ``command`` predicate for the command *tokens* spell, or ``None``.

    With *strict*, for a command found in prose rather than in backticks: a
    program that is also an English word, a subcommand the program is not
    known to have, and a bare program with nothing after it are not
    commands.
    """
    words = list(tokens)
    while words and words[0].lower() in _WRAPPERS:
        words.pop(0)
    if not words:
        return None
    program = words[0].lower().rsplit("/", 1)[-1].rsplit("\\", 1)[-1]
    program = program[:-4] if program.endswith(".exe") else program
    if program not in PROGRAMS or (strict and program in _ENGLISH):
        return None
    rest = words[1:]
    subcommand: list[str] = []
    if program in SUBCOMMAND_PROGRAMS and rest and not rest[0].startswith("-"):
        subcommand.append(rest.pop(0).lower())
        known = _KNOWN_SUB.get(program, None)
        if strict and known is not None and subcommand[0] not in known:
            return None
        second = TWO_LEVEL.get(program, frozenset())
        takes_second = second is None or subcommand[0] in second
        if takes_second and rest and not rest[0].startswith("-"):
            subcommand.append(rest.pop(0))
    flags: list[str] = []
    args: list[str] = []
    for word in rest:
        if word.startswith("--") and len(word) > 2:
            flags.append(word.split("=", 1)[0])
        elif word.startswith("-") and len(word) > 1 and not word[1:].isdigit():
            flags += [f"-{c}" for c in word[1:]] if word[1] != "-" else [word]
        else:
            args.append(word)
    if strict and not (subcommand or flags or args):
        return None
    if strict and program in SUBCOMMAND_PROGRAMS and not subcommand:
        return None
    pred: dict[str, Any] = {"type": "command", "program": program}
    if subcommand:
        pred["subcommand"] = subcommand
    if len(flags) == 1:
        synonyms = _SYNONYMS.get((program, flags[0]), ())
        pred["flags_any"] = sorted({flags[0], *synonyms})
    elif flags:
        pred["flags_all"] = flags
    globs = [
        a
        for a in args
        if a in (".", "..") or any(c in a for c in "/*?\\") or a[:1] in ".~"
    ]
    if globs:
        pred["args_any_glob"] = globs
    return pred


def _command_in(text: str) -> dict[str, Any] | None:
    """The first command *text* names: in backticks, in prose, or as a phrase."""
    for span in _SPAN.findall(text):
        found = command_of(_tokens(span))
        if found is not None:
            return found
    words = _tokens(_SPAN.sub(" ", text))
    for index, word in enumerate(words):
        if word.lower() in PROGRAMS or word.lower() in _WRAPPERS:
            run: list[str] = []
            for later in words[index:]:
                if later.lower() in _PROSE_STOP and run:
                    break
                run.append(later.rstrip(",.;:"))
            found = command_of(run, strict=True)
            if found is not None:
                return found
    lower = text.lower()
    for pattern, spelled in _PHRASES:
        if pattern.search(lower):
            return command_of(spelled)
    for gerund, spelled in _GERUNDS.items():
        if re.search(rf"\b{gerund}\b", lower):
            return command_of(spelled)
    return None


def _command_phrase(text: str) -> dict[str, Any] | None:
    """A command from one side of "A before B" or "use X instead of Y"."""
    clean = _RUN.sub("", text.strip().strip("`,. "))
    return _command_in(clean) or _command_in(f"`{clean}`")


def _paths_in(text: str, *, except_for: str | None = None) -> list[tuple[str, int]]:
    """Every path-like token in *text* with where it starts, first first.

    In prose, ``a/b`` with no extension, no trailing slash and no anchor
    (``/``, ``~``, ``./``, a drive) is a path only when the sentence talks
    of a file, a folder, a directory or a path; in backticks it always is.
    """
    found: list[tuple[str, int]] = []
    seen: set[str] = set()
    spoken = _FILE_WORDS.search(text) is not None

    def keep(token: str, at: int, *, literal: bool) -> None:
        token = token.rstrip(".,;:")
        if len(token.strip("/\\")) < 2 or token in seen or token in _NOT_PATHS:
            return
        if re.fullmatch(r"\d+/\d+", token):
            return
        if except_for is not None and token.strip("`") == except_for:
            return
        if not literal and not spoken:
            bare = token.replace("\\", "/")
            anchored = bare.startswith(("/", "~", "./")) or re.match("[A-Za-z]:/", bare)
            plain = "/" in bare and not bare.endswith("/") and not anchored
            if plain and "." not in bare.rsplit("/", 1)[-1]:
                return
        seen.add(token)
        found.append((token, at))

    for match in _SPAN.finditer(text):
        inner = match.group(1).strip()
        if " " not in inner and _PATHLIKE.search(inner):
            keep(inner, match.start(), literal=True)
    blanked = _SPAN.sub(lambda m: " " * len(m.group(0)), text)
    for match in _PATHLIKE.finditer(blanked):
        keep(match.group(1), match.start(), literal=False)
    return sorted(found, key=lambda pair: pair[1])


def path_globs(token: str) -> list[str]:
    """Glob patterns for a path as a person wrote it.

    An absolute or home-relative path is itself (and, as a directory, what
    lies below it); a relative one matches in any directory.
    """
    text = token.replace("\\", "/").rstrip("/")
    directory = "." not in text.rsplit("/", 1)[-1]
    if text.startswith(("~", "/")) or re.match(r"[A-Za-z]:/", text):
        return [text, f"{text}/**"] if directory else [text]
    text = text[2:] if text.startswith("./") else text
    return [f"**/{text}", f"**/{text}/**"] if directory else [f"**/{text}"]


def _verb_class(text: str, at: int) -> str | None:
    """The kind of thing done to the path at *at*: the nearest verb before it."""
    best: tuple[int, str] | None = None
    for name, pattern in _VERBS.items():
        for match in pattern.finditer(text):
            if match.start() < at and (best is None or match.start() > best[0]):
                best = (match.start(), name)
    if best is not None:
        return best[1]
    for name, pattern in _VERBS.items():
        if pattern.search(text):
            return name
    return None


def _scope_dir(text: str) -> str | None:
    match = _SCOPE.search(text)
    return None if match is None else match.group(1).rstrip(".,;:")


def _slug(*parts: str) -> str:
    text = re.sub(r"[^a-z0-9]+", "-", " ".join(parts).lower()).strip("-")
    return text[:48].rstrip("-") or "rule"


def _name(token: str) -> str:
    return token.replace("\\", "/").rstrip("/").rsplit("/", 1)[-1]


@dataclass(frozen=True)
class Proposal:
    """What became of one statement: a rule, or a reason there is none."""

    statement: Statement
    rule: dict[str, Any] | None
    shape: str  #: command, path, stage, order, instead, or none
    note: str = ""
    covered: str = ""  #: Id of a rule already in effect that says the same.


def _text(statement: Statement) -> str:
    text = statement.text.strip()
    text = text[0].upper() + text[1:]
    return text if text.endswith((".", "!")) else f"{text}."


def _source(statement: Statement) -> str:
    more = f" and {statement.times - 1} more time(s)" if statement.times > 1 else ""
    return f"said {statement.date} in session {statement.session[:8]}{more}"


def _rule(
    statement: Statement,
    slug: str,
    effect: str,
    when: Mapping[str, Any],
    scope: str | None = None,
) -> dict[str, Any]:
    rule: dict[str, Any] = {
        "id": f"draft.{slug}",
        "text": _text(statement),
        "source": _source(statement),
        "effect": effect,
        "when": dict(when),
    }
    if scope is not None:
        rule["applies"] = {"cwd_under": [scope]}
    return rule


def _describe(pred: Mapping[str, Any]) -> str:
    parts = [str(pred.get("program", ""))]
    parts += list(pred.get("subcommand", ()))
    parts += list(pred.get("flags_all", ()) or pred.get("flags_any", ())[:1])
    return " ".join(p for p in parts if p)


def _git(*verbs: str) -> dict[str, Any]:
    commands = [command_of(["git", verb]) for verb in verbs]
    return {"type": "any", "of": commands}


def _touching(op: str, paths: Sequence[tuple[str, int]]) -> dict[str, Any]:
    globs: list[str] = []
    for token, _ in paths:
        globs += [g for g in path_globs(token) if g not in globs]
    return {"type": "path", "op": op, "glob": globs}


def _clauses(statement: Statement) -> list[str]:
    """The words a rule is made from: from each cue to the end of its clause.

    "Fetch it with get_file_contents (fresh SHA; never trust a remembered
    one)" is about trusting, not about fetching: what stands before the cue
    is context.  An order that starts with ``don't`` or ``stop`` is one
    clause, whole.
    """
    text = statement.text
    if statement.cue in ("stop", "do", "don't", "dont"):
        return [text]
    found = [
        _CLAUSE_END.split(text[match.start() :], 1)[0] for match in _CUE.finditer(text)
    ]
    return found or [text]


def _from_clause(statement: Statement, clause: str, effect: str) -> Proposal | None:
    """A rule from one clause, or ``None`` when it names nothing checkable."""
    command = _command_in(clause)
    scope = _scope_dir(clause)
    paths = _paths_in(clause, except_for=scope)
    if command is not None:
        slug = _slug(_describe(command))
        when: dict[str, Any] = command
        if paths and not command.get("args_any_glob"):
            when = {"type": "all", "of": [command, _touching("any", paths)]}
            slug = _slug(_describe(command), _name(paths[0][0]))
        rule = _rule(statement, slug, effect, when, scope)
        return Proposal(statement, rule, "command")
    if paths:
        token, at = paths[0]
        verb = _verb_class(clause, at) or "write"
        if verb == "stage":
            staged: dict[str, Any] = {
                "type": "all",
                "of": [dict(_GIT_ADD), _touching("any", paths)],
            }
            rule = _rule(
                statement, _slug("commit", _name(token)), effect, staged, scope
            )
            return Proposal(statement, rule, "stage")
        touched = _touching(verb, paths)
        rule = _rule(statement, _slug(verb, _name(token)), effect, touched, scope)
        return Proposal(statement, rule, "path")
    if scope is not None and _VERBS["stage"].search(clause):
        rule = _rule(
            statement, _slug("git", _name(scope)), effect, _git(*_GIT_VERBS), scope
        )
        return Proposal(statement, rule, "stage")
    return None


def propose(statement: Statement) -> Proposal:
    """One statement as a rule the gate can check, or as said."""
    text = statement.text
    effect = "ask" if statement.kind == "never" else "warn"

    instead = _INSTEAD.match(text)
    if instead is not None:
        other = _command_phrase(instead.group("y"))
        if other is not None:
            slug = _slug("use", instead.group("x")[:24], "not", _describe(other))
            return Proposal(statement, _rule(statement, slug, "warn", other), "instead")

    ordered = _WITHOUT.match(text) or _BEFORE.match(text)
    if ordered is not None:
        first = _command_phrase(ordered.group("a"))
        then = _command_phrase(ordered.group("b"))
        if first is not None and then is not None:
            after = {"type": "not_preceded_by", "predicate": first}
            when = {"type": "all", "of": [then, after]}
            slug = _slug(_describe(first), "before", _describe(then))
            return Proposal(statement, _rule(statement, slug, "ask", when), "order")
        if then is not None:
            note = "the command that must come first is not named"
            return Proposal(statement, None, "none", note)

    if statement.kind == "always":
        note = "says what to do, not what to stop; add 'instead of ...' or 'before ...'"
        return Proposal(statement, None, "none", note)

    for clause in _clauses(statement):
        made = _from_clause(statement, clause, effect)
        if made is not None:
            return made
    note = "names no command or path the gate can check"
    return Proposal(statement, None, "none", note)


# ---------------------------------------------------------------------------
# The draft
# ---------------------------------------------------------------------------
@dataclass
class Draft:
    """Everything one run found."""

    transcripts: int = 0
    sessions: int = 0
    statements: list[Statement] = field(default_factory=list)
    proposals: list[Proposal] = field(default_factory=list)

    def as_dict(self) -> dict[str, Any]:
        return {
            "transcripts": self.transcripts,
            "sessions": self.sessions,
            "statements": len(self.statements),
            "proposals": [
                {
                    "rule": p.rule,
                    "shape": p.shape,
                    "note": p.note,
                    "covered": p.covered,
                    "statement": {
                        "text": p.statement.text,
                        "kind": p.statement.kind,
                        "cue": p.statement.cue,
                        "session": p.statement.session,
                        "when": p.statement.when,
                        "times": p.statement.times,
                    },
                }
                for p in self.proposals
            ],
        }


def collect(paths: Iterable[str], *, since: float | None = None) -> Draft:
    """Every distinct standing order in the transcripts, earliest first.

    Raises
    ------
    FileNotFoundError
        If a path does not exist.
    """
    result = Draft()
    seen: dict[str, Statement] = {}
    sessions: set[str] = set()
    for file in transcript_files(paths):
        result.transcripts += 1
        for statement in statements(file, since=since):
            sessions.add(statement.session)
            key = _key(statement.text)
            earlier = seen.get(key)
            if earlier is None:
                seen[key] = statement
            elif statement.when and (not earlier.when or statement.when < earlier.when):
                seen[key] = replace(statement, times=earlier.times + 1)
            else:
                seen[key] = replace(earlier, times=earlier.times + 1)
    result.sessions = len(sessions)
    result.statements = sorted(seen.values(), key=lambda s: (s.when, s.text))
    return result


def _same(rule: Mapping[str, Any], others: Iterable[Rule]) -> str:
    """Id of a rule in *others* with the same condition and scope, or ""."""
    try:
        parsed = parse_rule(rule)
    except LedgerError:
        return ""
    for other in others:
        if other.predicate == parsed.predicate and other.applies == parsed.applies:
            return other.id
        if _key(other.text) == _key(parsed.text):
            return other.id
    return ""


def draft(
    paths: Iterable[str],
    *,
    since: float | None = None,
    existing: Iterable[Rule] = (),
) -> Draft:
    """Read the transcripts and propose a rule for every order that fits a shape.

    *existing* are the rules in effect; a proposal that says what one of
    them already says is marked ``covered`` with that rule's id.  Ids are
    unique among the proposals and against *existing*.
    """
    others = list(existing)
    taken = {rule.id for rule in others}
    result = collect(paths, since=since)
    for statement in result.statements:
        proposal = propose(statement)
        if proposal.rule is not None:
            try:
                parse_rule(proposal.rule)
            except LedgerError as exc:
                note = f"not a valid rule: {exc}"
                proposal = replace(proposal, rule=None, shape="none", note=note)
        if proposal.rule is not None:
            base = str(proposal.rule["id"])
            candidate, n = base, 2
            while candidate in taken:
                candidate, n = f"{base}-{n}", n + 1
            taken.add(candidate)
            rule = {**proposal.rule, "id": candidate}
            proposal = replace(proposal, rule=rule, covered=_same(rule, others))
        result.proposals.append(proposal)
    return result


def render(result: Draft) -> str:
    """The draft as text: counts, then the drafted rules, then the rest."""
    drafted = [p for p in result.proposals if p.rule is not None]
    rest = [p for p in result.proposals if p.rule is None]
    kinds = {
        k: sum(1 for s in result.statements if s.kind == k) for k in ("never", "always")
    }
    shapes = sorted({p.shape for p in drafted})
    by_shape = ", ".join(
        f"{shape} {sum(1 for p in drafted if p.shape == shape)}" for shape in shapes
    )
    covered = sum(1 for p in drafted if p.covered)
    lines = [
        f"{result.transcripts} transcript(s), {result.sessions} session(s) with an "
        f"order: {len(result.statements)} standing order(s) "
        f"({kinds['never']} never, {kinds['always']} always)",
        f"  drafted {len(drafted)}"
        + (f" ({by_shape})" if by_shape else "")
        + f", not formalised {len(rest)}, already in the ledger {covered}",
    ]
    if drafted:
        lines += ["", "## drafted (unconfirmed until you confirm them)"]
        for p in drafted:
            rule = p.rule or {}
            lines.append(
                f"{rule['id']}  [{rule['effect']}, {p.shape}]  {rule['source']}"
            )
            lines.append(f"    {rule['text']}")
            lines.append(f"    when: {json.dumps(rule['when'], separators=(',', ':'))}")
            if "applies" in rule:
                scope = json.dumps(rule["applies"], separators=(",", ":"))
                lines.append(f"    applies: {scope}")
            if p.covered:
                lines.append(f"    already in the ledger as {p.covered}")
    if rest:
        lines += [
            "",
            "## said, not drafted (write these by hand, or sharpen the words)",
        ]
        for p in rest:
            s = p.statement
            more = f" (x{s.times})" if s.times > 1 else ""
            lines.append(f"{s.date}  {s.session[:8]}  {s.text}{more}")
            lines.append(f"    {p.note}")
    return "\n".join(lines)
