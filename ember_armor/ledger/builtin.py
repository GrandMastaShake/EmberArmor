"""The built-in pack of destructive-action rules.

Every rule here is ordinary ledger data: a dictionary in the ledger file
format, validated by the same parser and evaluated by the same engine as a
user's rules.  There are no special-cased checks in code.  The helper
functions below only shorten the dictionaries.
"""

from __future__ import annotations

from collections.abc import Sequence
from functools import lru_cache
from typing import Any

from ember_armor.ledger.model import LEDGER_VERSION, Rule, parse_ledger

SOURCE = "EmberArmor built-in pack"

Pred = dict[str, Any]


def _command(program: str | list[str], *subcommand: str, **fields: Any) -> Pred:
    pred: Pred = {"type": "command", "program": program, **fields}
    if subcommand:
        pred["subcommand"] = list(subcommand)
    return pred


def _any(*preds: Pred) -> Pred:
    return {"type": "any", "of": list(preds)}


def _rule(rule_id: str, effect: str, text: str, when: Pred) -> dict[str, Any]:
    return {
        "id": f"builtin.{rule_id}",
        "text": text,
        "source": SOURCE,
        "effect": effect,
        "when": when,
        "confirmed": True,
    }


def _either_case(text: str) -> str:
    """Glob that matches *text* in any letter case (for case-sensitive shells)."""
    return "".join(f"[{c.upper()}{c.lower()}]" if c.isalpha() else c for c in text)


#: Build, cache and temporary directories whose contents are disposable, and
#: files a tool regenerates.  Only names that mean one thing: ``out``,
#: ``bin`` or ``vendor`` are left to the user's ``disposable`` setting.
DISPOSABLE = [
    "**/node_modules", "**/dist", "**/build", "**/.venv", "**/venv",
    "**/__pycache__", "**/.pytest_cache", "**/target", "**/.mypy_cache",
    "**/.ruff_cache", "**/.tox", "**/.nox", "**/.next", "**/.nuxt", "**/.output",
    "**/.turbo", "**/.cache", "**/.parcel-cache", "**/.vite", "**/.svelte-kit",
    "**/.astro", "**/.angular", "**/.swc", "**/.docusaurus", "**/.expo",
    "**/storybook-static", "**/coverage", "**/htmlcov", "**/.nyc_output",
    "**/playwright-report", "**/test-results", "**/TestResults",
    "**/.hypothesis", "**/.ipynb_checkpoints", "**/*.egg-info", "**/.eggs",
    "**/.gradle", "**/.dart_tool", "**/obj", "**/cdk.out", "**/.aws-sam",
    "**/.serverless", "**/_build", "**/_site", "**/.pnpm-store",
    "**/npm-cache", "**/_cacache", "**/_npx", "**/pip/cache",
    "**/tmp", "**/temp", "**/.tmp", "/var/folders", "/private/var/folders",
    "**/AppData/Local/Temp", "$TMPDIR", "$TEMP", "$TMP",
    "**/package-lock.json", "**/yarn.lock", "**/pnpm-lock.yaml", "**/*.log",
    "**/*.tsbuildinfo", "**/.eslintcache", "**/.coverage", "**/.DS_Store",
    "**/*.pyc", "**/*.map", "**/*.tgz",
]  # fmt: skip
#: Filesystem roots, home directories and users directories.
PROTECTED = [
    "/", "?:/", "~", "/root", "/home", "/home/*", "/Users", "/Users/*",
    "?:/Users", "?:/Users/*",
]  # fmt: skip
SECRET_FILES = [
    "**/.env", "**/.env.local", "**/.env.*.local", "**/.env.production",
    "**/.env.prod", "**/.env.development", "**/.env.dev", "**/.env.staging",
    "**/.env.test", "**/.envrc",
    "**/id_rsa", "**/id_dsa", "**/id_ecdsa", "**/id_ed25519", "**/.ssh/*",
    "**/*.ppk", "**/*.p12", "**/*.pfx", "**/*.key", "**/*private*.pem",
    "**/*key*.pem", "**/.aws/credentials", "**/.netrc", "**/_netrc",
    "**/.pypirc", "**/.git-credentials", "**/.kube/config",
    "**/.docker/config.json", "**/credentials.json",
]  # fmt: skip
#: Files the secret globs would catch that hold nothing secret.
NOT_SECRET = [
    "**/*.pub", "**/*public*.pem", "**/*pubkey*.pem", "**/*public*.key",
    "**/.ssh/config", "**/.ssh/known_hosts*", "**/.ssh/authorized_keys*",
]  # fmt: skip
SQL_CLIENTS = [
    "psql", "mysql", "mariadb", "sqlite3", "sqlcmd", "pgcli", "mycli", "duckdb",
    "clickhouse-client", "cockroach", "snowsql", "sqlplus", "usql",
    "Invoke-Sqlcmd",
]  # fmt: skip
#: A destructive statement outside single-quoted SQL literals.  When the
#: quotes do not pair up, or the text runs dynamic SQL, literals are not
#: trusted and the statement is looked for everywhere.
DESTRUCTIVE_SQL = (
    r"(?is)\A(?:(?:[^']|'[^']*')*?"
    r"|(?=[^']*'(?:[^']*'[^']*')*+[^']*\Z|.*\b(?:exec|execute|prepare)\b).*?)"
    r"\b(?:drop\s+(?:table|database|schema|index|view|column|role|user|"
    r"function|trigger|sequence|type|extension|materialized)\b"
    r"|truncate\s+(?:table\s+)?[\"`\[]?\w"
    r"|delete\s+from\s+(?:(?:\"[^\"\s]+\"|`[^`\s]+`|\[[^\]\s]+\]|[\w$]+)\.?)++"
    r"(?![^;\"']*\bwhere\b))"
)
_HELP = ["--help", "-h"]
_TRUE = ["$true", "true", "1", "*:$true", "*:true", "*:1"]
_FALSE = ["$false", "false", "0", "*:$false", "*:false", "*:0"]
#: ``-WhatIf`` as written when it is switched on (not ``-WhatIf:$false``).
_WHAT_IF = ["-whatif", "-whatif:$true", "-whatif:true", "-whatif:1", "-wi"]
_HKLM, _HKCR = _either_case("HKLM"), _either_case("HKCR")
_MACHINE = _either_case("HKEY_LOCAL_MACHINE")
_CLASSES = _either_case("HKEY_CLASSES_ROOT")
#: Registry syntax only: a key always has a colon or a backslash after the hive.
_MACHINE_KEYS = [
    f"{_HKLM}:*", f"{_HKLM}\\*", f"{_MACHINE}\\*", f"{_HKCR}:*", f"{_HKCR}\\*",
    f"{_CLASSES}\\*", f"*::{_MACHINE}*", f"*::{_CLASSES}*", f"*:{_HKLM}:*",
]  # fmt: skip
_ADD_ROOT = r"(?i)(?:^|\s)[-/]addstore\s(?:.*\s)?(?:root|authroot)(?:\s|$)"
_FIREWALL_UNITS = ["firewalld*", "ufw*", "nftables*", "iptables*"]
_DEFENDER = ["WinDefend", "windefend", "MpsSvc", "mpssvc", "Sense", "WdNisSvc"]
_BCDEDIT_CHANGES = ["/set", "/delete", "/deletevalue", "/create", "/copy", "/import",
                    "/default", "/displayorder", "/bootsequence", "/timeout",
                    "/debug", "/bootdebug"]  # fmt: skip
_WORKTREE = [".", "./", ":/"]
_TERRAFORM = ["terraform", "tofu", "terragrunt"]
_TERRAFORM_HELP = ["-help", "--help"]


def _git(*subcommand: str, **fields: Any) -> Pred:
    return _command("git", *subcommand, **{"flags_none": _HELP, **fields})


def _sql(program: str | list[str], *subcommand: str) -> Pred:
    return _command(program, *subcommand, args_regex=DESTRUCTIVE_SQL)


def _rules(disposable: Sequence[str]) -> list[dict[str, Any]]:
    recursive_delete = {
        "type": "path",
        "op": "delete",
        "recursive": True,
        "not_within": [*DISPOSABLE, *disposable],
    }
    return [
        # -- recursive deletion ----------------------------------------------
        _rule(
            "delete.protected",
            "deny",
            "Never recursively delete a filesystem root, a home directory or a "
            "users directory.",
            {"type": "path", "op": "delete", "recursive": True, "glob": PROTECTED},
        ),
        _rule(
            "delete.git-dir",
            "deny",
            "Never recursively delete the .git directory of the repository you "
            "are in: it is the repository's whole history.",
            # A .git below a subdirectory (a fresh clone, a vendored copy) is
            # left to delete.recursive, which asks.
            {**recursive_delete, "glob": ["**/.git"], "not_glob": ["*/**/.git"]},
        ),
        _rule(
            "delete.recursive",
            "ask",
            "Ask before deleting a directory tree outside build, cache and "
            "temporary directories.",
            recursive_delete,
        ),
        # -- git history and working tree ------------------------------------
        _rule(
            "git.force-push",
            "ask",
            "Ask before force-pushing: it rewrites history on the remote.",
            _any(
                _git(
                    "push",
                    flags_any=["-f", "--force", "--force-with-lease"],
                    flags_none=["-n", "--dry-run", *_HELP],
                ),
                _git(
                    "push",
                    args_any_glob=["+*"],
                    flags_none=["-n", "--dry-run", *_HELP],
                ),
            ),
        ),
        _rule(
            "git.reset-hard",
            "ask",
            "Ask before git reset --hard: it discards uncommitted work.",
            _git("reset", flags_any=["--hard"]),
        ),
        _rule(
            "git.clean",
            "ask",
            "Ask before git clean -f: it deletes untracked files.",
            _git(
                "clean",
                flags_any=["-f", "--force"],
                flags_none=["-n", "--dry-run", *_HELP],
            ),
        ),
        _rule(
            "git.discard-worktree",
            "ask",
            "Ask before discarding all working-tree changes "
            "(git checkout -- . / git restore .).",
            _any(
                _git("checkout", args_any_glob=_WORKTREE),
                _git("checkout", flags_any=["-f", "--force"]),
                _git("switch", flags_any=["-f", "--force", "--discard-changes"]),
                _git(
                    "restore",
                    args_any_glob=_WORKTREE,
                    flags_none=["--staged", "-S", *_HELP],
                ),
                _git(
                    "restore", args_any_glob=_WORKTREE, flags_any=["--worktree", "-W"]
                ),
            ),
        ),
        _rule(
            "git.branch-force-delete",
            "ask",
            "Ask before force-deleting a branch (git branch -D).",
            _any(
                _git("branch", flags_any=["-D"]),
                *(
                    _git("branch", flags_all=[delete, force])
                    for delete in ("-d", "--delete")
                    for force in ("-f", "--force")
                ),
            ),
        ),
        # -- SQL -------------------------------------------------------------
        _rule(
            "sql.destructive",
            "ask",
            "Ask before DROP, TRUNCATE, or DELETE without WHERE through a "
            "database client.",
            _any(
                _sql(SQL_CLIENTS),
                _sql("wrangler", "d1", "execute"),
                _sql("turso", "db", "shell"),
                _sql("bq", "query"),
            ),
        ),
        # -- cloud and platform deletion -------------------------------------
        _rule(
            "cloud.gh-repo-delete",
            "ask",
            "Ask before deleting a GitHub repository.",
            _command("gh", "repo", "delete", flags_none=_HELP),
        ),
        _rule(
            "cloud.vercel-remove",
            "ask",
            "Ask before removing a Vercel deployment or project.",
            _any(
                _command(["vercel", "vc"], "remove", flags_none=_HELP),
                _command(["vercel", "vc"], "rm", flags_none=_HELP),
            ),
        ),
        _rule(
            "cloud.terraform-destroy",
            "ask",
            "Ask before terraform destroy.",
            _any(
                _command(_TERRAFORM, "destroy", flags_none=_TERRAFORM_HELP),
                _command(
                    _TERRAFORM,
                    "apply",
                    flags_any=["-destroy", "--destroy"],
                    flags_none=_TERRAFORM_HELP,
                ),
            ),
        ),
        _rule(
            "cloud.kubectl-delete",
            "ask",
            "Ask before deleting Kubernetes resources.",
            _command(
                ["kubectl", "oc"],
                "delete",
                flags_none=_HELP,
                args_none_glob=["--dry-run", "--dry-run=client", "--dry-run=server"],
            ),
        ),
        _rule(
            "cloud.docker-prune",
            "ask",
            "Ask before docker system prune -a: it removes all unused images.",
            _command(
                ["docker", "podman"],
                "system",
                "prune",
                flags_any=["-a", "--all"],
                flags_none=["--help"],
            ),
        ),
        _rule(
            "cloud.docker-volume-rm",
            "ask",
            "Ask before removing Docker volumes: their data is not recoverable.",
            _command(["docker", "podman"], "volume", "rm", flags_none=["--help"]),
        ),
        _rule(
            "cloud.aws-s3-delete",
            "ask",
            "Ask before removing an S3 bucket or deleting objects recursively.",
            _any(
                _command("aws", "s3", "rb", args_none_glob=["help"]),
                _command(
                    "aws",
                    "s3",
                    "rm",
                    flags_any=["--recursive"],
                    flags_none=["--dryrun"],
                    args_none_glob=["help"],
                ),
            ),
        ),
        _rule(
            "cloud.npm-unpublish",
            "ask",
            "Ask before unpublishing a package from the registry.",
            _command(["npm", "pnpm"], "unpublish", flags_none=["--dry-run", *_HELP]),
        ),
        # -- system trust and defences ---------------------------------------
        _rule(
            "system.trust-root-cert",
            "ask",
            "Ask before adding a certificate to a trusted root store.",
            _any(
                # certutil ignores letter case, whichever shell starts it.
                _command("certutil", args_regex=_ADD_ROOT),
                _command(
                    "Import-Certificate",
                    args_any_glob=[
                        "cert:\\*\\root",
                        "cert:\\*\\authroot",
                        "*:cert:\\*\\root",
                    ],
                    args_none_glob=_WHAT_IF,
                ),
                _command("security", "add-trusted-cert"),
                _command(
                    ["update-ca-certificates", "update-ca-trust"], flags_none=_HELP
                ),
                _command("trust", "anchor"),
            ),
        ),
        _rule(
            "system.firewall-off",
            "ask",
            "Ask before turning off a firewall.",
            _any(
                # netsh ignores letter case, whichever shell starts it.
                _command(
                    "netsh", "advfirewall", "set", args_any_glob=[_either_case("off")]
                ),
                _command(
                    "netsh", "firewall", "set", args_any_glob=[_either_case("disable")]
                ),
                _command(
                    "Set-NetFirewallProfile",
                    flags_any=["-Enabled"],
                    args_any_glob=_FALSE,
                    args_none_glob=_WHAT_IF,
                ),
                _command("ufw", "disable"),
                _command("systemctl", "stop", args_any_glob=_FIREWALL_UNITS),
                _command("systemctl", "disable", args_any_glob=_FIREWALL_UNITS),
                _command("systemctl", "mask", args_any_glob=_FIREWALL_UNITS),
            ),
        ),
        _rule(
            "system.antivirus-off",
            "ask",
            "Ask before turning off antivirus protection or adding exclusions.",
            _any(
                _command(
                    "Set-MpPreference",
                    args_any_glob=_TRUE,
                    args_none_glob=_WHAT_IF,
                    flags_any=[
                        "-DisableRealtimeMonitoring",
                        "-DisableBehaviorMonitoring",
                        "-DisableIOAVProtection",
                        "-DisableScriptScanning",
                        "-DisableBlockAtFirstSeen",
                        "-DisableIntrusionPreventionSystem",
                    ],
                ),
                _command(
                    "Add-MpPreference",
                    args_none_glob=_WHAT_IF,
                    flags_any=[
                        "-ExclusionPath",
                        "-ExclusionProcess",
                        "-ExclusionExtension",
                    ],
                ),
                _command(
                    ["Stop-Service", "Set-Service"],
                    args_any_glob=_DEFENDER,
                    args_none_glob=_WHAT_IF,
                ),
                _command("sc", "stop", args_any_glob=_DEFENDER),
                _command("sc", "config", args_any_glob=_DEFENDER),
                _command("sc", "delete", args_any_glob=_DEFENDER),
                _command("net", "stop", args_any_glob=_DEFENDER),
            ),
        ),
        _rule(
            "system.registry-delete",
            "ask",
            "Ask before deleting machine-wide registry keys.",
            _any(
                _command("reg", "delete", args_any_glob=_MACHINE_KEYS),
                _command(
                    ["Remove-Item", "Remove-ItemProperty"],
                    args_any_glob=_MACHINE_KEYS,
                    args_none_glob=_WHAT_IF,
                ),
            ),
        ),
        _rule(
            "system.disk",
            "ask",
            "Ask before formatting, repartitioning or changing boot configuration.",
            _any(
                _command("format", args_any_glob=["?:", "?:\\", "?:/"]),
                _command(["Format-Volume", "Clear-Disk"], args_none_glob=_WHAT_IF),
                _command("diskpart", flags_none=["/?"]),
                _command("bcdedit", flags_any=_BCDEDIT_CHANGES),
            ),
        ),
        # -- secrets ---------------------------------------------------------
        _rule(
            "secrets.read",
            "ask",
            "Ask before reading secret files: .env files, private keys and "
            "credential files.",
            {
                "type": "path",
                "op": "read",
                "glob": SECRET_FILES,
                "not_glob": NOT_SECRET,
                "not_under": ["**/node_modules"],
            },
        ),
        # -- shell input the gate cannot vouch for ---------------------------
        _rule(
            "shell.download-pipe",
            "ask",
            "Ask before running a download directly in a shell.",
            {"type": "dynamic_shell", "reason": ["download_pipe"]},
        ),
        _rule(
            "shell.unreadable",
            "ask",
            "Ask before running a shell command the gate could not read in "
            "full: the other rules could not be checked against it.",
            {"type": "dynamic_shell", "reason": ["parse_error", "encoded_command"]},
        ),
    ]


def builtin_document(disposable: Sequence[str] = ()) -> dict[str, Any]:
    """The built-in pack as a ledger document (``version`` and ``rules``).

    Parameters
    ----------
    disposable:
        Further directory patterns the user treats as disposable (the
        ``disposable`` list of ``config.json``), added to :data:`DISPOSABLE`.
    """
    return {"version": LEDGER_VERSION, "rules": _rules(disposable)}


@lru_cache(maxsize=8)
def builtin_rules(disposable: tuple[str, ...] = ()) -> tuple[Rule, ...]:
    """The validated built-in rules (see :func:`builtin_document`)."""
    document = builtin_document(disposable)
    return tuple(parse_ledger(document, origin="builtin", name="builtin"))
