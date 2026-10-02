"""The built-in pack of destructive-action rules.

Every rule here is ordinary ledger data: a dictionary in the ledger file
format, validated by the same parser and evaluated by the same engine as a
user's rules.  There are no special-cased checks in code.  The helper
functions below only shorten the dictionaries.
"""

from __future__ import annotations

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


def _all(*preds: Pred) -> Pred:
    return {"type": "all", "of": list(preds)}


def _not(pred: Pred) -> Pred:
    return {"type": "not", "of": pred}


def _rule(rule_id: str, effect: str, text: str, when: Pred) -> dict[str, Any]:
    return {
        "id": f"builtin.{rule_id}",
        "text": text,
        "source": SOURCE,
        "effect": effect,
        "when": when,
        "confirmed": True,
    }


#: Build, cache and temporary directories whose contents are disposable.
DISPOSABLE = [
    "**/node_modules", "**/dist", "**/build", "**/.venv", "**/venv",
    "**/__pycache__", "**/.pytest_cache", "**/target", "**/.mypy_cache",
    "**/.ruff_cache", "**/.tox", "**/.next", "**/.turbo", "**/.cache",
    "**/coverage", "**/htmlcov", "**/*.egg-info", "**/tmp", "**/temp", "**/.tmp",
    "/var/folders", "/private/var/folders", "**/AppData/Local/Temp",
    "$TMPDIR", "$TEMP", "$TMP",
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
    "**/id_rsa", "**/id_dsa", "**/id_ecdsa", "**/id_ed25519", "**/*.ppk",
    "**/*.p12", "**/*.pfx", "**/*.key", "**/*private*.pem", "**/*key*.pem",
    "**/.aws/credentials", "**/.netrc", "**/_netrc", "**/.pypirc",
    "**/.git-credentials", "**/.kube/config", "**/.docker/config.json",
    "**/credentials.json",
]  # fmt: skip
SQL_CLIENTS = [
    "psql", "mysql", "mariadb", "sqlite3", "sqlcmd", "pgcli", "mycli", "duckdb",
    "clickhouse-client", "cockroach", "snowsql", "sqlplus", "usql", "bq",
    "wrangler", "turso", "Invoke-Sqlcmd",
]  # fmt: skip
DESTRUCTIVE_SQL = (
    r"(?is)\b(?:drop\s+(?:table|database|schema|index|view|column|role|user|"
    r"function|trigger|sequence|type|extension|materialized)\b"
    r"|truncate\s+(?:table\s+)?[\"`\[]?\w"
    r"|delete\s+from\s+(?:(?:\"[^\"\s]+\"|`[^`\s]+`|\[[^\]\s]+\]|[\w$]+)\.?)++"
    r"(?![^;\"']*\bwhere\b))"
)
_TRUE = ["$true", "true", "1", "*:$true", "*:true", "*:1"]
_FALSE = ["$false", "false", "0", "*:$false", "*:false", "*:0"]
_MACHINE_KEYS = ["HKLM*", "hklm*", "HKEY_LOCAL_MACHINE*", "hkey_local_machine*",
                 "HKCR*", "hkcr*", "HKEY_CLASSES_ROOT*", "*::HKEY_LOCAL_MACHINE*",
                 "*:HKLM:*"]  # fmt: skip
_FIREWALL_UNITS = ["firewalld*", "ufw*", "nftables*", "iptables*"]
_DEFENDER = ["WinDefend", "windefend", "MpsSvc", "mpssvc", "Sense", "WdNisSvc"]
_BCDEDIT_CHANGES = ["/set", "/delete", "/deletevalue", "/create", "/copy", "/import",
                    "/default", "/displayorder", "/bootsequence", "/timeout",
                    "/debug", "/bootdebug"]  # fmt: skip


def _git(*subcommand: str, **fields: Any) -> Pred:
    return _command("git", *subcommand, **fields)


_RECURSIVE_DELETE = {
    "type": "path",
    "op": "delete",
    "recursive": True,
    "not_under": DISPOSABLE,
}

_RULES: list[dict[str, Any]] = [
    # -- recursive deletion --------------------------------------------------
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
        "Never recursively delete a .git directory: it is the repository's "
        "whole history.",
        {**_RECURSIVE_DELETE, "glob": ["**/.git"]},
    ),
    _rule(
        "delete.recursive",
        "ask",
        "Ask before deleting a directory tree outside build, cache and "
        "temporary directories.",
        _RECURSIVE_DELETE,
    ),
    # -- git history and working tree ----------------------------------------
    _rule(
        "git.force-push",
        "ask",
        "Ask before force-pushing: it rewrites history on the remote.",
        _any(
            _git("push", flags_any=["-f", "--force", "--force-with-lease"]),
            _git("push", args_any_glob=["+*"]),
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
        _all(
            _git("clean", flags_any=["-f", "--force"]),
            _not(_git("clean", flags_any=["-n", "--dry-run"])),
        ),
    ),
    _rule(
        "git.discard-worktree",
        "ask",
        "Ask before discarding all working-tree changes "
        "(git checkout -- . / git restore .).",
        _any(
            _git("checkout", args_any_glob=[".", "./", ":/"]),
            _git("checkout", flags_any=["-f", "--force"]),
            _all(
                _git("restore", args_any_glob=[".", "./", ":/"]),
                _any(
                    _not(_git("restore", flags_any=["--staged", "-S"])),
                    _git("restore", flags_any=["--worktree", "-W"]),
                ),
            ),
        ),
    ),
    _rule(
        "git.branch-force-delete",
        "ask",
        "Ask before force-deleting a branch (git branch -D).",
        _any(
            _git("branch", flags_any=["-D"]),
            _git("branch", flags_all=["--delete", "--force"]),
        ),
    ),
    # -- SQL -----------------------------------------------------------------
    _rule(
        "sql.destructive",
        "ask",
        "Ask before DROP, TRUNCATE, or DELETE without WHERE through a database client.",
        _all(
            _command(SQL_CLIENTS),
            {"type": "text_regex", "field": "command", "pattern": DESTRUCTIVE_SQL},
        ),
    ),
    # -- cloud and platform deletion -----------------------------------------
    _rule(
        "cloud.gh-repo-delete",
        "ask",
        "Ask before deleting a GitHub repository.",
        _command("gh", "repo", "delete"),
    ),
    _rule(
        "cloud.vercel-remove",
        "ask",
        "Ask before removing a Vercel deployment or project.",
        _any(_command(["vercel", "vc"], "remove"), _command(["vercel", "vc"], "rm")),
    ),
    _rule(
        "cloud.terraform-destroy",
        "ask",
        "Ask before terraform destroy.",
        _any(
            _command(["terraform", "tofu", "terragrunt"], "destroy"),
            _command(
                ["terraform", "tofu", "terragrunt"],
                "apply",
                flags_any=["-destroy", "--destroy"],
            ),
        ),  # fmt: skip
    ),
    _rule(
        "cloud.kubectl-delete",
        "ask",
        "Ask before deleting Kubernetes resources.",
        _command(["kubectl", "oc"], "delete"),
    ),
    _rule(
        "cloud.docker-prune",
        "ask",
        "Ask before docker system prune -a: it removes all unused images.",
        _command(["docker", "podman"], "system", "prune", flags_any=["-a", "--all"]),
    ),
    _rule(
        "cloud.docker-volume-rm",
        "ask",
        "Ask before removing Docker volumes: their data is not recoverable.",
        _command(["docker", "podman"], "volume", "rm"),
    ),
    _rule(
        "cloud.aws-s3-delete",
        "ask",
        "Ask before removing an S3 bucket or deleting objects recursively.",
        _any(
            _command("aws", "s3", "rb"),
            _command("aws", "s3", "rm", flags_any=["--recursive"]),
        ),
    ),
    _rule(
        "cloud.npm-unpublish",
        "ask",
        "Ask before unpublishing a package from the registry.",
        _command(["npm", "pnpm"], "unpublish"),
    ),
    # -- system trust and defences -------------------------------------------
    _rule(
        "system.trust-root-cert",
        "ask",
        "Ask before adding a certificate to a trusted root store.",
        _any(
            _command(
                "certutil",
                flags_any=["-addstore", "/addstore"],
                args_any_glob=["[Rr][Oo][Oo][Tt]", "[Aa]uth[Rr]oot"],
            ),
            _command(
                "Import-Certificate",
                args_any_glob=[
                    "cert:\\*\\root",
                    "cert:\\*\\authroot",
                    "*:cert:\\*\\root",
                ],
            ),
            _command("security", "add-trusted-cert"),
            _command(["update-ca-certificates", "update-ca-trust"]),
            _command("trust", "anchor"),
        ),  # fmt: skip
    ),
    _rule(
        "system.firewall-off",
        "ask",
        "Ask before turning off a firewall.",
        _any(
            _command("netsh", "advfirewall", "set", args_any_glob=["off", "OFF"]),
            _command("netsh", "firewall", "set", args_any_glob=["disable", "DISABLE"]),
            _command(
                "Set-NetFirewallProfile", flags_any=["-Enabled"], args_any_glob=_FALSE
            ),
            _command("ufw", "disable"),
            _command("systemctl", "stop", args_any_glob=_FIREWALL_UNITS),
            _command("systemctl", "disable", args_any_glob=_FIREWALL_UNITS),
            _command("systemctl", "mask", args_any_glob=_FIREWALL_UNITS),
        ),  # fmt: skip
    ),
    _rule(
        "system.antivirus-off",
        "ask",
        "Ask before turning off antivirus protection or adding exclusions.",
        _any(
            _command(
                "Set-MpPreference",
                args_any_glob=_TRUE,
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
                flags_any=[
                    "-ExclusionPath",
                    "-ExclusionProcess",
                    "-ExclusionExtension",
                ],
            ),
            _command(["Stop-Service", "Set-Service"], args_any_glob=_DEFENDER),
            _command("sc", "stop", args_any_glob=_DEFENDER),
            _command("sc", "config", args_any_glob=_DEFENDER),
            _command("sc", "delete", args_any_glob=_DEFENDER),
            _command("net", "stop", args_any_glob=_DEFENDER),
        ),  # fmt: skip
    ),
    _rule(
        "system.registry-delete",
        "ask",
        "Ask before deleting machine-wide registry keys.",
        _any(
            _command("reg", "delete", args_any_glob=_MACHINE_KEYS),
            _command(
                ["Remove-Item", "Remove-ItemProperty"], args_any_glob=_MACHINE_KEYS
            ),
        ),
    ),
    _rule(
        "system.disk",
        "ask",
        "Ask before formatting, repartitioning or changing boot configuration.",
        _any(
            _command("format", args_any_glob=["?:", "?:\\", "?:/"]),
            _command(["Format-Volume", "Clear-Disk"]),
            _command("diskpart"),
            _command("bcdedit", flags_any=_BCDEDIT_CHANGES),
        ),
    ),
    # -- secrets -------------------------------------------------------------
    _rule(
        "secrets.read",
        "ask",
        "Ask before reading secret files: .env files, private keys and "
        "credential files.",
        {"type": "path", "op": "read", "glob": SECRET_FILES},
    ),
    # -- download piped into a shell -----------------------------------------
    _rule(
        "shell.download-pipe",
        "ask",
        "Ask before running a download directly in a shell.",
        {"type": "dynamic_shell", "reason": ["download_pipe"]},
    ),
]


def builtin_document() -> dict[str, Any]:
    """The built-in pack as a ledger document (``version`` and ``rules``)."""
    return {"version": LEDGER_VERSION, "rules": _RULES}


@lru_cache(maxsize=1)
def builtin_rules() -> tuple[Rule, ...]:
    """The validated built-in rules."""
    return tuple(parse_ledger(builtin_document(), origin="builtin", name="builtin"))
