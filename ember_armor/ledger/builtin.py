"""The built-in pack of destructive-action rules.

Every rule here is ordinary ledger data: a dictionary in the ledger file
format, validated by the same parser and evaluated by the same engine as a
user's rules.  There are no special-cased checks in code.  The helper
functions below only shorten the dictionaries.
"""

from __future__ import annotations

from collections.abc import Sequence
from functools import lru_cache

from ember_armor.ledger.model import LEDGER_VERSION, Rule, parse_ledger

TYPE_CHECKING = False
if TYPE_CHECKING:
    from typing import Any

    Pred = dict[str, Any]
else:
    Pred = dict

SOURCE = "EmberArmor built-in pack"


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
    "**/id_rsa", "**/id_dsa", "**/id_ecdsa", "**/id_ed25519", "**/.ssh",
    "**/.ssh/*",
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
#: ``-addstore``, ``/addstore`` and the MSYS-escaped ``//addstore``.
_ADD_ROOT = r"(?i)(?:^|\s)(?:-|//?)addstore\s(?:.*\s)?(?:root|authroot)(?:\s|$)"
#: ``Cert:\LocalMachine\Root`` with either separator, alone or after ``-Param:``.
_ROOT_STORES = [
    f"{prefix}cert:[\\/]*[\\/]{store}{tail}"
    for store in ("root", "authroot")
    for prefix in ("", "*:")
    for tail in ("", "[\\/]")
]
_FIREWALL_UNITS = ["firewalld*", "ufw*", "nftables*", "iptables*"]
_SECURITY_UNITS = ["clamav*", "falcon-sensor*", "apparmor*", "auditd*", "mdatp*",
                   "sentinelone*", "crowdstrike*"]  # fmt: skip
_STOP_UNIT = ["stop", "disable", "mask"]
#: Defender's services by name or display name, also from the stage that pipes in.
_DEFENDER = r"(?i)\b(?:windefend|mpssvc|wdnissvc|sense|wscsvc)\b|defender"
#: Registry values that switch Defender, the firewall or UAC off.
_DEFENCE_VALUES = (
    r"(?i)windows defender|disableantispyware|disablerealtimemonitoring|"
    r"disableantivirus|firewallpolicy|enablefirewall|\benablelua\b"
)
_MP_SWITCHES = ["-DisableRealtimeMonitoring", "-DisableBehaviorMonitoring",
                "-DisableIOAVProtection", "-DisableScriptScanning",
                "-DisableBlockAtFirstSeen", "-DisableIntrusionPreventionSystem",
                "-DisableArchiveScanning", "-DisableEmailScanning",
                "-DisableRemovableDriveScanning"]  # fmt: skip
_MP_EXCLUSIONS = ["-ExclusionPath", "-ExclusionProcess", "-ExclusionExtension",
                  "-ExclusionIpAddress"]  # fmt: skip
_MP_LEVELS = ["-MAPSReporting", "-SubmitSamplesConsent", "-PUAProtection",
              "-EnableControlledFolderAccess", "-EnableNetworkProtection"]  # fmt: skip
_MP_OFF = ["disabled", "0", "neversend", "2", "*:disabled", "*:0", "*:neversend"]
_BCDEDIT_VERBS = ["set", "delete", "deletevalue", "create", "copy", "import",
                  "default", "displayorder", "bootsequence", "timeout", "debug",
                  "bootdebug"]  # fmt: skip
_BCDEDIT_CHANGES = [f"{dash}{verb}" for verb in _BCDEDIT_VERBS for dash in "/-"]
_MKFS = ["mkfs", "mke2fs", "mkswap", "mkfs.ext2", "mkfs.ext3", "mkfs.ext4",
         "mkfs.xfs", "mkfs.btrfs", "mkfs.vfat", "mkfs.fat", "mkfs.ntfs",
         "mkfs.exfat", "mkfs.f2fs"]  # fmt: skip
#: The whole working tree; ``[*]`` is a literal star (``git checkout -- *``).
_WORKTREE = [".", "./", ":/", "[*]"]
_DRY_RUN = ["-n", "--dry-run"]
_VERCEL_GROUPS = ["project", "projects", "env", "domains", "alias", "dns", "certs"]
#: Files that run, or grant access, at every login.
_LOGIN_FILES = [
    "**/.ssh/authorized_keys", "**/.ssh/authorized_keys2", "~/.bashrc",
    "~/.bash_profile", "~/.bash_login", "~/.profile", "~/.zshrc", "~/.zprofile",
    "~/.zshenv", "~/.zlogin", "~/.config/fish/config.fish",
    "~/**/PowerShell/*profile.ps1", "~/**/WindowsPowerShell/*profile.ps1",
    "~/.config/powershell/*profile.ps1", "**/[$]PROFILE", "/etc/profile",
    "/etc/bash.bashrc",
]  # fmt: skip
_HOMES = ["~", "/home/*", "/root", "/Users/*", "?:/Users/*"]
#: A wildcard in a home directory itself or in one of its top-level folders.
_HOME_WILDCARDS = [f"{home}{folder}/*[*?]*" for home in _HOMES for folder in ("", "/*")]
#: The gate's own files: the Ember home and any project ``.ember`` directory.
_EMBER_FILES = ["~/.ember", "$EMBER_HOME", "**/.ember"]
_GATE_VARIABLES = [
    "EMBER_GATE_MODE",
    "EMBER_LEDGER",
    "EMBER_HOME",
    "EMBER_GATE_BUILTIN",
    "EMBER_GATE_REMIND_INTERVAL",
]
_GATE_EDITS = ["add", "confirm", "remove"]
_GATE_MODULE = (
    r"(?:^|\s)-m\s+ember_armor\.ledger\.cli\s+"
    r"(?:rules\s+(?:add|confirm|remove)|install)(?:\s|$)"
)
_HOST_SETTINGS = ["**/.claude/settings.json", "**/.claude/settings.local.json"]
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
        _rule(
            "delete.home-wildcard",
            "ask",
            "Ask before deleting with a wildcard directly in a home directory or "
            "in one of its top-level folders.",
            {
                "type": "path",
                "op": "delete",
                "glob": _HOME_WILDCARDS,
                "not_within": [*DISPOSABLE, *disposable],
            },
        ),
        _rule(
            "delete.mirror",
            "ask",
            "Ask before a sync that deletes what the source does not have "
            "(rsync --delete, robocopy /MIR).",
            _any(
                _command(
                    "rsync",
                    flags_any=[
                        "--delete",
                        "--delete-before",
                        "--delete-during",
                        "--delete-after",
                        "--delete-excluded",
                        "--del",
                        "--remove-source-files",
                    ],
                    flags_none=[*_DRY_RUN, *_HELP],
                ),  # fmt: skip
                _command("robocopy", flags_any=["/MIR", "/PURGE"], flags_none=["/L"]),
            ),
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
            "git.remote-delete",
            "ask",
            "Ask before deleting branches or tags on a remote.",
            _any(
                _git(
                    "push",
                    flags_any=["--delete", "-d", "--mirror", "--prune"],
                    flags_none=[*_DRY_RUN, *_HELP],
                ),
                _git("push", args_any_glob=[":?*"], flags_none=[*_DRY_RUN, *_HELP]),
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
                _git("submodule", "deinit", flags_any=["-f", "--force"]),
            ),
        ),
        _rule(
            "git.stash-drop",
            "ask",
            "Ask before dropping stashed work (git stash drop, git stash clear).",
            _any(_git("stash", "drop"), _git("stash", "clear")),
        ),
        _rule(
            "git.history-prune",
            "ask",
            "Ask before making commits unrecoverable: expiring the reflog, "
            "pruning now, or deleting a ref directly.",
            _any(
                _git("reflog", "expire"),
                _git("reflog", "delete"),
                _git("gc", args_any_glob=["--prune=now", "--prune=all"]),
                _git("update-ref", flags_any=["-d", "--delete"]),
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
                *(
                    _command(["vercel", "vc"], group, verb, flags_none=_HELP)
                    for group in _VERCEL_GROUPS
                    for verb in ("rm", "remove")
                ),
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
                _command(_TERRAFORM, "state", "rm", flags_none=_TERRAFORM_HELP),
                _command(_TERRAFORM, "workspace", "delete", flags_none=_TERRAFORM_HELP),
                _command("terragrunt", "run-all", "destroy"),
                _command("terragrunt", "destroy-all"),
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
            _any(
                _command(["docker", "podman"], "volume", "rm", flags_none=["--help"]),
                _command(
                    ["docker", "podman"], "volume", "prune", flags_none=["--help"]
                ),
                _command(
                    ["docker", "podman"],
                    "compose",
                    "down",
                    flags_any=["-v", "--volumes"],
                ),
                _command("docker-compose", "down", flags_any=["-v", "--volumes"]),
            ),
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
                _command(
                    "aws", "s3", "sync", flags_any=["--delete"], flags_none=["--dryrun"]
                ),
            ),
        ),
        _rule(
            "cloud.resource-delete",
            "ask",
            "Ask before deleting cloud resources or infrastructure (helm, gcloud, "
            "az, aws, gsutil, pulumi, cdk, fly, wrangler, heroku, supabase).",
            _any(
                _command("helm", "uninstall", flags_none=[*_HELP, "--dry-run"]),
                _command("helm", "delete", flags_none=[*_HELP, "--dry-run"]),
                _command("gcloud", args_any_glob=["delete"], flags_none=_HELP),
                _command("az", args_any_glob=["delete", "purge"], flags_none=_HELP),
                _command(
                    "aws",
                    args_any_glob=["delete-*", "terminate-instances"],
                    args_none_glob=["help"],
                    flags_none=["--dry-run"],
                ),
                _command("gsutil", "rm", flags_any=["-r", "-R", "-a"]),
                _command("gsutil", "rb"),
                _command("pulumi", "destroy", flags_none=_HELP),
                _command("pulumi", "stack", "rm", flags_none=_HELP),
                _command(["cdk", "cdktf"], "destroy", flags_none=_HELP),
                _command(["fly", "flyctl"], "apps", "destroy"),
                _command("wrangler", "delete", flags_none=_HELP),
                _command("heroku", "apps:destroy"),
                _command("supabase", "db", "reset"),
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
                    ["Import-Certificate", "Import-PfxCertificate"],
                    args_any_glob=_ROOT_STORES,
                    args_none_glob=_WHAT_IF,
                ),
                _command("security", "add-trusted-cert"),
                _command(
                    ["update-ca-certificates", "update-ca-trust"], flags_none=_HELP
                ),
                _command("trust", "anchor"),
                _command("mkcert", flags_any=["-install", "--install"]),
                _command("dotnet", "dev-certs", "https", flags_any=["--trust", "-t"]),
                _command("caddy", "trust"),
                _command("step", "certificate", "install"),
                _command(
                    "keytool",
                    flags_any=["-importcert", "-import"],
                    args_regex=r"(?i)cacerts",
                ),
            ),
        ),
        _rule(
            "system.firewall-off",
            "ask",
            "Ask before turning off a firewall.",
            _any(
                # netsh ignores letter case, whichever shell starts it.
                _command(
                    "netsh",
                    "advfirewall",
                    "set",
                    args_any_glob=["off", "allowinbound*"],
                ),
                _command("netsh", "advfirewall", "reset"),
                _command(
                    "netsh",
                    "firewall",
                    "set",
                    args_any_glob=["disable", "mode=disable"],
                ),
                _command(
                    "Set-NetFirewallProfile",
                    flags_any=["-Enabled"],
                    args_any_glob=_FALSE,
                    args_none_glob=_WHAT_IF,
                ),
                _command(
                    "Set-NetFirewallProfile",
                    flags_any=["-DefaultInboundAction"],
                    args_any_glob=["allow", "*:allow"],
                    args_none_glob=_WHAT_IF,
                ),
                _command("ufw", "disable"),
                _command("ufw", "reset"),
                _command("ufw", "default", "allow"),
                *(
                    _command("systemctl", verb, args_any_glob=_FIREWALL_UNITS)
                    for verb in _STOP_UNIT
                ),
                _command(
                    ["iptables", "ip6tables"],
                    flags_any=["-F", "--flush", "-X", "--delete-chain"],
                ),
                _command(
                    ["iptables", "ip6tables"],
                    flags_any=["-P", "--policy"],
                    args_any_glob=["ACCEPT"],
                ),
                _command("nft", "flush", "ruleset"),
                _command("pfctl", flags_any=["-d"]),
                _command(
                    "socketfilterfw",
                    flags_any=["--setglobalstate"],
                    args_any_glob=["off"],
                ),
            ),
        ),
        _rule(
            "system.antivirus-off",
            "ask",
            "Ask before turning off antivirus protection or another security "
            "control, or adding exclusions.",
            _any(
                _command(
                    "Set-MpPreference",
                    args_any_glob=_TRUE,
                    args_none_glob=_WHAT_IF,
                    flags_any=_MP_SWITCHES,
                ),
                _command(
                    "Set-MpPreference",
                    args_any_glob=_MP_OFF,
                    args_none_glob=_WHAT_IF,
                    flags_any=_MP_LEVELS,
                ),
                _command(
                    ["Add-MpPreference", "Set-MpPreference"],
                    args_none_glob=_WHAT_IF,
                    flags_any=_MP_EXCLUSIONS,
                ),
                _command(
                    ["Stop-Service", "Set-Service"],
                    args_regex=_DEFENDER,
                    args_none_glob=_WHAT_IF,
                ),
                *(
                    _command("sc", verb, args_regex=_DEFENDER)
                    for verb in ("stop", "config", "delete")
                ),
                _command("net", "stop", args_regex=_DEFENDER),
                *(
                    _command("systemctl", verb, args_any_glob=_SECURITY_UNITS)
                    for verb in _STOP_UNIT
                ),
                _command("setenforce", args_any_glob=["0", "[Pp]ermissive"]),
                _command("aa-teardown"),
                _command("spctl", flags_any=["--master-disable", "--global-disable"]),
                _command("csrutil", "disable"),
            ),
        ),
        _rule(
            "system.registry-defences",
            "ask",
            "Ask before registry changes that switch Defender, the firewall or "
            "UAC off.",
            _any(
                _command("reg", "add", args_regex=_DEFENCE_VALUES),
                _command(
                    ["Set-ItemProperty", "New-ItemProperty", "New-Item"],
                    args_regex=_DEFENCE_VALUES,
                    args_any_glob=[*_MACHINE_KEYS, *(f"*:{k}" for k in _MACHINE_KEYS)],
                    args_none_glob=_WHAT_IF,
                ),
            ),
        ),
        _rule(
            "system.registry-delete",
            "ask",
            "Ask before deleting machine-wide registry keys.",
            _any(
                _command("reg", "delete", args_any_glob=_MACHINE_KEYS),
                _command(
                    [
                        "Remove-Item",
                        "Remove-ItemProperty",
                        "Clear-Item",
                        "Clear-ItemProperty",
                    ],
                    args_any_glob=_MACHINE_KEYS,
                    args_none_glob=_WHAT_IF,
                ),  # fmt: skip
            ),
        ),
        _rule(
            "system.disk",
            "ask",
            "Ask before formatting, wiping, repartitioning or changing boot "
            "configuration.",
            _any(
                _command("format", args_any_glob=["?:", "?:\\", "?:/"]),
                _command(
                    [
                        "Format-Volume",
                        "Clear-Disk",
                        "Remove-Partition",
                        "Initialize-Disk",
                    ],
                    args_none_glob=_WHAT_IF,
                ),  # fmt: skip
                _command("diskpart", flags_none=["/?"]),
                _command("bcdedit", flags_any=_BCDEDIT_CHANGES),
                _command(_MKFS, flags_none=[*_HELP, "-V", "--version"]),
                _command("wipefs", flags_any=["-a", "--all"]),
                _command("sgdisk", flags_any=["-Z", "--zap-all", "-o", "--clear"]),
                _command("blkdiscard", flags_none=_HELP),
                _command(
                    "dd",
                    args_any_glob=["of=/dev/*"],
                    args_none_glob=["of=/dev/null", "of=/dev/stdout", "of=/dev/stderr"],
                ),
                _command("shred", args_any_glob=["/dev/*"]),
                *(
                    _command("diskutil", verb)
                    for verb in ("eraseDisk", "eraseVolume", "zeroDisk", "secureErase")
                ),
                _command("zpool", "destroy"),
                _command("zfs", "destroy"),
                _command(["lvremove", "vgremove"], flags_none=_HELP),
            ),
        ),
        # -- secrets ---------------------------------------------------------
        _rule(
            "secrets.read",
            "ask",
            "Ask before reading, sending, archiving or staging secret files: "
            ".env files, private keys and credential files.",
            {
                "type": "path",
                "op": "read",
                "glob": SECRET_FILES,
                "not_glob": NOT_SECRET,
                "not_under": ["**/node_modules"],
            },
        ),
        _rule(
            "system.login-files",
            "ask",
            "Ask before changing SSH authorized keys or shell profile files: "
            "they grant access or run at every login.",
            _any(
                {"type": "path", "op": "write", "glob": _LOGIN_FILES},
                {"type": "path", "op": "delete", "glob": _LOGIN_FILES},
            ),
        ),
        # -- the gate itself -------------------------------------------------
        _rule(
            "gate.files",
            "ask",
            "Ask before changing the gate's own files: its configuration, its "
            "ledgers and its audit log.",
            _any(
                {"type": "path", "op": "write", "under": _EMBER_FILES},
                {"type": "path", "op": "delete", "under": _EMBER_FILES},
            ),
        ),
        _rule(
            "gate.rules",
            "ask",
            "Ask before adding, confirming or removing ledger rules, or "
            "installing the hook: that is the owner's decision.",
            _any(
                *(_command("ember-gate", "rules", edit) for edit in _GATE_EDITS),
                _command("ember-gate", "install"),
                _command(["python", "python3", "py"], args_regex=_GATE_MODULE),
            ),
        ),
        _rule(
            "gate.environment",
            "ask",
            "Ask before setting the variables that choose the gate's mode, "
            "ledger, home, built-in pack or reminder interval.",
            {"type": "assigns", "name": _GATE_VARIABLES},
        ),
        _rule(
            "gate.host-settings",
            "ask",
            "Ask before changing Claude Code settings files: they hold the hook "
            "that runs this gate.",
            _any(
                {"type": "path", "op": "write", "glob": _HOST_SETTINGS},
                {"type": "path", "op": "delete", "glob": _HOST_SETTINGS},
            ),
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
