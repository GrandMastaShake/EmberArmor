# Security Policy

EmberArmor is a prototype and is not ready for use as a security control. Do not rely on it to protect a system. Current status is in [README.md](README.md).

## Supported versions

Only the default branch (`master`) is supported. There are no tagged releases.

## Reporting a vulnerability

Use GitHub's private vulnerability reporting (Security tab, Report a vulnerability). Please do not put exploit details in a public issue.

## What the code does today

Checked against the code on 2026-10-02 (the items on directory scopes, on exceptions and on relative paths on 2026-10-05):

- Every route except `GET /ready` requires `Authorization: Bearer <EMBER_API_KEY>`. A missing, malformed or wrong key gets 401. The comparison uses `hmac.compare_digest`.
- Start-up fails unless `EMBER_API_KEY` and `EMBER_TOKEN_SECRET` are set and at least 32 characters each. A `.env` file is read only when `EMBER_ENV=development`.
- Rate limiting is in memory, per peer address, 60 requests per 60 seconds by default. Start uvicorn with `--no-proxy-headers`; without it, uvicorn takes the peer address from `X-Forwarded-For` on connections from 127.0.0.1 and a local client can sidestep the limit.
- `/docs`, `/redoc` and `/openapi.json` are switched off.
- `.gitignore` excludes `.env`, `*.pem` and `*.key`. A scan of the git history found no provider API keys and no private keys.
- The constraint ledger gate (`ember-gate`, `ember_armor/ledger`) can only restrict: there is no `allow` effect, the Claude Code hook never prints `allow`, and a ledger shipped inside a repository cannot grant anything. A rule nobody has confirmed on this machine can do no more than warn.
- A rule scoped to a directory or a repository is judged for each command of a shell call, on the directory in effect when the command runs (`cd`, `pushd`, `git -C` and the like are followed). A directory the gate cannot read from the command string counts as in scope, so an unreadable `cd` does not lead out of a rule. Neither does a `cd` that may not have run (behind `||`, behind `&&` after a command that can fail, in a branch, in a loop, in a function that is called): the directory after it is unknown. A call that names no working directory is in an unknown directory as well.
- Exceptions to rules exist only in the owner's `~/.ember/config.json`. A ledger cannot hold one, so a repository cannot ship one, and a `config.json` inside a repository is never read. Each exception must name a directory, a repository or a condition and give a reason; a whole filesystem or drive is refused as a directory. The two built-in deny rules and the rules that guard the gate's own files, rules, variables and host settings take no exception. A directory the gate cannot read, or cannot be sure of, gains none. For a rule that looks at paths an exception reaches only the paths in its own directories: `rm -rf ~/Documents` run in a directory where recursive deletes are excepted is still asked about. Each use is recorded in the audit log. A malformed exception is a configuration failure: no exception is taken from that file.
- If the gate itself fails (unreadable ledger or configuration, a repository lookup that is refused or raises, unreadable hook input, internal error), then in `enforce` mode the decision is `ask` with the error as the reason, never silent approval and never a hard block; in `observe` mode the call proceeds and the error is logged.
- Shell input the gate cannot read in full is marked and asked about, never dropped. More than 32 stacked wrappers, a command string over 200,000 characters, more than 2,000 commands, a brace expansion to more than 64 words or a relative path to resolve against more than 9 possible directories are parse errors.
- A delete or a write with a relative path is judged in every directory it may happen in: after a `cd` that may not have run, both where the `cd` leads and where the shell was (`[ -d /tmp/x ] && cd /tmp/x; rm -rf src` is asked about). Paths inside a nested shell that is started in another directory (`env -C dir sh -c '...'`, `pwsh -WorkingDirectory dir`) are resolved there, so the rules on the gate's own files and on protected directories see them.
- The gate asks before an agent writes to or deletes its configuration, ledgers or audit log, confirms or removes rules through `ember-gate`, sets `EMBER_GATE_MODE`, `EMBER_LEDGER`, `EMBER_HOME` or `EMBER_GATE_BUILTIN` in a command, or edits the Claude Code settings files that hold the hook.
- Every gate evaluation goes to a hash-chained audit log under `~/.ember/audit/`, with secret-shaped values replaced before writing. `ember-gate log verify` detects edits, removed entries and a deleted month file. It is not proof against someone with write access who recomputes the chain.
- The HTTP ledger routes take no file path from a request and never look for a project ledger. Load and gate failures are answered in fixed words; the details go to the server log.

## What it does not do

- The detector is four regular expressions. It passes plain prompt-injection text as `SAFE`.
- The gate is built for good-faith agents that drift. An agent that deliberately obfuscates a command (a program named by a variable the gate cannot resolve, `eval` of an expansion, code run through `python -c`) can get past the built-in pack; those forms are marked, and a user rule on `dynamic_shell` can ask about them. The gate also never sees work done inside a tool the host does not report.
- The directory a command runs in is read from the command string and never checked against the machine. A `cd` that fails, a `cd` run in the background, `GIT_DIR` in the environment, a `cd` inside a script the shell sources or behind an alias, a command in the body of a function that is called somewhere else, or the directory option of a program the gate does not know (`tar -C`, `go -C`) can make a directory-scoped rule miss a command, or let an exception cover one that runs elsewhere.
- An exception on a rule that looks at a command alone is judged by where the command runs, not by what it is aimed at: with `builtin.delete.mirror` excepted under a directory, `rsync --delete` from there to anywhere is not asked about.
- Redaction in the audit log is by name and shape. A secret with an unremarkable name and shape, passed where nothing marks it, reaches the log.
- The service has no audit log of its own: `AuditLogger` in `ember_armor/security/` exists, but no route calls it.
- JWT signing (`ember_armor/security/tokens.py`) and PBKDF2 key derivation (`ember_armor/security/crypto.py`) exist with tests, but no route uses them.
- There is no Dockerfile and no container configuration in this repository.
- `ember_proxy/` is experimental and should not be installed. Its installer adds a mitmproxy root certificate to the machine-wide Windows Trusted Root store, its launcher runs `git pull` on every start, and its scripts carry a hardcoded default API key (in `ember_proxy/addon.py`, `ember_proxy/start.bat` and `ember_proxy/install_windows.bat`). If you already ran the installer, follow the removal steps in [ember_proxy/README.md](ember_proxy/README.md).

Other known weaknesses are listed under Known issues and Known limits in the README, and in [docs/constraint-ledger.md](docs/constraint-ledger.md).
