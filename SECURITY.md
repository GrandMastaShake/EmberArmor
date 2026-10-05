# Security Policy

EmberArmor is a prototype and is not ready for use as a security control. Do not rely on it to protect a system. Current status is in [README.md](README.md).

## Supported versions

Only the default branch (`master`) is supported. There are no tagged releases.

## Reporting a vulnerability

Use GitHub's private vulnerability reporting (Security tab, Report a vulnerability). Please do not put exploit details in a public issue.

## What the code does today

Checked against the code on 2026-10-02 (the two items on directory scopes and on exceptions on 2026-10-05):

- Every route except `GET /ready` requires `Authorization: Bearer <EMBER_API_KEY>`. A missing, malformed or wrong key gets 401. The comparison uses `hmac.compare_digest`.
- Start-up fails unless `EMBER_API_KEY` and `EMBER_TOKEN_SECRET` are set and at least 32 characters each. A `.env` file is read only when `EMBER_ENV=development`.
- Rate limiting is in memory, per peer address, 60 requests per 60 seconds by default. Start uvicorn with `--no-proxy-headers`; without it, uvicorn takes the peer address from `X-Forwarded-For` on connections from 127.0.0.1 and a local client can sidestep the limit.
- `/docs`, `/redoc` and `/openapi.json` are switched off.
- `.gitignore` excludes `.env`, `*.pem` and `*.key`. A scan of the git history found no provider API keys and no private keys.
- The constraint ledger gate (`ember-gate`, `ember_armor/ledger`) can only restrict: there is no `allow` effect, the Claude Code hook never prints `allow`, and a ledger shipped inside a repository cannot grant anything. A rule nobody has confirmed on this machine can do no more than warn.
- A rule scoped to a directory or a repository is judged for each command of a shell call, on the directory in effect when the command runs (`cd`, `pushd`, `git -C` and the like are followed). A directory the gate cannot read from the command string counts as in scope, so an unreadable `cd` does not lead out of a rule.
- Exceptions to rules exist only in the owner's `~/.ember/config.json`. A ledger cannot hold one, so a repository cannot ship one, and a `config.json` inside a repository is never read. Each exception must name a directory, a repository or a condition and give a reason. The two built-in deny rules and the rules that guard the gate's own files, rules, variables and host settings take no exception. A directory the gate cannot read gains none. Each use is recorded in the audit log. A malformed exception is a configuration failure: no exception is taken from that file.
- If the gate itself fails (unreadable ledger or configuration, a repository lookup that is refused, unreadable hook input, internal error), then in `enforce` mode the decision is `ask` with the error as the reason, never silent approval and never a hard block; in `observe` mode the call proceeds and the error is logged.
- Shell input the gate cannot read in full is marked and asked about, never dropped. More than 32 stacked wrappers, a command string over 200,000 characters, more than 2,000 commands or a brace expansion to more than 64 words are parse errors.
- The gate asks before an agent writes to or deletes its configuration, ledgers or audit log, confirms or removes rules through `ember-gate`, sets `EMBER_GATE_MODE`, `EMBER_LEDGER`, `EMBER_HOME` or `EMBER_GATE_BUILTIN` in a command, or edits the Claude Code settings files that hold the hook.
- Every gate evaluation goes to a hash-chained audit log under `~/.ember/audit/`, with secret-shaped values replaced before writing. `ember-gate log verify` detects edits, removed entries and a deleted month file. It is not proof against someone with write access who recomputes the chain.
- The HTTP ledger routes take no file path from a request and never look for a project ledger. Load and gate failures are answered in fixed words; the details go to the server log.

## What it does not do

- The detector is four regular expressions. It passes plain prompt-injection text as `SAFE`.
- The gate is built for good-faith agents that drift. An agent that deliberately obfuscates a command (a program named by a variable the gate cannot resolve, `eval` of an expansion, code run through `python -c`) can get past the built-in pack; those forms are marked, and a user rule on `dynamic_shell` can ask about them. The gate also never sees work done inside a tool the host does not report.
- The directory a command runs in is read from the command string and never checked against the machine. A `cd` that fails, a `cd` run in the background, `GIT_DIR` in the environment, or the directory option of a program the gate does not know (`tar -C`, `go -C`) can make a directory-scoped rule miss a command, or let an exception cover one that runs elsewhere.
- Redaction in the audit log is by name and shape. A secret with an unremarkable name and shape, passed where nothing marks it, reaches the log.
- The service has no audit log of its own: `AuditLogger` in `ember_armor/security/` exists, but no route calls it.
- JWT signing (`ember_armor/security/tokens.py`) and PBKDF2 key derivation (`ember_armor/security/crypto.py`) exist with tests, but no route uses them.
- There is no Dockerfile and no container configuration in this repository.
- `ember_proxy/` is experimental and should not be installed. Its installer adds a mitmproxy root certificate to the machine-wide Windows Trusted Root store, its launcher runs `git pull` on every start, and its scripts carry a hardcoded default API key (in `ember_proxy/addon.py`, `ember_proxy/start.bat` and `ember_proxy/install_windows.bat`). If you already ran the installer, follow the removal steps in [ember_proxy/README.md](ember_proxy/README.md).

Other known weaknesses are listed under Known issues and Known limits in the README, and in [docs/constraint-ledger.md](docs/constraint-ledger.md).
