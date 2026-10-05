# Constraint ledger

Status: design for v0. This document is the specification the first implementation is built against.

## What it is

A ledger of rules an AI agent was given, kept outside the model's context as structured data, and a gate that checks every proposed tool call against that ledger before the call runs.

It exists because of one failure pattern: an agent is told "never do X here", works for a while, and later does X anyway. Nothing attacked it. The instruction was lost to a long session, a context compaction, a handoff to another agent, or plain pressure to finish the task. The ledger does not rely on the model remembering.

## What it is not

- Not a prompt-injection detector and not a sandbox. It reads the tool call the agent proposes; an agent that deliberately obfuscates a command can get past it. It is built for good-faith agents that drift.
- Not a natural-language policy engine. Rules are structured. A sentence can be attached to a rule so the agent and the human can read why it exists, but the sentence is never what gets evaluated.
- Not a replacement for the host's own permission system. The gate can only restrict. It never grants permission.

## Rules

A ledger is a JSON file: `{"version": 1, "rules": [ ... ]}`. Each rule:

| Field | Meaning |
|---|---|
| `id` | Short stable identifier, unique in the ledger. |
| `text` | The constraint as a person would say it. Shown to the agent and the user when the rule fires. |
| `source` | Where the rule came from (who, when, which conversation or document). |
| `effect` | `deny`, `ask` or `warn`. |
| `applies` | Scope: `tools` (names or globs), `cwd_under` (directories). Missing means everywhere. |
| `when` | A predicate (below). The rule fires when it is true for the call. |
| `require` | Alternative to `when` for obligations: the rule fires when the predicate is false. Exactly one of `when` and `require` is present. |
| `confirmed` | `true` once a human has approved the rule. An unconfirmed rule can do no more than `warn`. In a project ledger this field is ignored (see Ledger files). |
| `expires` | Optional ISO date after which the rule is ignored. |

There is no `allow` effect. Exceptions are written into the predicate (`not`, `not_under`, `not_glob`, `flags_none`, `args_none_glob`). When several rules fire, the most restrictive effect wins: `deny` over `ask` over `warn`.

### Predicates

A closed set. Each is a JSON object with a `type`. An unknown type or field is an error, never a rule that silently matches nothing.

- `command`: matches one simple command in the parsed shell input. Every field must hold for the same command. Fields: `program` (name or list; compared without path and without `.exe`, case-insensitive on Windows and in Windows shells), `subcommand` (list of leading non-flag arguments, for example `["push"]` or `["repo", "delete"]`), `flags_any`, `flags_all`, `flags_none`, `args_any_glob`, `args_none_glob`, `args_regex`, `shell` (`bash`, `powershell` or `any`). Flag matching understands combined short flags in POSIX shells (`-rf` contains `-r` and `-f`), `--flag=value`, and PowerShell parameter names, which are case-insensitive and may be abbreviated to any unambiguous prefix. The `args_*` fields look at the arguments after the subcommand (`git -C . checkout main` has no `.` argument). `flags_none` and `args_none_glob` are the exceptions: a dry run or `--help` on the command itself. `args_regex` is searched in the command's joined arguments, in the here-document or here-string it is given, and in the arguments of the pipeline stage that feeds it; a command elsewhere in the same string does not count.
- `path`: matches a file path the call reads, writes or deletes. Every field must hold for the same path. Fields: `op` (`read`, `write`, `delete`, `any`), `recursive` (`true`: only deletions of whole trees), `under`, `not_under`, `not_within`, `glob`, `not_glob`. Paths come from file tools and from recognised shell commands and redirections. They are resolved against the call's working directory and normalised: separators, drive-letter case, MSYS form (`/c/Users/x` and `//c/Users/x` equal `C:\Users\x`, as do `/mnt/c/Users/x`, `\\?\C:\Users\x` and `\\localhost\C$\Users\x`), PowerShell's `FileSystem::` qualifier, `~`, and `.`/`..` segments. Comparison is case-insensitive on Windows. A shell operand that still holds a wildcard (`cat .env*`) matches a `glob` when it abbreviates a name the glob describes: its last segment starts with literal text, and that text falls on the glob's own literal text (`.env*`, `.env.*`, `id_rsa*`; `readme*` is not `*key*.pem`, although `readme-key.pem` would fit both). It never matches an exclusion. A pattern that names a variable which is not set matches nothing. `not_within` is an exception like `not_under`, judged from where the call is made: the directory that matches must not be the working directory or a directory above it, so `**/build` spares `./build/x` and `../build` but neither a project checked out below a directory named `build` nor that directory itself.
- `arg`: compares one field of a structured tool input. Fields: `name` (dotted path), `op` (`<`, `<=`, `>`, `>=`, `==`, `!=`, `in`, `matches`), `value`. The value of an ordered comparison must be a number. A comparison on a missing or non-numeric argument is false, so a cap is best written as an obligation: `require amount <= 5000000`.
- `expr`: linear arithmetic over numeric arguments. Fields: `lhs` (map of argument name to coefficient), `op`, `rhs` (number). Sums are computed exactly.
- `text_regex`: escape hatch. Fields: `field`, `pattern`. Input is truncated before matching.
- `dynamic_shell`: true when the shell input cannot be fully resolved to literal commands (see below).
- `assigns`: true when the shell input sets a variable whose name matches one of `name` (names or globs; case-insensitive on Windows): an assignment in Bash (alone, in front of a command, through `export`, `declare`, `env NAME=value` or `sudo NAME=value`, also `unset`), `$env:NAME = ...`, `[Environment]::SetEnvironmentVariable("NAME", ...)` and a cmdlet that changes an `Env:NAME` item in PowerShell, `setx NAME`, and `set NAME=value` in `cmd.exe`. The names are kept in the audit summary; the values are not.
- `all`, `any`, `not`: combinators.
- `not_preceded_by`: true when no earlier call in the same session matches the inner predicate. Used for ordering rules such as "run the tests before pushing".
- `count_exceeds`: true when more than `max` earlier calls in the session (or in the last `within_seconds`) match the inner predicate.

The two history predicates read the audit log, at most once per call and only when the rest of the rule does not already decide. v0 knows which calls were proposed and not denied; it does not know whether they succeeded. A call without a session id has no history.

### Shell parsing

Bash and PowerShell command strings are parsed into a list of simple commands, each an argument vector, before any rule is evaluated. The parser handles: `;`, `&&`, `||`, `|`, newlines, quoting and escapes for each shell, leading environment assignments, arrays, brace expansion, extended globs, `sudo` and similar wrappers (in both shells: `sudo`, `gsudo`, `doas`, `env`, `nohup`, `timeout`, `nice`, `xargs`, `wsl`), package runners and container exec (`npx`, `pnpm dlx`, `yarn dlx`, `bunx`, `uvx`, `uv run`, `pipx run`, `npm exec`, `docker [compose] exec`), subshells and command substitution, redirections (recorded as writes), here-documents, and nested literal shells (`bash -c '...'`, `sh -c`, `powershell -Command "..."`, `pwsh -c`, `cmd /c`, `wsl`, `Start-Process` with a literal program and argument list), which are parsed recursively. In Bash the substitutions inside `[[ ]]`, `${name:-...}`, `$(( ))`, `(( ))` and an unquoted here-document are parsed, and so are the command of `trap`, `coproc`, the `time` keyword, `find -exec` (wrappers and nested shells included) and the quoted command of `for /f` in `cmd.exe`. In PowerShell whatever stands in `( )`, `{ }`, `@{ }` or `[ ]` is parsed, never skipped: casts (`[void](cmd)`), typed, multiple and chained assignments, hashtable values, method arguments, index expressions, expanding here-strings, a command after `param(...)` or `return`. En and em dashes are read as the parameter hyphen, a module-qualified cmdlet (`Microsoft.PowerShell.Management\Remove-Item`) as the cmdlet, and `"$($env:NAME)"` as the variable. PowerShell aliases for removal, reading, listing and starting (`rm`, `del`, `erase`, `rd`, `rmdir`, `ri`, `cat`, `type`, `gc`, `ls`, `dir`, `gci`, `%`, `start`, `saps`) are mapped to their cmdlets. Windows tools that read their own subcommands in any letter case (`reg`, `netsh`, `sc`, `net`, `certutil`, `bcdedit`, `robocopy` and a few more) are matched that way whichever shell starts them.

Tools whose input is a shell command are parsed as shells: `Bash` and `PowerShell` (in any letter case), `mcp__Windows-MCP__PowerShell`, and `mcp__terminal__run_in_terminal` (PowerShell on Windows, Bash elsewhere; its `cwd` field is where its command starts). `shell_tools` in `config.json` adds more (see Modes). A call to such a tool without its command string is a gate failure.

Paths follow the shell where that is certain:

- `cd`, `cd -`, `pushd` and `popd` are followed; a move inside a subshell, a substitution or a nested shell ends with it; a bare `cd` in Bash goes home.
- A variable resolves when the command string gives it exactly one value made of literal text and other resolvable variables, when it is a loop variable or array over literal words (each word is tried), or when it comes from `mktemp -d` or a literal `Join-Path`. Anything else assigned in the string (a command's output, `read`, two different values) is unknown and stays as written; it is not replaced by an environment variable of a similar name. Bash names are case-sensitive. In PowerShell only `$env:NAME`, `$HOME` and `$PWD` read the environment. A resolved variable is also filled in where it names the program (`PY=$VENV/bin/python; $PY -m ...`, `& $exe`; a variable left in the directory part does not hide the program) and, in PowerShell, as an argument of a native program (`git push $flag`), never as a parameter name of a cmdlet.
- A delete or read that takes its targets from a pipe uses what a literal lister before it names (`find ... -name X | xargs rm`, `Get-ChildItem dir -Filter X | Remove-Item`, `$_` inside `ForEach-Object`). Fed by anything else, a delete is taken to act on the working directory.
- `-WhatIf` means nothing is touched; `-WhatIf:$false` does not.

When the command to be executed is not a literal (for example `eval`, `Invoke-Expression`, a variable in command position, output of a decoder piped into a shell, a download piped into a shell), the call is marked `dynamic_shell` with the reason. Rules can then decide what to do with it. Command substitution used only as an argument (`git commit -m "$(...)"`, `node script.js "$(curl ...)"`) is not dynamic; a download counts only where it is the code: the script after `-c`, the first operand of a shell or interpreter, an argument of `eval`.

A parse failure never produces "no commands". It produces `dynamic_shell` with reason `parse_error`, the commands read before the failure are kept, and the built-in pack asks about it. The same holds for a command string over 200,000 characters, more than 2,000 commands, more than 32 stacked wrappers, a brace expansion to more than 64 words, and a path over 1,024 characters. A test generates about 9,000 Bash and 10,000 PowerShell statements that wrap a destructive command in every construct the parsers know, one inside another, and checks that the pack never answers `none` for any of them.

## Decisions

The engine returns one of `none`, `warn`, `ask`, `deny`, with the rule ids that fired and their `text` and `source`.

Evaluation of a concrete call is direct: predicates are evaluated on the facts extracted from the call. No solver is involved and no model is called. The hot path uses only the Python standard library and must not import the web application.

### Modes

- `observe` (default): the gate never blocks and never asks. It records what it would have done.
- `enforce`: decisions take effect.

Mode comes from `EMBER_GATE_MODE`, else `~/.ember/config.json`, else `observe`.

`config.json` may hold `mode`, `builtin` (`false` switches the built-in pack off), `disposable` (a list of directory patterns the built-in delete rules leave alone, added to the pack's own list) and `shell_tools` (a map from a tool name or glob to `{"shell": ..., "field": ..., "cwd": ...}`: `shell` is `bash`, `powershell`, `cmd` or `native` (PowerShell on Windows, Bash elsewhere); `field` is the input field holding the command, `command` when left out; `cwd`, optional, names the field with the directory the command starts in). Any other key, or a value of the wrong type, is an error. A UTF-8 byte order mark is accepted. A configuration file that cannot be read or decoded (for example one saved as UTF-16) is treated as `enforce` with a gate failure: the owner may have asked for `enforce` in it.

### Failure behaviour

If the gate itself fails (unreadable ledger or configuration, unreadable hook input, internal error), then in `enforce` mode the decision is `ask` with the error as the reason, and in `observe` mode the call proceeds and the error is logged. The gate never turns its own failure into silent approval in `enforce` mode, and never into a hard block that would make the host unusable.

Each ledger is loaded on its own. A ledger that cannot be loaded adds an `ask`; it never removes the rules of the others, so a `deny` from the built-in pack or the user ledger stands and `observe` mode still records it.

## Lint (the solver's job)

`ember-gate lint` checks the ledger itself, using Z3. It needs the optional `smt` extra; without it the command says so and exits non-zero rather than reporting a clean result.

For each scope it reports:

- **Dead rule**: the rule's condition can never be true.
- **Blanket rule**: the rule fires on every call in its scope.
- **Shadowed rule**: another rule with an equal or stronger effect fires whenever this one does.
- **Contradiction**: a set of `deny` rules that together deny every possible call in a scope, with the smallest such set (from the solver's unsat core). Example: "never transfer more than 5,000,000" and "transfers must be at least 10,000,000" on the same tool. Rules that are not confirmed yet are named as such.

Numeric arguments are solver variables, with the exact values the engine computes with. Command and path predicates become boolean atoms, with implications added where they are certain (a path under `a/b` is under `a`). A path below the working directory, the home directory or a variable is somewhere lint does not know; it is under `/` on POSIX and under no fixed directory on Windows.

## Audit log

Every evaluation appends one JSON line to `~/.ember/audit/YYYY-MM.jsonl`: time, session, tool, working directory, a redacted summary of the call, the decision, the rules that fired, the mode, and a hash that chains to the previous entry. The first entry chains to a fixed genesis value, and `~/.ember/audit/head` holds the hash of the last one. An empty marker file named `.last.<file>.<size>.<hash>` repeats what the last append left behind; its name is read from the directory listing, so the next append links to the hash without opening the file it has just written (Windows scans such a file on its next open). When the size no longer matches, the log is read. Appends are serialised with a file lock. After a line cut short by a crash, the next entry starts on a new line.

Secret-shaped values in arguments are replaced before logging: values of secret-named flags, keys and assignments, bearer tokens, known key prefixes, credentials in URLs, long generated-looking or hexadecimal strings, and everything below a secret-named key of a structured input. Commands are stored as parsed argument vectors. Every field is capped in length.

`ember-gate log verify` recomputes the chain. This detects accidental damage and naive editing, including entries removed from the start or the end and a deleted month file (so pruning old files shows up as well). It is not proof against someone with write access who recomputes the chain; nothing local can be.

## Built-in rules

A default pack of destructive-action rules ships with the package and is active unless disabled. Default effect is `ask`; a few are `deny`.

- Recursive deletion (`rm -r`, `Remove-Item -Recurse`, `rd /s`, `del /s`, `find -delete`, `find -exec rm` over a whole tree), except inside build, cache and temporary directories with unambiguous names (`node_modules`, `dist`, `build`, `.venv`, `__pycache__`, `.pytest_cache`, `target`, `.next`, `coverage`, tool caches, temporary directories; the full list is `DISPOSABLE` in `builtin.py`) and except regenerable files (`package-lock.json`, `*.log`, `*.tsbuildinfo` and the like). The exception is judged from the working directory (`not_within`): a disposable directory spares what lies in it only when it is not the working directory or a directory above it, so a project checked out below a directory named `build` or `tmp`, or in the system temporary directory, keeps every rule, and `./build`, `../dist` and `/tmp/x` seen from elsewhere are still spared. Names that can also hold source (`out`, `bin`, `vendor`) are not on the list; the user adds them with `disposable` in `config.json`. `deny` when the target is a filesystem root, a home directory, a users directory, or the `.git` directory of the working directory or of a directory above or outside it. A `.git` below a subdirectory (a fresh clone, a vendored copy) is asked about.
- A delete with a wildcard directly in a home directory or in one of its top-level folders (`rm ~/Documents/*`, `del C:\Users\x\*`), and a sync that deletes what the source does not have (`rsync --delete`, `robocopy /MIR` or `/PURGE`).
- Git history and working-tree destruction: forced push, `reset --hard`, `clean -f`, `checkout -- .` (also `*`), `checkout -f`, `switch -f`, `restore .`, `submodule deinit -f`, `branch -D` (also `-d -f`), `stash drop` and `stash clear`, `reflog expire`, `gc --prune=now`, `update-ref -d`, and deleting on a remote (`push --delete`, `push :branch`, `push --mirror`).
- SQL: `DROP`, `TRUNCATE`, and `DELETE FROM` with no `WHERE`, in what a database client receives (its arguments, its here-document, the stage piped into it), outside SQL string literals.
- Cloud and platform deletion: `gh repo delete`, `vercel remove` (also `project`, `env`, `domains`, `alias` ... `rm`), `terraform destroy`, `state rm` and `workspace delete`, `terragrunt run-all destroy`, `kubectl delete`, `docker system prune -a`, `docker volume rm` and `prune`, `docker compose down -v`, `aws s3 rb`, `rm --recursive` and `sync --delete`, `npm unpublish`, and the commonest deletions of other clients (`helm uninstall`, `gcloud ... delete`, `az ... delete`, `aws ... delete-*`, `gsutil rm -r`, `pulumi destroy`, `cdk destroy`, `fly apps destroy`, `wrangler delete`, `heroku apps:destroy`, `supabase db reset`).
- System trust and defences: adding a certificate to a trusted root store (`certutil -addstore`, `Import-Certificate` and `Import-PfxCertificate` into `Cert:\...\Root` with either separator, `security add-trusted-cert`, `update-ca-certificates`, `mkcert -install`, `dotnet dev-certs https --trust`, `keytool ... -cacerts`), turning off a firewall (`netsh`, `Set-NetFirewallProfile -Enabled false` or `-DefaultInboundAction Allow`, `ufw disable`, `iptables -F`, `nft flush ruleset`, `pfctl -d`, stopping firewall units), turning off antivirus or another security control or adding exclusions (`Set-MpPreference`, `Add-MpPreference`, stopping Defender's services by name or display name, `setenforce 0`, stopping clamav and EDR units, `spctl --master-disable`, `csrutil disable`), registry writes that switch Defender, the firewall or UAC off, deleting machine registry keys, formatting, wiping and repartitioning (`format`, `diskpart`, `Format-Volume`, `Clear-Disk`, `Remove-Partition`, `Initialize-Disk`, `mkfs`, `wipefs`, `sgdisk`, `dd of=/dev/...`, `diskutil erase*`, `zpool destroy`) and `bcdedit`.
- Writing to, or deleting, SSH `authorized_keys` and shell profile files (`.bashrc`, `.zshrc`, `.profile`, the PowerShell profiles, `$PROFILE`), by file tool or shell.
- Reading secret files through the shell or a file tool, or handing them to a program that sends, packs or stages them (`curl -d @file`, `--data-binary`, `-F name=@file`, `-T`; `wget --post-file`; `scp`; `rsync`; `tar` creating an archive; `zip`; `7z a`; `git add`; `Compress-Archive`; `Invoke-WebRequest -InFile`), or moving them (`mv`, `move`, `Move-Item`: the source is both written and read, since its content arrives somewhere else): `.env` (not `.env.example`), private keys, the `.ssh` directory and everything in it except public keys, `config` and `known_hosts`, credential files. Public keys (`*.pub`, `*public*.pem`) and files under `node_modules` are not secret. A wildcard or name filter that abbreviates a secret name counts (`cat .env*`, `rg -g .env`, Grep with `glob: ".env"`); a negated Grep glob (`!**/.env`) does not.
- The gate itself: writes, deletes and redirections into the Ember home (`~/.ember`, `$EMBER_HOME`) or any project `.ember` directory; `ember-gate rules add|confirm|remove` and `ember-gate install`, also as `python -m ember_armor.ledger.cli ...`; setting `EMBER_GATE_MODE`, `EMBER_LEDGER`, `EMBER_HOME` or `EMBER_GATE_BUILTIN` in a command; writes to Claude Code settings files (`~/.claude/settings.json`, any `.claude/settings.json` or `settings.local.json`), by file tool or shell. Reads are not restricted.
- Download piped into a shell.
- Shell input the gate could not read in full (`parse_error`, an encoded command that does not decode).

A dry run or `--help` on the command itself is not asked about (`git push -n`, `kubectl delete --dry-run=client`, `aws s3 rm --dryrun`, `npm unpublish --dry-run`, `-WhatIf`); `--dry-run=none` and `-WhatIf:$false` are.

## Interfaces

- **Command line**: `ember-gate check`, `rules list|add|confirm|remove`, `lint`, `log tail|verify|stats`, `replay` (run recorded tool calls from Claude Code transcripts through the gate and print aggregate counts), `hook`, and `install claude-code --print` (prints the settings snippet; it does not edit settings). `rules confirm --project` records the approval in the Ember home, not in the repository.
- **Claude Code hook**: `ember-gate hook` reads the PreToolUse JSON on standard input. On `deny` or `ask` in `enforce` mode it prints `hookSpecificOutput` with `permissionDecision` and a reason that quotes the rule's `text` and `source` (capped in length; a rule from a project ledger is labelled as such). In every other case it prints nothing and exits 0, so the host's normal permission flow is untouched. It never prints `allow`.
- **HTTP**: `POST /v1/ledger/check`, `GET /v1/ledger/rules`, `POST /v1/ledger/lint`, behind the existing bearer authentication. These replace the `/v1/anchor` stub routes. The server reads the ledger named by `EMBER_LEDGER_PATH`, else the user ledger; it never looks for a project ledger, and no file path is taken from a request. Load and gate failures are answered in fixed words; the details go to the server log.

Ledger files: the user ledger at `~/.ember/ledger.json`, plus a project ledger at `.ember/ledger.json` found by walking up from the working directory (network and device paths are not searched). `EMBER_LEDGER` overrides both; the file it names must exist. Because rules can only restrict, a ledger shipped inside a repository cannot grant anything.

A project ledger travels with a repository, so it is not trusted as written:

- `confirmed` in the file is ignored. A project rule is confirmed when this machine recorded it, by rule id and content hash, in `~/.ember/project-confirmed.json` (`ember-gate rules confirm ID --project`). If the repository changes the rule, it is unconfirmed again.
- An unconfirmed project rule can only warn, and one that holds a regular expression is not evaluated at all (`rules list` says so): a pattern that takes minutes to match would stall every call made in that repository.

## Known limits of v0

- A determined agent can evade shell parsing. The `dynamic_shell` predicate catches the common forms, not all of them.
- A command whose program is a variable the gate cannot resolve (`$CMD args`, `& $obj.FullName`), a script handed to a shell with unknown parts (`bash -c "$SCRIPT"`), `eval` of an expansion and a decoder or download piped into a shell are marked (`variable_command`, `nested_dynamic`, `eval`, `pipe_to_shell`, `decoder_pipe`) but not asked about by the built-in pack; `eval "$(ssh-agent -s)"` and its kind are too common. In the owner's history of about 48,000 calls, 17 calls carry `variable_command` and 3 `nested_dynamic`. A user rule `{"type": "dynamic_shell", "reason": ["variable_command", "nested_dynamic"]}` asks about them.
- No knowledge of whether an earlier call succeeded. A call the gate asked about counts as "preceded" whether or not the user approved it, and so does a look-alike invocation (`pytest --version`). History predicates look at earlier calls only: `pytest && git push` in one call is not "tests before push".
- Rules are written by hand. Drafting rules from a conversation with a model, for a human to confirm, is the next step and is why `confirmed` exists.
- Only what crosses the hook is seen. Work done inside a tool the host does not report is invisible.
- Nothing here has been measured on a public benchmark yet.
- A recursive search over a directory (`grep -r KEY .`, Grep on a directory with no glob) is not treated as reading the secret files in it, and neither is an archive or sync of a directory that holds one (`tar czf x.tgz .`); that would ask on most searches and backups. Wildcards that are only an extension or only `*` (`cat *.pem`, `cat *`), or whose own text is not part of the secret name (`readme*`, `server*.pem`), are not matched against secret files either, and readers outside the table (`jq`, an editor, `python -c`, `git diff`, `git show`) contribute no paths.
- A regular expression in the user ledger or in a confirmed project rule runs unbounded. Python's matcher cannot be interrupted, so a pathological pattern there stalls the hook.
- The built-in SQL rule reads statements, not SQL: a destructive statement hidden in a comment trick, or run from a file (`psql -f drop.sql`), is not seen. Database tools other than the listed clients (`dropdb`, `rails db:drop`, migration runners) are not covered.
- A program with the same name as a guarded Windows tool (`scripts/format.cmd C:`) is asked about.
- Destroying files by other means than the recognised delete commands (`git rm -rf`, truncating with `>`, `python -c "..."`, `[IO.File]::WriteAllText`) is not a delete or write to the gate; the same holds for its own files and the host's settings files. `git worktree remove --force` is not asked about: the corpus holds it as routine cleanup. `git clean -d` with `-c clean.requireForce=false` is not read as forced. A relative registry path after `cd HKLM:\...` is read as a file path. `reg import` is not read.
- A disposable directory is judged against the working directory of the call, not against a directory the command `cd`s into: `cd /srv/build/other && rm -rf .git` from a project elsewhere is spared, as it was before.
- Redaction is by name and shape. A secret with an unremarkable name and shape, passed where nothing marks it (`echo hunter2 | docker login --password-stdin`), reaches the audit log.
- Lint does not model non-finite numbers (`1e999`), which the engine compares as infinity.
- HTTP requests are parsed before they are authenticated, as on the other routes; only the size of `tool_input` is capped.
