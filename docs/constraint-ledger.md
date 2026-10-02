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
- `path`: matches a file path the call reads, writes or deletes. Every field must hold for the same path. Fields: `op` (`read`, `write`, `delete`, `any`), `under`, `not_under`, `glob`, `not_glob`. Paths come from file tools and from recognised shell commands and redirections. They are resolved against the call's working directory and normalised: separators, drive-letter case, MSYS form (`/c/Users/x` equals `C:\Users\x`, as do `/mnt/c/Users/x`, `\\?\C:\Users\x` and `\\localhost\C$\Users\x`), `~`, and `.`/`..` segments. Comparison is case-insensitive on Windows. A shell operand that still holds a wildcard (`cat .env*`) matches a `glob` when some file name fits both, provided its last segment starts with literal text; it never matches an exclusion. A pattern that names a variable which is not set matches nothing.
- `arg`: compares one field of a structured tool input. Fields: `name` (dotted path), `op` (`<`, `<=`, `>`, `>=`, `==`, `!=`, `in`, `matches`), `value`. The value of an ordered comparison must be a number. A comparison on a missing or non-numeric argument is false, so a cap is best written as an obligation: `require amount <= 5000000`.
- `expr`: linear arithmetic over numeric arguments. Fields: `lhs` (map of argument name to coefficient), `op`, `rhs` (number). Sums are computed exactly.
- `text_regex`: escape hatch. Fields: `field`, `pattern`. Input is truncated before matching.
- `dynamic_shell`: true when the shell input cannot be fully resolved to literal commands (see below).
- `all`, `any`, `not`: combinators.
- `not_preceded_by`: true when no earlier call in the same session matches the inner predicate. Used for ordering rules such as "run the tests before pushing".
- `count_exceeds`: true when more than `max` earlier calls in the session (or in the last `within_seconds`) match the inner predicate.

The two history predicates read the audit log, at most once per call and only when the rest of the rule does not already decide. v0 knows which calls were proposed and not denied; it does not know whether they succeeded. A call without a session id has no history.

### Shell parsing

Bash and PowerShell command strings are parsed into a list of simple commands, each an argument vector, before any rule is evaluated. The parser handles: `;`, `&&`, `||`, `|`, newlines, quoting and escapes for each shell, leading environment assignments, arrays, brace expansion, extended globs, `sudo` and similar wrappers, package runners and container exec (`npx`, `pnpm dlx`, `yarn dlx`, `bunx`, `uvx`, `pipx run`, `npm exec`, `docker [compose] exec`), subshells and command substitution, redirections (recorded as writes), here-documents, and nested literal shells (`bash -c '...'`, `sh -c`, `powershell -Command "..."`, `pwsh -c`, `cmd /c`), which are parsed recursively. PowerShell aliases for removal, reading and listing (`rm`, `del`, `erase`, `rd`, `rmdir`, `ri`, `cat`, `type`, `gc`, `ls`, `dir`, `gci`, `%`) are mapped to their cmdlets. Tools named `Bash` and `PowerShell` (in any letter case) and `mcp__Windows-MCP__PowerShell` are parsed as shells; a call to one of them without a command string is a gate failure.

Paths follow the shell where that is certain:

- `cd`, `cd -`, `pushd` and `popd` are followed; a move inside a subshell, a substitution or a nested shell ends with it; a bare `cd` in Bash goes home.
- A variable resolves when the command string gives it exactly one value made of literal text and other resolvable variables, when it is a loop variable or array over literal words (each word is tried), or when it comes from `mktemp -d` or a literal `Join-Path`. Anything else assigned in the string (a command's output, `read`, two different values) is unknown and stays as written; it is not replaced by an environment variable of a similar name. Bash names are case-sensitive. In PowerShell only `$env:NAME`, `$HOME` and `$PWD` read the environment.
- A delete or read that takes its targets from a pipe uses what a literal lister before it names (`find ... -name X | xargs rm`, `Get-ChildItem dir -Filter X | Remove-Item`, `$_` inside `ForEach-Object`). Fed by anything else, a delete is taken to act on the working directory.
- `-WhatIf` means nothing is touched; `-WhatIf:$false` does not.

When the command to be executed is not a literal (for example `eval`, `Invoke-Expression`, a variable in command position, output of a decoder piped into a shell, a download piped into a shell), the call is marked `dynamic_shell` with the reason. Rules can then decide what to do with it. Command substitution used only as an argument (`git commit -m "$(...)"`, `node script.js "$(curl ...)"`) is not dynamic; a download counts only where it is the code: the script after `-c`, the first operand of a shell or interpreter, an argument of `eval`.

A parse failure never produces "no commands". It produces `dynamic_shell` with reason `parse_error`, the commands read before the failure are kept, and the built-in pack asks about it. The same holds for a command string over 200,000 characters, more than 2,000 commands, a brace expansion to more than 64 words, and a path over 1,024 characters.

## Decisions

The engine returns one of `none`, `warn`, `ask`, `deny`, with the rule ids that fired and their `text` and `source`.

Evaluation of a concrete call is direct: predicates are evaluated on the facts extracted from the call. No solver is involved and no model is called. The hot path uses only the Python standard library and must not import the web application.

### Modes

- `observe` (default): the gate never blocks and never asks. It records what it would have done.
- `enforce`: decisions take effect.

Mode comes from `EMBER_GATE_MODE`, else `~/.ember/config.json`, else `observe`.

`config.json` may hold `mode`, `builtin` (`false` switches the built-in pack off) and `disposable` (a list of directory patterns the built-in delete rules leave alone, added to the pack's own list). Any other key, or a value of the wrong type, is an error. A UTF-8 byte order mark is accepted. A configuration file that cannot be read or decoded (for example one saved as UTF-16) is treated as `enforce` with a gate failure: the owner may have asked for `enforce` in it.

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

Every evaluation appends one JSON line to `~/.ember/audit/YYYY-MM.jsonl`: time, session, tool, working directory, a redacted summary of the call, the decision, the rules that fired, the mode, and a hash that chains to the previous entry. The first entry chains to a fixed genesis value, and `~/.ember/audit/head` holds the hash of the last one. Appends are serialised with a file lock. After a line cut short by a crash, the next entry starts on a new line.

Secret-shaped values in arguments are replaced before logging: values of secret-named flags, keys and assignments, bearer tokens, known key prefixes, credentials in URLs, long generated-looking or hexadecimal strings, and everything below a secret-named key of a structured input. Commands are stored as parsed argument vectors. Every field is capped in length.

`ember-gate log verify` recomputes the chain. This detects accidental damage and naive editing, including entries removed from the start or the end and a deleted month file (so pruning old files shows up as well). It is not proof against someone with write access who recomputes the chain; nothing local can be.

## Built-in rules

A default pack of destructive-action rules ships with the package and is active unless disabled. Default effect is `ask`; a few are `deny`.

- Recursive deletion (`rm -r`, `Remove-Item -Recurse`, `rd /s`, `del /s`, `find -delete`, `find -exec rm` over a whole tree), except inside build, cache and temporary directories with unambiguous names (`node_modules`, `dist`, `build`, `.venv`, `__pycache__`, `.pytest_cache`, `target`, `.next`, `coverage`, tool caches, temporary directories; the full list is `DISPOSABLE` in `builtin.py`) and except regenerable files (`package-lock.json`, `*.log`, `*.tsbuildinfo` and the like). Names that can also hold source (`out`, `bin`, `vendor`) are not on the list; the user adds them with `disposable` in `config.json`. `deny` when the target is a filesystem root, a home directory, a users directory, or the `.git` directory of the working directory or of a directory above or outside it. A `.git` below a subdirectory (a fresh clone, a vendored copy) is asked about.
- Git history and working-tree destruction: forced push, `reset --hard`, `clean -f`, `checkout -- .`, `checkout -f`, `switch -f`, `restore .`, `branch -D` (also `-d -f`).
- SQL: `DROP`, `TRUNCATE`, and `DELETE FROM` with no `WHERE`, in what a database client receives (its arguments, its here-document, the stage piped into it), outside SQL string literals.
- Cloud and platform deletion: `gh repo delete`, `vercel remove`, `terraform destroy`, `kubectl delete`, `docker system prune -a`, `docker volume rm`, `aws s3 rb` and `rm --recursive`, `npm unpublish`.
- System trust and defences: adding a certificate to a trusted root store, turning off the firewall or antivirus, deleting machine registry keys, `format`, `diskpart`, `bcdedit`.
- Reading secret files through the shell or a file tool: `.env` (not `.env.example`), private keys, everything in `.ssh` except public keys, `config` and `known_hosts`, credential files. Public keys (`*.pub`, `*public*.pem`) and files under `node_modules` are not secret. A wildcard or name filter that can match a secret file counts (`cat .env*`, `rg -g .env`, Grep with `glob: ".env"`).
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
- No knowledge of whether an earlier call succeeded. A call the gate asked about counts as "preceded" whether or not the user approved it, and so does a look-alike invocation (`pytest --version`). History predicates look at earlier calls only: `pytest && git push` in one call is not "tests before push".
- Rules are written by hand. Drafting rules from a conversation with a model, for a human to confirm, is the next step and is why `confirmed` exists.
- Only what crosses the hook is seen. Work done inside a tool the host does not report is invisible.
- Nothing here has been measured on a public benchmark yet.
- A recursive search over a directory (`grep -r KEY .`, Grep on a directory with no glob) is not treated as reading the secret files in it; that would ask on most searches. Wildcards that are only an extension or only `*` (`cat *.pem`, `cat *`) are not matched against secret files either, and readers outside the table (`tar`, `jq`, an editor, `python -c`) contribute no paths.
- A regular expression in the user ledger or in a confirmed project rule runs unbounded. Python's matcher cannot be interrupted, so a pathological pattern there stalls the hook.
- The built-in SQL rule reads statements, not SQL: a destructive statement hidden in a comment trick, or run from a file (`psql -f drop.sql`), is not seen. Database tools other than the listed clients (`dropdb`, `rails db:drop`, migration runners) are not covered.
- A program with the same name as a guarded Windows tool (`scripts/format.cmd C:`) is asked about.
- Destroying files by other means than the recognised delete commands (`rsync --delete`, `robocopy /PURGE`, `git rm -rf`, truncating with `>`) is not a recursive delete to the gate.
- Redaction is by name and shape. A secret with an unremarkable name and shape, passed where nothing marks it (`echo hunter2 | docker login --password-stdin`), reaches the audit log.
- Lint does not model non-finite numbers (`1e999`), which the engine compares as infinity.
- HTTP requests are parsed before they are authenticated, as on the other routes; only the size of `tool_input` is capped.
