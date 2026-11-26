# Collision Guard for Claude Code (free)

[![tests](https://github.com/paultuddenham/claude-collision-guard/actions/workflows/test.yml/badge.svg)](https://github.com/paultuddenham/claude-collision-guard/actions/workflows/test.yml)

Warns a Claude Code session before it writes over another session's work.

Part of a larger setup for running many sessions at once, where shared memory and collision protection work together: [How the whole memory setup fits together](https://tudlab.com/memory).

The real setup it runs in, drawn as one map with real counts: [a home run by AI agents](https://tudlab.com/answers/home-run-by-ai-agents-map).

If you run several sessions at once in the same project, each one starts blind. One edits a
config file; another, on a different task, saves its own copy of the same
file a few minutes later, and the first change is gone. Nobody notices until
something breaks.

This plugin is one Python file and a few hooks:

- Every write (Edit, Write, a shell command that changes a file, an MCP tool
  that changes something) **claims** what it touches. Reads claim nothing, and
  quoted text in a command (a commit message, say) is ignored.
- Before a write, a **guard** checks the claims. If another live session holds
  the same thing, or changed the file since this session last read it, the
  write is **blocked once** with a plain reason. The agent reads the reason,
  adjusts its edits or asks you, then its retry goes through. The block does not stay: it fires once per conflict,
  so a session is never stuck waiting. It is a prompt to coordinate, not a lock.
- Every session sees a short table of what the other live sessions are
  changing right now.
- A claim lasts until its session closes, or until it sits unused for 45
  minutes.

Standard library only. All state is plain JSON in `~/.claude/orchestration/`.
Nothing is sent anywhere.

## New in 1.2: guardrails that work across agents

Collision Guard only sees Claude Code sessions. If you run Claude Code next to
Codex CLI or Cursor in the same repo, they cannot see each other's work.
`scripts/guardrails.py` adds three things, shared by every agent on the machine:

- **File locks that are enforced.** An edit takes a short lock on the file
  (10 minutes, renewed on each edit, released when the session ends). A second
  agent that tries to edit the same file is blocked, and told who holds it and
  until when. Agents without hooks can take and release locks through an MCP
  server (`acquire_lock`, `release_lock`, `list_locks`).
- **No reading secrets.** `.env`, `*.pem`, `*.key`, SSH private keys,
  `~/.aws/credentials` and a few more are blocked, from the file tools and
  from shell commands that print a file (`cat .env`, `grep KEY .env`).
  Commands that only name one (`cp .env.example .env`, `echo .env >> .gitignore`)
  are fine, and so are `.env.example` and `*.pub`.
- **No destructive commands.** `git push --force`, `git reset --hard`,
  `git clean -f`, `git checkout .` / `-f`, `git restore .`, `rm -rf` of the
  root, a home folder, `.`, `..` or `*` (but `rm -rf build` and
  `rm -rf /tmp/build-1` are fine), and `curl ... | sh` including
  `bash -c "$(curl ...)"`. Commands are split into words first, so a commit
  message that mentions `git push --force` is not blocked, and `sudo -u x`,
  `env`, `timeout`, `xargs`, `if ... then` and `bash -c "..."` do not hide a command.

The rules are in `guardrails.yaml` (plain text, every rule has a reason the
agent reads). Put a `.guardrails.yaml` in a project to change them there;
agents may not edit that file, with file tools or the shell. Note that a
repo you clone can ship its own `.guardrails.yaml`, which then replaces the
rules for that repo: look at it, as you would at any repo's hooks.
If the rules file has an error, the guard lets every call through and says
"Guardrails is OFF" on each call until you fix it.

| Agent | How it is wired | Locks | Secrets | Commands |
|---|---|---|---|---|
| Claude Code | PreToolUse hook (this plugin) | enforced | enforced | enforced |
| Codex CLI | the same hook, in `~/.codex/hooks.json` | enforced (`apply_patch`) | enforced | enforced |
| Cursor | `beforeShellExecution` / `beforeReadFile` hooks | taken after each edit, not enforced before | enforced | enforced |
| Any MCP client | `guardrails.py mcp` (stdio) | if the agent calls it | `check_path` | `check_command` |

Setup for Codex, Cursor and MCP: [docs/other-agents.md](docs/other-agents.md).

Check it from a terminal:

```
python3 scripts/guardrails.py check-command "git push --force"   # BLOCKED: ...
python3 scripts/guardrails.py check-path .env                    # BLOCKED: ...
python3 scripts/guardrails.py locks                              # who holds what
python3 scripts/guardrails.py unlock path/to/file                # free one by hand
python3 scripts/guardrails.py health                             # last decisions
```

What it is not: a sandbox. A determined agent can write a script that reads
`.env`. It catches the common, accidental cases. If you mainly want broad
command and secret blocking, [CC Safety Net](https://github.com/kenryu42/claude-code-safety-net)
covers far more commands; it has no file locks, which is the gap this fills.
They can run side by side.

## Install

You need Claude Code with plugin support and Python 3.8 or later. On Windows
you also need Git for Windows, because Claude Code runs plugin hooks in Git Bash.

```
claude plugin marketplace add paultuddenham/claude-collision-guard
claude plugin install collision-guard@tudlab
```

Start a new session. Then check the guard actually fires (replace `<version>` with the folder name under `~/.claude/plugins/cache/tudlab/collision-guard/`):

```
python3 ~/.claude/plugins/cache/tudlab/collision-guard/<version>/scripts/claims.py selftest
```

(On Windows use `python`.) You should see only PASS lines. Or try it for
real: open two sessions in the same folder, have the first edit a file, then
ask the second to edit the same file. The second is stopped once and told why.

### Without the plugin system

Copy `scripts/claims.py` to `~/.claude/orchestration/claims.py` and add the
hooks to `~/.claude/settings.json` yourself. The five hook entries (the digest
command runs twice, at session start and on each prompt) are in
`hooks/hooks.json`; replace the `sh ... run-hook claims.py` part of each
command with `python3 ~/.claude/orchestration/claims.py` (on Windows use `python`; keep the last word:
`digest`, `check`, `touch` or `end`). For example, the guard entry under `PreToolUse` in `settings.json` looks like this:

```json
{ "type": "command",
  "command": "python3 ~/.claude/orchestration/claims.py check",
  "timeout": 10 }
```

Keep the `matcher` and `timeout` values from `hooks/hooks.json` for each event.

## Check it is alive

```
python3 ~/.claude/plugins/cache/tudlab/collision-guard/<version>/scripts/claims.py health
```

This prints the last guard decisions (if you copied the file by hand, use `~/.claude/orchestration/claims.py` instead). "The guard has never run" means the hooks
are not wired. A guard whose hooks are not wired stays silent while you work, which looks
the same as a quiet one, so run this now and then.

## Why "block once" and not "ask"

Claude Code hooks can return `ask`, which prompts you. In permission modes
that auto-approve, an `ask` can be resolved without the agent ever seeing the
reason, so the write lands anyway. `deny` always reaches the agent, with the
explanation attached. Denying only once means a crashed or finished session
can never trap anyone.

## Settings

Optional. Create `~/.claude/orchestration/config.json`:

```json
{ "guard_mode": "deny", "claim_ttl_minutes": 45,
  "area_tags": [ { "tag": "docs", "pattern": "(^|/)docs/" } ] }
```

`guard_mode` is `deny` (block once), `warn` (log only) or `off`. Area tags put
a broad label on every file that matches, so two sessions in the same area see
each other even when they touch different files.

### Weekly note

If the guard blocked at least one overwrite in the last 7 days, the next
session start shows one line, at most once every 7 days on this machine:
"Collision Guard stopped N overwrites between your sessions this week", with a
link to the paid version (and, until 31-Dec-2026, its launch price). It never
appears on a prompt or inside a block message the agent reads. The count is
kept as timestamps in `~/.claude/orchestration/offer.json` and never leaves
your machine. To turn it off, add `"offer_note": false` to `config.json`, or
set the environment variable `COLLISION_GUARD_NO_OFFER=1`.

To drop this session's claims early:
`echo '{"session_id": "<id>"}' | python3 ~/.claude/plugins/cache/tudlab/collision-guard/<version>/scripts/claims.py release`

Replace `<id>` with the id of the session you want to release. It is the file name (without `.jsonl`) of that session's transcript under `~/.claude/projects/<project>/`. If you run the command inside that session, send `{}` instead of the id part (`echo '{}' | ...`): the guard falls back to the `CLAUDE_CODE_SESSION_ID` environment variable.

## Run the tests

From a clone of this repo, with Python 3.8 or later and nothing to install:

```
python -m unittest discover -s tests -v
```

Each test uses its own temporary state folder, so it never touches your real
claims. The last test drives the hook launcher with `sh`, the way Claude Code
does, and is skipped if `sh` is not on your PATH.

## Turn it off

`claude plugin disable collision-guard@tudlab`, or set `"guard_mode": "off"`.
To keep Collision Guard but loosen the guardrails, put a `.guardrails.yaml`
with only the rules you want in the project (an empty `deny_commands: []`
turns command rules off there).

## Limits

- Used daily on Windows 11 and Debian Linux. The test suite runs on Linux,
  Windows and macOS for every push (GitHub Actions), but no one has run it
  day to day on a Mac yet.
- It only sees sessions on the same machine (state is local files).
- Guardrail locks cover file-tool edits (and Codex `apply_patch`), not files
  changed by a shell command such as `sed -i`.
- Hooks fail open: if Python is missing or anything errors, the call goes
  through. That is deliberate. Use `health` to confirm it is running.

## The full version

This is the free part of a larger plugin, Tudlab Code: Orchestrate. The paid
version adds a shared blackboard injected into every session (including
"turned off on purpose, leave it" notes), risky actions that announce
themselves, a task-card handshake, setup and announce skills, and a 23-page
guide on tuning out false alarms and testing a guard that fails silently.
US$19: https://gumroad.com/l/tudlab-code-orchestrate

This free plugin mentions it once a week at most, in one line at session
start, and only in a week when it actually stopped an overwrite (see
[Weekly note](#weekly-note) for what it says and how to turn it off).

If you install the full plugin, uninstall this one first
(`claude plugin uninstall collision-guard@tudlab`); the full plugin includes
the same guard.

## How this was made

Built with Claude Code, from hooks I run every day across several parallel
sessions. Claude wrote most of the code and tests; I designed the rules, ran
the tests, and fixed what broke in real use.

MIT licence. See `LICENSE`.
