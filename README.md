# Collision Guard for Claude Code (free)

Stops two Claude Code sessions from writing over each other.

Part of a larger setup: [How the whole memory setup fits together](https://tudlab.com/memory).

If you run several sessions at once, each one starts blind. One edits a
config file; another, on a different task, saves its own copy of the same
file a few minutes later, and the first change is gone. Nobody notices until
something breaks.

This plugin is one Python file and a few hooks:

- Every write (Edit, Write, a shell command that changes a file, an MCP tool
  that changes something) **claims** what it touches. Reads claim nothing, and
  quoted text in a command (a commit message, say) is ignored.
- Before a write, a **guard** checks the claims. If another live session holds
  the same thing, or changed the file since this session last read it, the
  write is **blocked once** with a plain reason. The agent coordinates, then
  its retry goes through. A block happens once per conflict, so a session is never stuck waiting.
- Every session sees a short table of what the other live sessions are
  changing right now.
- A claim lasts until its session closes, or until it sits unused for 45
  minutes.

Standard library only. All state is plain JSON in `~/.claude/orchestration/`.
Nothing is sent anywhere.

## Install

You need Claude Code with plugin support and Python 3.8 or later. On Windows
you also need Git for Windows, because Claude Code runs plugin hooks in Git Bash.

```
claude plugin marketplace add paultuddenham/claude-collision-guard
claude plugin install collision-guard@tudlab
```

Start a new session. Then check the guard actually fires:

```
python3 ~/.claude/plugins/cache/tudlab/collision-guard/1.0.0/scripts/claims.py selftest
```

(On Windows use `python`.) You should see three PASS lines. Or try it for
real: open two sessions in the same folder, have the first edit a file, then
ask the second to edit the same file. The second is stopped once and told why.

### Without the plugin system

Copy `scripts/claims.py` to `~/.claude/orchestration/claims.py` and add the
hooks to `~/.claude/settings.json` yourself. The five hook entries (the digest
command runs twice, at session start and on each prompt) are in
`hooks/hooks.json`; replace the `sh ... run-hook claims.py` part of each
command with `python3 ~/.claude/orchestration/claims.py` (keep the last word:
`digest`, `check`, `touch` or `end`).

## Check it is alive

```
python3 <path-to>/claims.py health
```

prints the last guard decisions. "The guard has never run" means the hooks
are not wired. A guard that fails silently looks exactly like a quiet one, so
run this now and then.

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

To drop this session's claims early:
`echo '{"session_id": "<id>"}' | python3 <path-to>/claims.py release`

## Turn it off

`claude plugin disable collision-guard@tudlab`, or set `"guard_mode": "off"`.

## Limits

- Tested on Windows 11 and Debian Linux. macOS uses the same launcher as
  Linux but has not been tested on a Mac.
- It only sees sessions on the same machine (state is local files).
- Hooks fail open: if Python is missing or anything errors, the call goes
  through. That is deliberate. Use `health` to confirm it is running.

## The full version

This is the free part of a larger plugin, Tudlab Code: Orchestrate. The paid
version adds a shared blackboard injected into every session (including
"turned off on purpose, leave it" notes), risky actions that announce
themselves, a task-card handshake, setup and announce skills, and a 23-page
guide on tuning out false alarms and testing a guard that fails silently.
US$19: https://gumroad.com/l/tudlab-code-orchestrate

If you install the full plugin, uninstall this one first
(`claude plugin uninstall collision-guard@tudlab`); the full plugin includes
the same guard.

## How this was made

Built with Claude Code, from hooks I run every day across several parallel
sessions. Claude wrote most of the code and tests; I designed the rules, ran
the tests, and fixed what broke in real use.

MIT licence. See `LICENSE`.
