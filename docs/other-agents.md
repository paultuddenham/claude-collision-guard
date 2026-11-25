# Guardrails for Codex CLI, Cursor and other MCP clients

All agents on one machine share the same lock store (`~/.agent-guardrails/`,
or `$GUARDRAILS_HOME`) and the same rules (`guardrails.yaml`), so a lock taken
by Claude Code stops Codex, and the other way round.

Replace `/path/to/claude-collision-guard` with where you cloned this repo.
On Windows use `python` instead of `python3`.

How far each one is tested: the Claude Code hook is tested inside real
Claude Code sessions. The Codex and Cursor adapters are tested against the
payloads in those tools' hook docs (see `tests/test_guardrails.py`), not yet
inside the tools themselves. If one misbehaves for you, please open an issue
with the hook payload.

## Codex CLI

Codex's `PreToolUse` hook uses the same input and deny output as Claude Code,
so the same command works. Add it to `~/.codex/hooks.json` (or a trusted
project's `.codex/hooks.json`), then review and trust it with `/hooks`:

```json
{
  "hooks": {
    "PreToolUse": [
      { "matcher": "Bash|apply_patch|Edit|Write",
        "hooks": [ { "type": "command", "command": "python3 /path/to/claude-collision-guard/scripts/guardrails.py hook --agent codex", "timeout": 10 } ] }
    ],
    "SessionEnd": [
      { "hooks": [ { "type": "command", "command": "python3 /path/to/claude-collision-guard/scripts/guardrails.py end --agent codex", "timeout": 10 } ] }
    ]
  }
}
```

Check the current file layout on the Codex hooks page before you rely on it;
the payload and deny output are what this adapter depends on.

The lock covers edits made with `apply_patch`. Codex locks are named
`codex:<session>`.

## Cursor

Add to `~/.cursor/hooks.json` (or `<project>/.cursor/hooks.json`):

```json
{
  "version": 1,
  "hooks": {
    "beforeShellExecution": [ { "command": "python3 /path/to/claude-collision-guard/scripts/guardrails.py cursor-hook" } ],
    "beforeReadFile":       [ { "command": "python3 /path/to/claude-collision-guard/scripts/guardrails.py cursor-hook" } ],
    "afterFileEdit":        [ { "command": "python3 /path/to/claude-collision-guard/scripts/guardrails.py cursor-hook" } ]
  }
}
```

Cursor has no hook that runs before an edit, so Cursor takes the lock after
its first edit to a file. That still stops Claude Code and Codex from editing
the file Cursor is working on, but it does not stop Cursor itself from
editing a file someone else locked. For that, also add the MCP server below
and tell Cursor in your rules to call `acquire_lock` before editing.

## Any MCP client (stdio)

```
claude mcp add guardrails -- python3 /path/to/claude-collision-guard/scripts/guardrails.py mcp
codex mcp add guardrails -- python3 /path/to/claude-collision-guard/scripts/guardrails.py mcp
```

Cursor: `~/.cursor/mcp.json`:

```json
{ "mcpServers": { "guardrails": { "command": "python3", "args": ["/path/to/claude-collision-guard/scripts/guardrails.py", "mcp"] } } }
```

Tools:

| Tool | Arguments | Returns |
|---|---|---|
| `acquire_lock` | `path`, `owner`, `ttl_minutes` (30, max 120), `note` | `ok`, or `ok: false` with the holder |
| `release_lock` | `path`, `owner` | `released` |
| `list_locks` | none | every live lock |
| `check_command` | `command`, `shell` (`bash`/`powershell`), `cwd` | `allowed`, `rule`, `reason` |
| `check_path` | `path`, `cwd` | `allowed`, `reason` |

An agent that only has the MCP server follows the rules if it calls them.
A line like this in `AGENTS.md` or your Cursor rules does the job:

> Before editing a file, call `acquire_lock` with your name as owner; if it
> fails, work on something else. Release it when done. Before running a shell
> command that deletes, resets or pushes, call `check_command`.
