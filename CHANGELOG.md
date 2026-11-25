# Changelog

## 1.2.0 (25-Nov-2026)

- New `scripts/guardrails.py` (one file, standard library only) and
  `guardrails.yaml`, shared by every agent on the machine:
  enforced file locks (an edit takes a 10-minute lock, renewed on each edit,
  released at session end; a second agent is blocked and told who holds it),
  secret-read deny (`.env`, keys, SSH private keys, `~/.aws/credentials`) and
  destructive-command deny (`git push --force`, `git reset --hard`,
  `git clean -f`, `git checkout .`, wide `rm -rf`, `curl | sh`).
- Adapters: Claude Code and Codex CLI PreToolUse hook, Cursor hooks, and an
  MCP stdio server (`acquire_lock`, `release_lock`, `list_locks`,
  `check_command`, `check_path`). Setup in `docs/other-agents.md`.
- The plugin now runs the guardrails hook too. A project `.guardrails.yaml`
  replaces the rules there; agents may not edit it.
- Before release, an adversarial review ran ~40 ordinary commands and ~25 bypass
  attempts; its confirmed findings are now test cases (commands that merely name a
  secret are allowed, rm -rf only blocks wide targets, sudo/timeout/xargs and
  if/then wrappers, `bash -c "$(curl ...)"`, config typos announce themselves).
- 22 new tests: blocked and allowed cases for every rule, locks
  (conflict, renew, expiry, release), each hook adapter, the MCP session,
  fail-open, and the YAML reader against PyYAML when it is installed.

## 1.1.0 (07-Nov-2026)

- Test suite in `tests/` (standard library `unittest`, 19 tests): block once
  then allow the retry, same session never blocked, release, claim expiry,
  stale-copy warning and how a re-read clears it, shell redirect parsing
  (quoted text is not a redirect), MCP read vs write tools, warn and off modes,
  fail-open on bad input, and an end-to-end run through the `run-hook`
  launcher exactly as Claude Code calls it.
- GitHub Actions runs the self-test and the suite on Linux, Windows and macOS
  for every push, plus Python 3.8 on Linux.
- `health` no longer prints a "Last inject: never" line when no blackboard is
  in use. That line belongs to the full plugin and confused free users.
- README: how to run the tests; platform notes updated.

## 1.0.0 (10-Oct-2026)

- First release: write claims, pre-write guard (block once with a reason),
  stale-copy warning, digest of live claims at session start and on each
  prompt, `selftest`, `health`, `show`, `gc`, `release`.
