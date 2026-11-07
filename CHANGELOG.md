# Changelog

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
