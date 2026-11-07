"""Tests for scripts/claims.py. Standard library only.

Run from the repo root:  python -m unittest discover -s tests -v

Every test points ORCH_HOME at a fresh temporary folder, so nothing touches
your real ~/.claude/orchestration state.
"""
import contextlib
import importlib.util
import io
import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SCRIPT = os.path.join(ROOT, "scripts", "claims.py")
LAUNCHER = os.path.join(ROOT, "scripts", "run-hook")

_spec = importlib.util.spec_from_file_location("claims", SCRIPT)
claims = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(claims)


class GuardTestCase(unittest.TestCase):
    def setUp(self):
        self.home = tempfile.mkdtemp(prefix="cg-test-")
        self._old_home = os.environ.get("ORCH_HOME")
        os.environ["ORCH_HOME"] = self.home
        self._real_now = claims.now
        self.target = os.path.join(self.home, "shared.txt")
        with open(self.target, "w") as fh:
            fh.write("x\n")

    def tearDown(self):
        claims.now = self._real_now
        if self._old_home is None:
            os.environ.pop("ORCH_HOME", None)
        else:
            os.environ["ORCH_HOME"] = self._old_home
        shutil.rmtree(self.home, ignore_errors=True)

    def config(self, **overrides):
        if overrides:
            with open(os.path.join(self.home, "config.json"), "w") as fh:
                json.dump(overrides, fh)
        return claims.load_config()

    def payload(self, session, tool="Edit", **tool_input):
        if not tool_input:
            tool_input = {"file_path": self.target}
        return {"session_id": session, "tool_name": tool, "tool_input": tool_input, "cwd": self.home}

    def run_mode(self, fn, payload, cfg=None):
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            fn(payload, cfg or claims.load_config())
        return buf.getvalue()

    def assert_denied(self, out, phrase):
        self.assertTrue(out.strip(), "expected a deny, got nothing")
        decision = json.loads(out)["hookSpecificOutput"]
        self.assertEqual(decision["permissionDecision"], "deny")
        self.assertIn(phrase, decision["permissionDecisionReason"])
        return decision["permissionDecisionReason"]


class CollisionTests(GuardTestCase):
    def test_second_session_is_blocked_once_then_allowed(self):
        self.run_mode(claims.cmd_touch, self.payload("sess-a"))
        first = self.run_mode(claims.cmd_check, self.payload("sess-b"))
        self.assert_denied(first, "Another live Claude Code session")
        second = self.run_mode(claims.cmd_check, self.payload("sess-b"))
        self.assertEqual(second.strip(), "", "the retry should go through")

    def test_same_session_is_never_blocked(self):
        self.run_mode(claims.cmd_touch, self.payload("sess-a"))
        self.assertEqual(self.run_mode(claims.cmd_check, self.payload("sess-a")).strip(), "")

    def test_different_files_do_not_collide(self):
        other = os.path.join(self.home, "other.txt")
        self.run_mode(claims.cmd_touch, self.payload("sess-a"))
        out = self.run_mode(claims.cmd_check, self.payload("sess-b", file_path=other))
        self.assertEqual(out.strip(), "")

    def test_release_drops_the_claim(self):
        self.run_mode(claims.cmd_touch, self.payload("sess-a"))
        self.run_mode(claims.cmd_release, {"session_id": "sess-a"})
        self.run_mode(claims.cmd_touch, self.payload("sess-b", tool="Read"))
        self.assertEqual(self.run_mode(claims.cmd_check, self.payload("sess-b")).strip(), "")

    def test_claim_expires_after_its_ttl(self):
        self.run_mode(claims.cmd_touch, self.payload("sess-a"))
        later = self._real_now() + 46 * 60
        claims.now = lambda: later
        out = self.run_mode(claims.cmd_check, self.payload("sess-b"))
        # The claim has expired, so this is no longer a live collision. The
        # write record remains, so a session that never read the file is still
        # told its copy may be stale.
        reason = self.assert_denied(out, "Possible stale copy")
        self.assertNotIn("Another live Claude Code session", reason)


class StaleCopyTests(GuardTestCase):
    def test_writer_gone_but_unread_change_is_flagged(self):
        self.run_mode(claims.cmd_touch, self.payload("sess-a"))
        self.run_mode(claims.cmd_release, {"session_id": "sess-a"})
        self.assert_denied(self.run_mode(claims.cmd_check, self.payload("sess-b")), "Possible stale copy")

    def test_rereading_the_file_clears_the_stale_warning(self):
        self.run_mode(claims.cmd_touch, self.payload("sess-a"))
        self.run_mode(claims.cmd_release, {"session_id": "sess-a"})
        self.run_mode(claims.cmd_touch, self.payload("sess-b", tool="Read"))
        self.assertEqual(self.run_mode(claims.cmd_check, self.payload("sess-b")).strip(), "")


class ShellParsingTests(GuardTestCase):
    def keys(self, command):
        return claims.resources_for("Bash", {"command": command}, self.home, self.config())

    def test_plain_reads_claim_nothing(self):
        for cmd in ("grep -n x " + self.target, "cat " + self.target, "git status", "git log --oneline -5"):
            self.assertEqual(self.keys(cmd), [], cmd)

    def test_redirect_claims_its_target(self):
        keys = self.keys("echo hi > notes.txt")
        self.assertTrue(any(k.startswith("file:") and k.endswith("notes.txt") for k in keys), keys)

    def test_quoted_text_is_not_a_redirect(self):
        self.assertEqual(self.keys('grep "a > notes.txt" ' + self.target), [])


class McpTests(GuardTestCase):
    def test_read_shaped_mcp_tool_claims_nothing(self):
        self.assertEqual(claims.resources_for("mcp__ha__get_state", {"entity_id": "light.hall"}, None, self.config()), [])

    def test_write_shaped_mcp_tool_claims_its_target(self):
        keys = claims.resources_for("mcp__ha__update_entity", {"entity_id": "light.hall"}, None, self.config())
        self.assertEqual(keys, ["mcp:ha:light.hall"])


class ModeTests(GuardTestCase):
    def test_warn_mode_never_blocks(self):
        cfg = self.config(guard_mode="warn")
        self.run_mode(claims.cmd_touch, self.payload("sess-a"), cfg)
        self.assertEqual(self.run_mode(claims.cmd_check, self.payload("sess-b"), cfg).strip(), "")

    def test_off_mode_never_blocks(self):
        cfg = self.config(guard_mode="off")
        self.run_mode(claims.cmd_touch, self.payload("sess-a"), cfg)
        self.assertEqual(self.run_mode(claims.cmd_check, self.payload("sess-b"), cfg).strip(), "")


class CommandLineTests(GuardTestCase):
    def cli(self, *args, stdin=""):
        env = dict(os.environ, ORCH_HOME=self.home)
        return subprocess.run([sys.executable, SCRIPT] + list(args), input=stdin, env=env,
                              capture_output=True, text=True, timeout=60)

    def test_selftest_passes(self):
        r = self.cli("selftest")
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        self.assertNotIn("FAIL", r.stdout)

    def test_garbage_input_fails_open(self):
        for mode in ("check", "touch", "digest", "end"):
            r = self.cli(mode, stdin="this is not json")
            self.assertEqual(r.returncode, 0, mode)
            self.assertEqual(r.stdout.strip(), "", mode)

    def test_health_runs(self):
        r = self.cli("health")
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn("Guard mode", r.stdout)

    def test_health_hides_inject_line_without_a_blackboard(self):
        self.config(blackboard_path=os.path.join(self.home, "no-blackboard.md"))
        r = self.cli("health")
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertNotIn("Last inject", r.stdout)

    @unittest.skipUnless(shutil.which("sh"), "needs sh (Git Bash on Windows)")
    def test_hook_launcher_end_to_end(self):
        """The same path Claude Code takes: sh run-hook claims.py <mode>, payload on stdin."""
        env = dict(os.environ, ORCH_HOME=self.home)

        def hook(mode, payload):
            return subprocess.run(["sh", LAUNCHER, "claims.py", mode], input=json.dumps(payload),
                                  env=env, capture_output=True, text=True, timeout=60)

        r = hook("touch", self.payload("sess-a"))
        self.assertEqual(r.returncode, 0, r.stderr)
        r = hook("check", self.payload("sess-b"))
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assert_denied(r.stdout, "Another live Claude Code session")


if __name__ == "__main__":
    unittest.main()
