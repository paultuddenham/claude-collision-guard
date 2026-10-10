#!/usr/bin/env python3
"""Resource claims and a pre-write guard for parallel Claude Code sessions.

Part of the Tudlab Code orchestration plugin. This one file also works on its
own (it is the free taster): it needs nothing but the Python standard library.

Modes (first argument). Each reads the hook's JSON payload on stdin.

  touch    PostToolUse       record what this call wrote (and what it read)
  check    PreToolUse        block ONCE if a live peer holds the same thing,
                             or if someone changed a file since you read it
  end      SessionEnd        the session closed: drop its claims and read records
  release  by hand / skill   drop this session's claims now (read records stay)
  digest   SessionStart/UserPromptSubmit   inject the live claims table
  show     by hand           print the table, even when it is empty
  gc       by hand           prune expired entries
  health   by hand           print where state lives, when the guard last ran
                             and when the blackboard was last injected
  selftest by hand           prove the guard still fires, in a throwaway folder

Fail-open is absolute: any error ends in exit 0 with no output. A guard that
crashes must never stop a session from working.

State lives in ~/.claude/orchestration/ (override with ORCH_HOME). Settings are
read from config.json in that folder; every setting has a default below.
"""
import json
import os
import re
import sys
import tempfile
import time

PY_OK = sys.version_info >= (3, 8)
IS_WINDOWS = os.name == "nt"

# ---------------------------------------------------------------------------
# Paths and settings
# ---------------------------------------------------------------------------


def state_dir():
    """One fixed folder for all state, shared by hooks, skills and the CLI.

    A fixed path (not a per-install folder) means a script started by hand, by
    a skill or by a hook always reads the same files.
    """
    d = os.environ.get("ORCH_HOME") or os.path.join("~", ".claude", "orchestration")
    return os.path.expanduser(d)


DEFAULTS = {
    # How long a claim stays live after its last write. Sessions sit idle for a
    # while mid-task, so this is generous: a stale claim costs one warning, a
    # short one misses a real overlap.
    "claim_ttl_minutes": 45,
    # How long we remember who last wrote each file. This covers the "stale
    # copy" case, where the writer may have finished long ago.
    "recent_write_hours": 6,
    # After a session is warned about a resource, its retry goes through for
    # this long. The guard informs; it never deadlocks.
    "warn_cooldown_minutes": 30,
    # deny = block once then allow (recommended). warn = log only. off = no guard.
    "guard_mode": "deny",
    # Area tags: a broad label for a group of files or services. Two sessions on
    # different files in the same area still see each other. Keep them few and
    # narrow, or every session will look like it conflicts with every other.
    "area_tags": [
        {"tag": "claude-config", "pattern": r"(^|/)\.claude/(settings[^/]*\.json|hooks/)"},
    ],
    # Extra shell words that should count as writes (regex fragments).
    "extra_write_verbs": [],
    # MCP tools. A tool whose action word looks like a read claims nothing; one
    # that looks like a write claims "mcp:<server>:<target>". Anything else is
    # ignored unless listed in write_tools.
    "mcp_read_words": r"get|list|read|search|query|fetch|describe|show|view|find|lookup|status|check|count|inspect|export",
    "mcp_write_words": r"create|update|delete|remove|set|write|edit|put|post|patch|restart|reboot|deploy|publish|send|move|rename|insert|upsert|apply|trigger|call|run|exec|manage|install|uninstall|enable|disable|start|stop",
    "write_tools": [],
    "read_tools": [],
    "mcp_target_fields": ["entity_id", "id", "url_path", "path", "file_path", "name", "key", "slug", "page", "table", "repo"],
    # Card ids, used to label who is working what. Default form: ABC-123.
    "card_id_pattern": r"\b(?!(?:UTF|ISO|SHA|RFC|TLS|SSL|HTTP|MD|PEP|ECMA)-)[A-Z][A-Z0-9]{1,9}-\d{1,6}\b",
    "max_digest_rows": 12,
    # --- used by the other hooks in the plugin -----------------------------
    # The shared blackboard every session reads.
    "blackboard_path": "~/.claude/blackboard.md",
    # How much of the blackboard head to inject. Claude Code moves hook output
    # over ~10,000 characters to a file and shows only a preview, which would
    # hide the cautions, so stay well under that.
    "inject_budget_chars": 7000,
    "inject_clip_chars": 200,
    # Cross-session activity log: lines kept, lines injected, prompt length.
    "activity_keep_lines": 200,
    "activity_inject_lines": 8,
    "activity_prompt_chars": 140,
    # Risky actions on shared infrastructure. A match adds one line to the
    # blackboard's ACTIVE WORK section until the session stops.
    "risky_actions": [
        {"label": "machine reboot or shutdown", "pattern": r"\b(?:reboot|poweroff|halt)\b|\bshutdown\s+(?:-[rh]|/+[rs])\b|Restart-Computer|Stop-Computer"},
        {"label": "scheduled task change", "pattern": r"(?:Register|Unregister|Set|Enable|Disable)-ScheduledTask|schtasks(?:\.exe)?\s+/+(?:create|change|delete|end)\b|crontab\s+-[er]\b"},
        {"label": "service stop/start", "pattern": r"systemctl\s+(?:--user\s+)?(?:restart|stop|start|disable|enable)\s|(?:Stop|Start|Restart|Set)-Service\b|launchctl\s+(?:kickstart|stop|start|bootout|unload|load)\b|brew\s+services\s+(?:restart|stop|start)\b|\bsc(?:\.exe)?\s+(?:stop|start|config)\s"},
        {"label": "container restart/stop", "pattern": r"docker\s+(?:restart|stop|kill|rm)\s|docker[\s-]compose\b[^\n;&|]*\b(?:down|restart|stop)\b"},
    ],
    # Task board files (a name or a path ending). Edits to these that name a
    # card mark that card as being worked.
    "board_paths": ["board.md"],
    # A card stays marked while it is mentioned or worked at least this often.
    "card_reinforce_minutes": 10,
    # Optional command run when a card is marked or cleared, e.g. to update a
    # dashboard. Gets ORCH_CARD and ORCH_CARD_STATE (working/cleared) in its
    # environment. Empty = off.
    "on_card_change_command": "",
    # Optional: stop shell rewrites of the blackboard (steer to the Edit tool).
    "shared_file_guard": False,
}


def load_config():
    cfg = dict(DEFAULTS)
    path = os.path.join(state_dir(), "config.json")
    try:
        with open(path, "r", encoding="utf-8") as fh:
            user = json.load(fh)
        if isinstance(user, dict):
            for k, v in user.items():
                if not k.startswith("_"):
                    cfg[k] = v
    except Exception:
        pass
    return cfg


# ---------------------------------------------------------------------------
# A small cross-platform file lock
# ---------------------------------------------------------------------------


class FileLock(object):
    """Exclusive-create lock file with stale reaping.

    Works the same on Windows, macOS and Linux. If the lock cannot be taken in
    time, .ok is False and the caller skips its write: a missed update is
    recoverable on the next tool call, a torn or lost one is not.
    """

    def __init__(self, path, timeout=3.0, stale=15.0):
        self.path = path
        self.timeout = timeout
        self.stale = stale
        self.ok = False

    def __enter__(self):
        deadline = time.time() + self.timeout
        try:
            os.makedirs(os.path.dirname(self.path), exist_ok=True)
        except Exception:
            return self
        while True:
            try:
                fd = os.open(self.path, os.O_CREAT | os.O_EXCL | os.O_WRONLY)
                try:
                    os.write(fd, str(os.getpid()).encode("ascii"))
                finally:
                    os.close(fd)
                self.ok = True
                return self
            except FileExistsError:
                try:
                    if time.time() - os.path.getmtime(self.path) > self.stale:
                        os.remove(self.path)   # holder died without cleaning up
                        continue
                except Exception:
                    pass
            except Exception:
                return self
            if time.time() > deadline:
                return self
            time.sleep(0.05)

    def __exit__(self, *exc):
        if self.ok:
            try:
                os.remove(self.path)
            except Exception:
                pass
        return False


def read_json(path, default):
    try:
        with open(path, "r", encoding="utf-8") as fh:
            return json.load(fh)
    except Exception:
        return default


def write_json(path, data):
    """Atomic replace, retried briefly (Windows refuses a replace while a reader has the file open)."""
    os.makedirs(os.path.dirname(path), exist_ok=True)
    fd, tmp = tempfile.mkstemp(prefix=".tmp-", dir=os.path.dirname(path))
    with os.fdopen(fd, "w", encoding="utf-8") as fh:
        json.dump(data, fh, indent=1)
    for _ in range(20):
        try:
            os.replace(tmp, path)
            return True
        except PermissionError:
            time.sleep(0.05)
    try:
        os.remove(tmp)
    except Exception:
        pass
    return False


def now():
    return int(time.time())


def session_of(payload):
    return (payload.get("session_id") or os.environ.get("CLAUDE_CODE_SESSION_ID")
            or os.environ.get("CLAUDE_SESSION_ID") or "unknown")


def short(sid):
    return (sid or "?")[:8]


# ---------------------------------------------------------------------------
# Paths: two sessions naming one file differently must still collide
# ---------------------------------------------------------------------------

_HOME = None


def _home():
    global _HOME
    if _HOME is None:
        h = os.path.expanduser("~").replace("\\", "/").rstrip("/")
        _HOME = h.lower() if IS_WINDOWS else h
    return _HOME


def norm_path(p, cwd=None):
    """Absolute, forward slashes, home shown as ~, lower case on Windows only."""
    if not p:
        return None
    s = str(p).strip().strip("\"'")
    if not s:
        return None
    if IS_WINDOWS:
        # Git Bash spells C:\x as /c/x. Convert before deciding if it is absolute.
        m = re.match(r"^/([a-zA-Z])(/.*)?$", s.replace("\\", "/"))
        if m:
            s = m.group(1) + ":" + (m.group(2) or "/")
    s = os.path.expanduser(s)
    if not os.path.isabs(s) and cwd:
        s = os.path.join(cwd, s)
    s = os.path.normpath(s).replace("\\", "/")
    if IS_WINDOWS:
        s = s.lower()
    h = _home()
    if s == h:
        return "~"
    if s.startswith(h + "/"):
        s = "~/" + s[len(h) + 1:]
    return s


# ---------------------------------------------------------------------------
# Shell commands: is it a write, and what does it touch?
# ---------------------------------------------------------------------------

# git with any number of -C <dir> / -c key=value options before the subcommand.
_GIT = r"""git(?:\s+-[Cc]\s+(?:"[^"]*"|'[^']*'|\S+))*\s+"""

_WRITE_VERB_CORE = (
    r"\b(?:" + _GIT + r"(?:add|commit|push|merge|rebase|reset|checkout|switch|restore|stash|pull|cherry-pick|revert|clean|rm|mv)\b|"
    r"Register-ScheduledTask|Unregister-ScheduledTask|Set-ScheduledTask|Enable-ScheduledTask|Disable-ScheduledTask|"
    r"Start-ScheduledTask|Stop-ScheduledTask|schtasks(?:\.exe)?\s+/+(?:create|change|delete|end|run)\b|crontab\s+-[er]|"
    r"Set-Service|Stop-Service|Start-Service|Restart-Service|"
    r"Remove-Item|Set-Content|Out-File|Add-Content|New-Item|Copy-Item|Move-Item|Rename-Item|"
    r"docker\s+(?:restart|stop|start|rm|kill|compose)|systemctl\s+(?:restart|stop|start|disable|enable|reload)|"
    r"launchctl\s+(?:kickstart|stop|start|bootout|bootstrap|unload|load)|brew\s+services\s+(?:restart|stop|start)|"
    r"rm\s|mv\s|cp\s|tee\s|touch\s|mkdir\s|chmod\s|ln\s|sed\s+-i|perl\s+-pi|truncate\s)"
)

# Quoted text and heredoc bodies are DATA, not the command. A commit message
# that mentions a file must not claim that file.
# PowerShell here-strings (@' ... '@ and @" ... "@) come first: their body may
# hold a lone apostrophe ("Don't"), which would otherwise pair with the opening
# quote and expose the rest of the message as if it were command.
_QUOTED = re.compile(r"""@'[ \t]*\r?\n[\s\S]*?\n[ \t]*'@|@"[ \t]*\r?\n[\s\S]*?\n[ \t]*"@|'[^']*'|"[^"]*\"""")


def _inner(span):
    """The text inside one quoted span, here-string or plain."""
    return span[2:-2] if span.startswith("@") else span[1:-1]
# A heredoc's BODY is data; the rest of its first line is still command. In
# `cat <<EOF > notes.md` the redirect to notes.md is a real write, so only the
# lines after the marker, up to the terminator, are removed. An unterminated
# heredoc loses everything after its first line.
_HEREDOC = re.compile(r"""(?<!<)(<<-?[ \t]*(['"]?)([A-Za-z_]\w*)\2)([^\n]*)(?:\n[\s\S]*?)?\n[ \t]*\3[ \t]*(?=\n|$)""")
_HEREDOC_OPEN = re.compile(r"""(?<!<)(<<-?[ \t]*(['"]?)([A-Za-z_]\w*)\2)([^\n]*)\n[\s\S]*$""")


def _strip_heredocs(cmd):
    s = _HEREDOC.sub(lambda m: m.group(1) + m.group(4), str(cmd or ""))
    return _HEREDOC_OPEN.sub(lambda m: m.group(1) + m.group(4), s)
# Redirects that write nothing shared: 2>&1, >/dev/null, > $null, > NUL.
_REDIR_NOISE = re.compile(r"\d?>>?\s*(?:&\s*\d|/dev/null|\$null|NUL\b)", re.IGNORECASE)
_REDIR_TARGET = re.compile(r"(?<![<>=-])>>?\s*([A-Za-z0-9_.~$/\\:-]+)")
_TEE_TARGET = re.compile(r"\btee\s+(?:-a\s+)?([A-Za-z0-9_.~$/\\:-]+)")
_SED_I_TARGET = re.compile(r"\bsed\s+-i\S*\s+(?:-e\s+)?\S+\s+([A-Za-z0-9_.~$/\\:-]+)")
_SEGMENT = re.compile(r"&&|\|\||;|\||\n")

# A segment led by a known reader only reads its arguments. Only a redirect
# target in that segment is really written.
_READER_LEAD = re.compile(
    r"""^\s*(?:(?:sudo|command|time|env|nice)\s+)?(?:
        grep|egrep|fgrep|rg|ag|cat|bat|head|tail|less|more|wc|sort|uniq|od|xxd|hexdump|
        file|stat|nl|cut|tr|column|jq|yq|diff|cmp|ls|dir|basename|dirname|realpath|find|echo|printf|
        Get-Content|Select-String|Get-ChildItem|Test-Path|Measure-Object|Format-Table|Write-Output
    )\b""",
    re.IGNORECASE | re.VERBOSE,
)
_SED_READ = re.compile(r"^\s*sed\b(?![^|;&]*\s-i)", re.IGNORECASE)
_AWK_READ = re.compile(r"^\s*awk\b(?![^|;&]*inplace)", re.IGNORECASE)
_GIT_READ = re.compile(r"^\s*" + _GIT + r"(?:log|show|diff|status|blame|ls-files|rev-parse|describe|cat-file|branch\s*$|fetch)\b", re.IGNORECASE)

# Task names are read from the skeleton (quoted spans are placeholders), so a
# task named only inside a commit message or an echo is never claimed.
_TASK_NAME = re.compile(r"(?:-TaskName|/+tn)\s+(\S+)", re.IGNORECASE)
_TASK_WRITE = re.compile(r"(?:Register|Unregister|Set|Enable|Disable|Start|Stop)-ScheduledTask|"
                         r"schtasks(?:\.exe)?\s+/+(?:create|change|delete|end|run)\b", re.IGNORECASE)
_SERVICES = [
    re.compile(r"\bsystemctl\s+(?:--user\s+)?(?:restart|stop|start|disable|enable|reload)\s+([\w@.-]+)", re.IGNORECASE),
    re.compile(r"\b(?:Stop|Start|Restart|Set)-Service\s+(?:-Name\s+)?[\"']?([\w.-]+)", re.IGNORECASE),
    re.compile(r"\bsc(?:\.exe)?\s+(?:stop|start|config)\s+([\w.-]+)", re.IGNORECASE),
    re.compile(r"\bbrew\s+services\s+(?:restart|stop|start)\s+([\w@.-]+)", re.IGNORECASE),
    re.compile(r"\blaunchctl\s+(?:kickstart|stop|start|bootout|unload|load)\s+(?:-\w+\s+)*([\w./@-]+)", re.IGNORECASE),
    re.compile(r"\bdocker\s+(?:restart|stop|start|rm|kill)\s+(?:-\w+\s+)*([\w.-]+)", re.IGNORECASE),
]
_COMPOSE = re.compile(r"\bdocker[\s-]compose\b[^;&|\n]*\b(?:up|down|restart|stop|rm)\b", re.IGNORECASE)


def despoken(cmd):
    """The command with its data payload (quotes, heredoc bodies) removed."""
    if not cmd:
        return ""
    return _QUOTED.sub(" ", _strip_heredocs(cmd))


def despoken_keep_paths(cmd):
    """Like despoken, but a quoted span with no whitespace in it is kept,
    unquoted, because it is far more likely a path ("my.md") than a message.
    For detectors that look for a named file in the command."""
    if not cmd:
        return ""

    def keep(m):
        inner = _inner(m.group(0))
        return " " if (not inner or re.search(r"\s", inner)) else inner
    return _QUOTED.sub(keep, _strip_heredocs(cmd))


def skeleton(cmd):
    """Heredoc bodies removed; each quoted span swapped for a placeholder.

    Placeholders keep separators inside quotes from splitting a pipeline, while
    still letting a quoted path ("my notes.md") be recovered as a target.
    """
    quotes = []

    def swap(m):
        quotes.append(_inner(m.group(0)))
        return "__q%d__" % (len(quotes) - 1)

    return _QUOTED.sub(swap, _strip_heredocs(cmd)), quotes


_QTOKEN = re.compile(r"__q(\d+)__")


def _unquote(token, quotes):
    def back(m):
        i = int(m.group(1))
        return quotes[i] if i < len(quotes) else ""
    return _QTOKEN.sub(back, token)


def _is_reader(seg):
    return bool(_READER_LEAD.match(seg) or _SED_READ.match(seg) or _AWK_READ.match(seg) or _GIT_READ.match(seg))


def deread(skel):
    """Drop arguments that are only read, keeping redirect targets."""
    out = []
    for seg in _SEGMENT.split(skel or ""):
        if _is_reader(seg):
            out.extend("> " + x for x in _REDIR_TARGET.findall(_REDIR_NOISE.sub(" ", seg)))
            continue
        out.append(seg)
    # Keep a separator between segments: later steps parse each one alone,
    # and "rm a" glued to "mv b c" would read as "rm a mv b c".
    return " ; ".join(out)


# Commands whose arguments are the files they change.
_ARG_VERBS = re.compile(
    r"^\s*(?:sudo\s+)?(rm|mv|cp|touch|mkdir|truncate|chmod|ln|Remove-Item|Set-Content|Add-Content|"
    r"Out-File|New-Item|Copy-Item|Move-Item|Rename-Item)\b(.*)$", re.IGNORECASE)
# Flags whose VALUE is not a path, so the value must not be claimed.
_VALUE_FLAGS = {"-value", "-encoding", "-inputobject", "-itemtype", "-m", "-s", "--mode", "-width", "-erroraction"}


def _arg_targets(seg):
    m = _ARG_VERBS.match(seg)
    if not m:
        return []
    verb = m.group(1).lower()
    args, skip = [], False
    for a in m.group(2).split():
        if skip:
            skip = False
            continue
        if a.startswith("-"):
            skip = a.lower() in _VALUE_FLAGS
            continue
        if a in (">", ">>") or a.startswith(">") or a.startswith("2>"):
            break
        args.append(a)
    if verb == "chmod" and args:
        args = args[1:]
    if verb in ("cp", "ln", "copy-item") and len(args) > 1:
        args = args[-1:]
    return args


# --- git: parsed per segment, on the skeleton, never on quoted text ----------
#
# Broad operations take every dirty file in the repo, including other
# sessions' half-done work: `git add -A`, `git commit -a`, `git reset --hard`,
# `git checkout -- .`, `git clean -f`, a stash with no path, `--autostash`
# (a blind stash with a pop bolted on: if the pop fails, everyone's edits are
# rewound). They claim "gitindex:<repo>", which collides with any live file
# claim in that repo. Path-scoped forms (`git checkout -- f`, `git restore f`,
# `git stash push f`, `git rm f`) overwrite exactly those files, so they claim
# the files. Staging a path (`git add f`) or committing named paths changes no
# file and claims nothing.

_PREFIX_WORDS = ("sudo", "command", "time", "env", "nice", "exec", "nohup")
_GIT_GLOBAL_VALUE = ("-c", "-C", "--git-dir", "--work-tree", "--namespace", "--exec-path", "--config-env")
_STASH_KEEP = ("pop", "apply", "list", "show", "drop", "clear", "branch", "create", "store")


def _git_parts(seg, quotes):
    """(repo dir or None, subcommand, args, autostash_by_config) or None."""
    toks = seg.split()
    i = 0
    while i < len(toks) and (toks[i].lower() in _PREFIX_WORDS or re.match(r"^\w+=", toks[i])):
        i += 1
    if i >= len(toks) or toks[i].lower() not in ("git", "git.exe"):
        return None
    i += 1
    repo, auto = None, False
    while i < len(toks) and toks[i].startswith("-"):
        t = toks[i]
        if t in _GIT_GLOBAL_VALUE and i + 1 < len(toks):
            v = _unquote(toks[i + 1], quotes)
            if t == "-C":
                repo = os.path.join(repo, v) if repo else v
            elif t == "-c" and re.match(r"(?i)^(?:rebase|merge|pull)\.autostash=(?:true|1|yes|on)$", v):
                auto = True
            i += 2
            continue
        i += 1
    if i >= len(toks):
        return None
    args = []
    for a in toks[i + 1:]:
        if re.match(r"^\d?[<>]", a):
            break
        args.append(_unquote(a, quotes))
    return repo, toks[i].lower(), args, auto


def _split_args(args, value_flags=()):
    """(flags, positional args before --, args after --)."""
    flags, pos, after, skip = [], [], [], False
    if "--" in args:
        after = args[args.index("--") + 1:]
        args = args[:args.index("--")]
    for a in args:
        if skip:
            skip = False
            continue
        if a.startswith("-") and a != "-":
            flags.append(a)
            skip = a in value_flags
            continue
        pos.append(a)
    return flags, pos, after


def _short_has(flags, letter, value_letters=""):
    """True if a short-flag cluster (-am) sets `letter` before any letter that takes a value."""
    for f in flags:
        if f.startswith("-") and not f.startswith("--"):
            for ch in f[1:]:
                if ch == letter:
                    return True
                if ch in value_letters:
                    break
    return False


def _is_file(p, base):
    try:
        return os.path.isfile(os.path.expanduser(os.path.join(base or os.getcwd(), p)))
    except Exception:
        return False


def _whole_tree(paths):
    return any(p in (".", "./", ":/", ":", "*") for p in paths)


def git_effects(seg, quotes, cwd=None):
    """For one shell segment: None if it is not git, else
    (repo dir or None, paths it overwrites, broad)."""
    g = _git_parts(seg, quotes)
    if not g:
        return None
    repo, sub, args, auto = g
    base = norm_path(repo, cwd) if repo else cwd
    paths, broad = [], auto
    if sub == "add":
        flags, pos, after = _split_args(args)
        spec = pos + after
        broad = broad or _whole_tree(spec) or (not spec and (
            any(f in ("--all", "--update", "-A", "-u") for f in flags) or _short_has(flags, "A") or _short_has(flags, "u")))
    elif sub == "commit":
        flags, _, _ = _split_args(args, ("-m", "-F", "-C", "-c", "--author", "--date", "-t", "--template", "--message", "--file"))
        broad = broad or "--all" in flags or _short_has(flags, "a", "mFCct")
    elif sub == "checkout":
        flags, pos, after = _split_args(args, ("-b", "-B", "--orphan"))
        if any(f in ("-f", "--force") for f in flags):
            broad = True
        if "--" in args:
            paths = after
        elif len(pos) >= 2:
            paths = pos[1:]
        elif len(pos) == 1 and (pos[0] == "." or _is_file(pos[0], base)):
            paths = pos
    elif sub == "restore":
        flags, pos, after = _split_args(args, ("-s", "--source"))
        staged_only = any(f in ("-S", "--staged") for f in flags) and not any(f in ("-W", "--worktree") for f in flags)
        if not staged_only:
            paths = pos + after
    elif sub == "reset":
        flags, pos, after = _split_args(args)
        if any(f in ("--hard", "--keep", "--merge", "--soft") for f in flags):
            broad = True
        elif not after and not any(_is_file(p, base) for p in pos):
            broad = True      # `git reset` / `git reset HEAD~1`: the whole index moves
    elif sub == "clean":
        flags, pos, after = _split_args(args, ("-e", "--exclude"))
        if any(f == "--force" or _short_has([f], "f") for f in flags):
            paths = pos + after
            broad = broad or not paths
    elif sub == "stash":
        what = args[0].lower() if args and not args[0].startswith("-") else "push"
        rest = args[1:] if args and not args[0].startswith("-") else args
        if what == "push":
            _, pos, after = _split_args(rest, ("-m", "--message"))
            paths = pos + after
            broad = broad or not paths
        elif what not in _STASH_KEEP:
            broad = True      # `git stash save <message>` and anything unknown
    elif sub == "switch":
        flags, _, _ = _split_args(args, ("-c", "-C", "--orphan"))
        broad = broad or any(f in ("-f", "--force", "--discard-changes") for f in flags)
    elif sub == "rm":
        flags, pos, after = _split_args(args)
        if "--cached" not in flags:
            paths = pos + after
    elif sub == "mv":
        _, pos, after = _split_args(args)
        paths = pos + after
    elif sub in ("pull", "rebase", "merge"):
        broad = broad or "--autostash" in args
    if _whole_tree(paths):
        paths, broad = [], True
    return repo, paths, broad


def is_blind_stash(cmd):
    """A stash (or --autostash) that takes the whole tree, read from the command
    itself, never from quoted text."""
    skel, quotes = skeleton(cmd)
    for seg in _SEGMENT.split(skel):
        g = _git_parts(seg, quotes)
        if not g:
            continue
        _, sub, args, auto = g
        if auto or (sub in ("pull", "rebase", "merge") and "--autostash" in args):
            return True
        if sub == "stash":
            eff = git_effects(seg, quotes)
            if eff and eff[2]:
                return True
    return False


def is_write(cmd, cfg):
    """True if a shell command plausibly changes shared state.

    Biased toward under-detection: a missed claim is one missing warning, a
    false one is noise in a table that only works while it stays short.
    """
    if not cmd:
        return False
    skel = despoken(cmd)
    verbs = _WRITE_VERB_CORE
    extra = [v for v in (cfg.get("extra_write_verbs") or []) if v]
    if extra:
        verbs = r"(?:" + verbs + r"|\b(?:" + "|".join(extra) + r"))"
    if re.search(verbs, skel, re.IGNORECASE) or is_blind_stash(cmd):
        return True
    # Redirects are looked for with each quoted span as a placeholder, so a
    # quoted target (> "my notes.md") still counts and a > inside quotes does not.
    return bool(_REDIR_TARGET.search(_REDIR_NOISE.sub(" ", skeleton(cmd)[0])))


def _path_ok(t):
    return t and not t.startswith(("&", "$", "%")) and not any(ch in t for ch in "*?")


def shell_keys(cmd, cwd, cfg):
    """(resource keys, skeleton text used for area tags) for a shell command.

    ([], "") means the command only reads. Every detector here works on the
    skeleton: quoted text and heredoc bodies are data, never what is touched.
    """
    if not is_write(cmd, cfg):
        return [], ""
    keys = set()
    skel, quotes = skeleton(cmd)
    body = deread(skel)
    targets = []
    for seg in _SEGMENT.split(body):
        clean = _REDIR_NOISE.sub(" ", seg)
        targets += _REDIR_TARGET.findall(clean)
        targets += _TEE_TARGET.findall(clean)
        targets += _SED_I_TARGET.findall(clean)
        targets += _arg_targets(clean)
    for t in targets:
        t = _unquote(t, quotes).strip()
        if _path_ok(t):
            p = norm_path(t, cwd)
            if p and p not in ("/dev/null",):
                keys.add("file:" + p)
    for seg in _SEGMENT.split(body):
        eff = git_effects(seg, quotes, cwd)
        if not eff:
            continue
        repo, paths, broad = eff
        base = norm_path(repo, cwd) if repo else (norm_path(cwd) if cwd else None)
        for p in paths:
            if _path_ok(p):
                np = norm_path(p, base or cwd)
                if np:
                    keys.add("file:" + np)
        if broad:
            keys.add("gitindex:" + (base or "cwd"))
    plain = despoken(cmd)
    if _TASK_WRITE.search(plain):
        for m in _TASK_NAME.finditer(skel):
            name = _unquote(m.group(1), quotes).strip().strip("\"'")
            if name:
                keys.add("task:" + name.lower())
    if re.search(r"\bcrontab\s+-[er]", plain):
        keys.add("task:crontab")
    for rx in _SERVICES:
        for name in rx.findall(plain):
            keys.add("svc:" + name.lower())
    if _COMPOSE.search(plain):
        keys.add("svc:compose:" + (norm_path(cwd) or "cwd"))
    # Area tags look at what is touched, never at quoted data.
    tag_text = " ".join([deread(plain)] + [k.split(":", 1)[1] for k in keys])
    return sorted(keys), tag_text


# ---------------------------------------------------------------------------
# MCP tools
# ---------------------------------------------------------------------------


def _mcp_parts(tool_name):
    m = re.match(r"^mcp__(.+?)__(.+)$", tool_name or "")
    return (m.group(1), m.group(2)) if m else (None, None)


def _rx_any(patterns, text):
    for p in patterns or []:
        try:
            if re.search(p, text):
                return True
        except re.error:
            continue
    return False


def mcp_keys(tool_name, ti, cfg):
    server, action = _mcp_parts(tool_name)
    if not server:
        return []
    if _rx_any(cfg.get("read_tools"), tool_name):
        return []
    forced = _rx_any(cfg.get("write_tools"), tool_name)
    words = re.split(r"[_\-.]+", action.lower())
    read_rx = re.compile(r"^(?:" + cfg["mcp_read_words"] + r")$")
    write_rx = re.compile(r"^(?:" + cfg["mcp_write_words"] + r")$")
    if not forced:
        if words and read_rx.match(words[0]):
            return []
        if not any(write_rx.match(w) for w in words):
            return []
        # A generic "call"/"run" tool whose operation field names a read is a read.
        for f in ("service", "action", "operation", "method", "op"):
            v = str(ti.get(f) or "").lower()
            if v and read_rx.match(re.split(r"[_\-.]+", v)[0]):
                return []
    target = ""
    for f in cfg.get("mcp_target_fields") or []:
        v = ti.get(f)
        if isinstance(v, (str, int)) and str(v).strip():
            target = str(v).strip().lower()
            break
    return ["mcp:" + server.lower() + (":" + target if target else "")]


# ---------------------------------------------------------------------------
# What a tool call touches
# ---------------------------------------------------------------------------

WRITE_FILE_TOOLS = ("Edit", "Write", "MultiEdit", "NotebookEdit")


def resources_for(tool_name, tool_input, cwd=None, cfg=None):
    """Resource keys a tool call writes. [] for anything that only reads."""
    cfg = cfg or load_config()
    ti = tool_input if isinstance(tool_input, dict) else {}
    keys = set()
    blob = ""
    if tool_name in WRITE_FILE_TOOLS:
        p = norm_path(ti.get("file_path") or ti.get("notebook_path"), cwd)
        if not p:
            return []
        keys.add("file:" + p)
        blob = p
    elif tool_name in ("Bash", "PowerShell"):
        k, blob = shell_keys(ti.get("command") or "", cwd, cfg)
        if not k and not blob:
            return []
        keys.update(k)
        if not keys and not blob.strip():
            return []
    elif (tool_name or "").startswith("mcp__"):
        k = mcp_keys(tool_name, ti, cfg)
        if not k:
            return []
        keys.update(k)
        blob = json.dumps(ti)
    else:
        return []
    # The blackboard is edited by every session, by design, one line each.
    # Claiming it would block the very workflow the blackboard exists for (and
    # the line being blocked is often a standing caution), so it is never
    # claimed. Whole-file shell rewrites of it have their own optional guard.
    bb = norm_path(os.path.expanduser(cfg.get("blackboard_path") or "~/.claude/blackboard.md"))
    if bb and ("file:" + bb) in keys:
        keys.discard("file:" + bb)
        if not keys:
            return []
    low = blob.replace("\\", "/").lower()
    for t in cfg.get("area_tags") or []:
        try:
            if re.search(t["pattern"], low, re.IGNORECASE):
                keys.add("area:" + t["tag"])
        except (re.error, KeyError, TypeError):
            continue
    if tool_name in ("Bash", "PowerShell") and not keys:
        # A write-shaped command that names nothing we can key on (for example
        # a script run with a redirect to an unknown place) claims nothing.
        return []
    return sorted(keys)


def read_target(tool_name, tool_input, cwd=None):
    """The file a Read call looked at, so a later stale-copy check knows."""
    if tool_name != "Read":
        return None
    ti = tool_input if isinstance(tool_input, dict) else {}
    p = norm_path(ti.get("file_path"), cwd)
    return ("file:" + p) if p else None


# ---------------------------------------------------------------------------
# State
# ---------------------------------------------------------------------------


def claims_path():
    return os.path.join(state_dir(), "claims.json")


def lock_path():
    return os.path.join(state_dir(), "claims.lock")


def load_state():
    d = read_json(claims_path(), {})
    if not isinstance(d, dict):
        d = {}
    for k in ("claims", "writes", "reads", "warned"):
        if not isinstance(d.get(k), dict):
            d[k] = {}
    return d


def live(claim, cfg, t=None):
    t = t or now()
    if claim.get("released"):
        return False
    return (t - int(claim.get("last", 0))) < int(cfg["claim_ttl_minutes"]) * 60


def prune(d, cfg, t=None):
    t = t or now()
    keep_w = int(cfg["recent_write_hours"]) * 3600
    d["claims"] = {k: c for k, c in d["claims"].items() if live(c, cfg, t)}
    d["writes"] = {k: w for k, w in d["writes"].items() if t - int(w.get("at", 0)) < keep_w}
    d["reads"] = {k: v for k, v in d["reads"].items() if t - int(v) < keep_w}
    cool = int(cfg["warn_cooldown_minutes"]) * 60
    d["warned"] = {k: v for k, v in d["warned"].items() if t - int(v) < cool}
    return d


def card_of(text, cfg):
    try:
        m = re.search(cfg["card_id_pattern"], text or "")
    except re.error:
        return None
    return m.group(0) if m else None


def session_names():
    """Best effort: session id -> the name other agents address it by.

    Reads an internal Claude Code file that may change in any release, so any
    failure just means the guard shows the short id instead.
    """
    out = {}
    d = os.path.join(os.path.expanduser("~"), ".claude", "sessions")
    try:
        for fn in os.listdir(d):
            if fn.endswith(".json"):
                j = read_json(os.path.join(d, fn), {})
                if isinstance(j, dict) and j.get("sessionId") and j.get("name"):
                    out[j["sessionId"]] = j["name"]
    except Exception:
        pass
    return out


def log(msg):
    """One line per guard decision. A silent no-op and a hook that never ran
    look the same from inside a session; this log tells them apart."""
    try:
        p = os.path.join(state_dir(), "guard.log")
        os.makedirs(state_dir(), exist_ok=True)
        if os.path.exists(p) and os.path.getsize(p) > 1024 * 1024:
            os.replace(p, p + ".1")
        with open(p, "a", encoding="utf-8") as fh:
            fh.write("%s %s\n" % (time.strftime("%Y-%m-%d %H:%M:%S"), msg))
    except Exception:
        pass


# ---------------------------------------------------------------------------
# Modes
# ---------------------------------------------------------------------------


def cmd_touch(payload, cfg):
    tool = payload.get("tool_name") or ""
    ti = payload.get("tool_input") or {}
    cwd = payload.get("cwd")
    sid = session_of(payload)
    t = now()

    rk = read_target(tool, ti, cwd)
    keys = [] if rk else resources_for(tool, ti, cwd, cfg)
    if not rk and not keys:
        return
    if tool in ("Bash", "PowerShell"):
        card = card_of(despoken(ti.get("command") or ""), cfg)
    else:
        card = card_of(json.dumps(ti)[:4000], cfg)

    with FileLock(lock_path()) as lk:
        if not lk.ok:
            return
        d = prune(load_state(), cfg, t)
        if rk:
            d["reads"][sid + "|" + rk] = t
            write_json(claims_path(), d)
            return
        for k in keys:
            if k.startswith("file:") and tool in WRITE_FILE_TOOLS + ("Bash", "PowerShell"):
                d["writes"][k] = {"at": t, "by": sid}
            cur = d["claims"].get(k)
            if cur and cur.get("session") != sid and live(cur, cfg, t):
                cur.setdefault("contested", [])
                if sid not in cur["contested"]:
                    cur["contested"].append(sid)
                continue
            mine = bool(cur) and cur.get("session") == sid
            d["claims"][k] = {
                "session": sid,
                "card": card or (cur or {}).get("card") if mine else card,
                "tool": tool,
                "since": cur.get("since", t) if mine else t,
                "last": t,
                "contested": cur.get("contested", []) if mine else [],
            }
        write_json(claims_path(), d)


def _deny(reason):
    print(json.dumps({"hookSpecificOutput": {
        "hookEventName": "PreToolUse",
        "permissionDecision": "deny",
        "permissionDecisionReason": reason,
    }}))


def cmd_check(payload, cfg):
    mode = str(cfg.get("guard_mode") or "deny").lower()
    if mode == "off":
        return
    tool = payload.get("tool_name") or ""
    ti = payload.get("tool_input") or {}
    cwd = payload.get("cwd")
    sid = session_of(payload)
    keys = resources_for(tool, ti, cwd, cfg)
    if not keys:
        log("CHECK %s %s no-keys" % (short(sid), tool))
        return
    t = now()
    with FileLock(lock_path()) as lk:
        if not lk.ok:
            log("CHECK %s lock-busy allow" % short(sid))
            return
        d = prune(load_state(), cfg, t)
        conflicts = []
        for k in keys:
            c = d["claims"].get(k)
            if c and c.get("session") != sid and live(c, cfg, t):
                conflicts.append((k, c))
        # A broad git add/commit/stash sweeps up every dirty file in the repo,
        # so it collides with any live file claim inside that repo.
        for k in keys:
            if not k.startswith("gitindex:"):
                continue
            repo = k.split(":", 1)[1]
            for ck, cc in d["claims"].items():
                if not ck.startswith("file:") or cc.get("session") == sid or not live(cc, cfg, t):
                    continue
                if repo != "cwd" and not ck[5:].startswith(repo.rstrip("/") + "/"):
                    continue
                if not any(x[0] == ck for x in conflicts):
                    conflicts.append((ck, cc))
        # Stale copy: someone else wrote this file, and this session has not
        # read or written it since. Fires even if the writer is long gone.
        stale = []
        for k in keys:
            if not k.startswith("file:"):
                continue
            w = d["writes"].get(k)
            if not w or w.get("by") == sid:
                continue
            seen = int(d["reads"].get(sid + "|" + k, 0))
            if seen >= int(w.get("at", 0)):
                continue
            stale.append((k, w))
        if not conflicts and not stale:
            log("CHECK %s %s clear" % (short(sid), ",".join(keys)[:80]))
            return
        all_keys = sorted(set([k for k, _ in conflicts] + [k for k, _ in stale]))
        cool = int(cfg["warn_cooldown_minutes"]) * 60
        fresh = [k for k in all_keys if t - int(d["warned"].get(sid + "|" + k, 0)) >= cool]
        if not fresh:
            log("CHECK %s allow-after-warning %s" % (short(sid), ",".join(all_keys)[:80]))
            return
        if mode != "deny":
            log("CHECK %s would-deny(warn mode) %s" % (short(sid), ",".join(all_keys)[:80]))
            return
        for k in all_keys:
            d["warned"][sid + "|" + k] = t
        write_json(claims_path(), d)

    names = session_names()
    if conflicts:
        lines = []
        for k, c in conflicts[:5]:
            who = names.get(c.get("session")) or short(c.get("session"))
            card = (" on " + c["card"]) if c.get("card") else ""
            mins = max(1, (t - int(c.get("last", t))) // 60)
            lines.append("  - %s: held by session %s%s, active %d min ago" % (k, who, card, mins))
        holder = names.get(conflicts[0][1].get("session")) or short(conflicts[0][1].get("session"))
        reason = (
            "Another live Claude Code session is working on what this call would change:\n"
            + "\n".join(lines) + "\n\n"
            "Do not just retry, and do not write over their work.\n"
            "1. Contact that session if you can. If your tools include SendMessage and ListAgents, "
            "message session " + holder + ": say what you are about to change and ask whether it is "
            "mid-change or done. If you have no way to reach it, stop and ask the user.\n"
            "2. If it is mid-change, wait, and pass on anything you found that it needs.\n"
            "3. If it has finished, or the overlap is only incidental, say so and run the call again. "
            "This guard warns once; the retry goes through."
        )
        if stale:
            reason += "\n\nAlso changed by another session since you last read it:\n" + "\n".join(
                "  - %s (%d min ago)" % (k, max(1, (t - int(w.get("at", t))) // 60)) for k, w in stale)
            reason += "\nRe-read before writing, or you will undo their change."
        _deny(reason)
        log("DENY %s collision %s" % (short(sid), ",".join(k for k, _ in conflicts)[:120]))
        return
    lines = ["  - %s: changed by session %s, %d min ago" % (
        k, names.get(w.get("by")) or short(w.get("by")), max(1, (t - int(w.get("at", t))) // 60)) for k, w in stale]
    _deny(
        "Possible stale copy. Another session changed this file after you last read it:\n"
        + "\n".join(lines) + "\n\n"
        "If the version in your context is older, saving it will silently undo their change.\n"
        "1. Read the file again now and check your change still fits.\n"
        "2. If their change is missing from what you are about to write, merge instead of overwrite.\n"
        "3. If you have already re-read it, run the call again. This guard warns once."
    )
    log("DENY %s stale %s" % (short(sid), ",".join(k for k, _ in stale)[:120]))


def cmd_release(payload, cfg, ended=False):
    """Drop this session's claims.

    Claims are NOT dropped when a turn ends: a session waiting on its human
    is still mid-task, and its files are still half-changed. They go when the
    session closes (ended=True, SessionEnd), when this is run by hand, or
    when they expire.

    Read records are kept unless the session has ended. They are what lets
    this session write a file it has re-read without a false stale-copy
    warning, so dropping them mid-session would cause exactly that.
    """
    sid = session_of(payload)
    if not ended and (sid == "unknown" or sid.startswith("${")):
        print("No session id, so nothing was released. Pass {\"session_id\": \"<id>\"} on stdin.")
        return
    with FileLock(lock_path()) as lk:
        if not lk.ok:
            if not ended:
                print("The state folder is busy; nothing was released. Try again.")
            return
        d = load_state()
        mine = sum(1 for c in d["claims"].values() if c.get("session") == sid)
        d["claims"] = {k: c for k, c in d["claims"].items() if c.get("session") != sid}
        if ended:
            d["reads"] = {k: v for k, v in d["reads"].items() if not k.startswith(sid + "|")}
            d["warned"] = {k: v for k, v in d["warned"].items() if not k.startswith(sid + "|")}
        write_json(claims_path(), prune(d, cfg))
    if not ended:
        print("Released %d claim(s) held by session %s. Its read records are kept." % (mine, short(sid)))


def digest_lines(cfg, me=None, include_empty=False):
    d = prune(load_state(), cfg)
    t = now()
    rows = [(k, c) for k, c in d["claims"].items() if live(c, cfg, t)]
    cards = []
    try:
        lc = read_json(os.path.join(state_dir(), "live-cards.json"), {})
        for s, v in (lc or {}).items():
            if isinstance(v, dict) and v.get("card") and v.get("active"):
                cards.append((s, v))
    except Exception:
        pass
    if not rows and not cards:
        return ["No live claims."] if include_empty else []
    names = session_names()

    def who(s):
        return names.get(s) or short(s)

    out = ["LIVE CLAIMS (other sessions are changing these now; check before you write):"]
    files = [(k, c) for k, c in rows if k.startswith("file:")]
    other = [(k, c) for k, c in rows if not k.startswith("file:")]
    other.sort(key=lambda kc: (not kc[0].startswith("area:"), kc[0]))
    shown = 0
    for k, c in other:
        if shown >= int(cfg["max_digest_rows"]):
            break
        mins = max(0, (t - int(c.get("last", t))) // 60)
        card = (" " + c["card"]) if c.get("card") else ""
        flag = "  <- CONTESTED" if c.get("contested") else ""
        you = "  (you)" if me and c.get("session") == me else ""
        out.append("  [%s%s] %s  (%d min ago)%s%s" % (who(c.get("session")), card, k, mins, you, flag))
        shown += 1
    by = {}
    for k, c in files:
        by.setdefault(c.get("session"), []).append(k[5:])
    for s, fl in list(by.items())[:5]:
        you = "  (you)" if me and s == me else ""
        out.append("  [%s] %d file(s): %s%s%s" % (who(s), len(fl), ", ".join(fl[:3]), "..." if len(fl) > 3 else "", you))
    for s, v in cards[:6]:
        you = "  (you)" if me and s == me else ""
        out.append("  [%s] working card %s%s" % (who(s), v["card"], you))
    out.append("  Overlap with yours? Talk to that session before writing. Never silently redo or undo its work.")
    return out


def cmd_digest(payload, cfg):
    lines = digest_lines(cfg, me=session_of(payload))
    if not lines:
        return
    event = payload.get("hook_event_name") or "UserPromptSubmit"
    text = "\n".join(lines)[:9000]
    print(json.dumps({"hookSpecificOutput": {"hookEventName": event, "additionalContext": text}}))


def cmd_health(cfg):
    print("Python        %s" % sys.version.split()[0])
    print("State folder  %s" % state_dir())
    print("Config file   %s (%s)" % (os.path.join(state_dir(), "config.json"),
                                     "found" if os.path.exists(os.path.join(state_dir(), "config.json")) else "not found, using defaults"))
    print("Guard mode    %s" % cfg.get("guard_mode"))
    p = os.path.join(state_dir(), "guard.log")
    if os.path.exists(p):
        with open(p, "r", encoding="utf-8", errors="replace") as fh:
            tail = fh.readlines()[-5:]
        print("Guard log     last %d line(s):" % len(tail))
        for line in tail:
            print("  " + line.rstrip())
    else:
        print("Guard log     none yet: the guard has never run. Check the hook wiring.")
    d = load_state()
    print("Live claims   %d" % sum(1 for c in d["claims"].values() if live(c, cfg)))
    print("Last inject   %s" % inject_age())


def inject_age(t=None):
    """How long ago the blackboard was last injected successfully.

    The inject hook writes inject.ok only when the head it injected really
    contained the STANDING CAUTIONS section, so an old time means sessions are
    not seeing the blackboard, even if every hook looks fine.
    """
    p = os.path.join(state_dir(), "inject.ok")
    try:
        age = int((t or time.time()) - os.path.getmtime(p))
    except Exception:
        return "never (no successful blackboard injection recorded; with the full plugin, start a session or send a prompt)"
    if age < 120:
        txt = "%d s ago" % max(0, age)
    elif age < 7200:
        txt = "%d min ago" % (age // 60)
    elif age < 172800:
        txt = "%d h ago" % (age // 3600)
    else:
        txt = "%d days ago" % (age // 86400)
    if age > 86400:
        txt += "  <- STALE: if sessions ran since then, the blackboard is not reaching them"
    return txt


def cmd_selftest():
    """Seed a collision in a throwaway folder and prove the guard denies it,
    allows the retry, and claims nothing for a plain read. Exit 1 on failure."""
    import io
    import shutil
    tmp = tempfile.mkdtemp(prefix="orch-selftest-")
    old = os.environ.get("ORCH_HOME")
    os.environ["ORCH_HOME"] = tmp
    ok = True
    try:
        cfg = load_config()
        target = os.path.join(tmp, "shared.txt")
        a = {"session_id": "sess-a", "tool_name": "Edit", "tool_input": {"file_path": target}, "cwd": tmp}
        b = dict(a, session_id="sess-b")

        def run(fn, p):
            buf, real = io.StringIO(), sys.stdout
            sys.stdout = buf
            try:
                fn(p, cfg)
            finally:
                sys.stdout = real
            return buf.getvalue()

        run(cmd_touch, a)
        first = run(cmd_check, b)
        second = run(cmd_check, b)
        read = resources_for("Bash", {"command": "grep -n x " + target}, tmp, cfg)
        checks = [
            ("guard denies a write to a file another live session holds", '"deny"' in first),
            ("guard lets the retry through after warning once", second.strip() == ""),
            ("a plain read claims nothing", read == []),
        ]
        for label, passed in checks:
            print("%s  %s" % ("PASS" if passed else "FAIL", label))
            ok = ok and passed
    finally:
        if old is None:
            os.environ.pop("ORCH_HOME", None)
        else:
            os.environ["ORCH_HOME"] = old
        shutil.rmtree(tmp, ignore_errors=True)
    return ok


def main(argv):
    mode = argv[1] if len(argv) > 1 else "touch"
    cfg = load_config()
    if mode == "selftest":
        return 0 if cmd_selftest() else 1
    if mode == "health":
        cmd_health(cfg)
        return 0
    if mode == "show":
        print("\n".join(digest_lines(cfg, include_empty=True)))
        return 0
    if mode == "gc":
        with FileLock(lock_path()) as lk:
            if lk.ok:
                write_json(claims_path(), prune(load_state(), cfg))
        return 0
    payload = {}
    try:
        raw = sys.stdin.read()
        if raw.strip():
            payload = json.loads(raw)
    except Exception:
        payload = {}
    if not isinstance(payload, dict):
        payload = {}
    if mode == "touch":
        cmd_touch(payload, cfg)
    elif mode == "check":
        cmd_check(payload, cfg)
    elif mode == "release":
        cmd_release(payload, cfg)
    elif mode == "end":
        cmd_release(payload, cfg, ended=True)
    elif mode == "digest":
        cmd_digest(payload, cfg)
    return 0


if __name__ == "__main__":
    code = 0
    try:
        if PY_OK:
            code = main(sys.argv)
    except Exception:
        code = 0      # fail open, always
    sys.exit(code if len(sys.argv) > 1 and sys.argv[1] == "selftest" else 0)
