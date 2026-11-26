#!/usr/bin/env python3
"""Guardrails for parallel AI coding agents: file locks, secret-read deny,
destructive-command deny. One file, standard library only, no network.

Modes (first argument):
  hook          Claude Code PreToolUse hook (payload on stdin)
  end           Claude Code SessionEnd hook: release this session's locks
  cursor-hook   Cursor hook (beforeShellExecution / beforeReadFile / afterFileEdit)
  mcp           MCP server over stdio: acquire_lock, release_lock, list_locks,
                check_command, check_path
  check-command <cmd...>   print the verdict for a command (exit 1 if blocked)
  check-path <path>        print the verdict for a file read (exit 1 if blocked)
  locks                    list live locks
  unlock <path>            free a lock whoever holds it (for humans)
  health                   last decisions and which config is in use

State lives in $GUARDRAILS_HOME (default ~/.agent-guardrails). Rules come from
$GUARDRAILS_CONFIG, else .guardrails.yaml in the project folder, else the
guardrails.yaml shipped next to this script. Hooks fail open on any error.
"""
import fnmatch
import json
import os
import re
import shlex
import sys
import time

VERSION = "1.2.1"
HERE = os.path.dirname(os.path.abspath(__file__))
DEFAULT_CONFIG = os.path.join(os.path.dirname(HERE), "guardrails.yaml")
PROJECT_CONFIG = ".guardrails.yaml"


# ---------------------------------------------------------------- YAML subset
# Block maps, block lists, "- key: value" list items, comments, quoted scalars,
# true/false/null/ints, and flow values ([...] / {...}) written as JSON.

def _strip_comment(line):
    out, q = [], None
    for i, ch in enumerate(line):
        if q:
            if ch == q:
                q = None
        elif ch in "'\"" and (i == 0 or line[i - 1] in " \t:[,-{"):
            q = ch
        elif ch == "#" and (i == 0 or line[i - 1] in " \t"):
            break
        out.append(ch)
    return "".join(out).rstrip()


_KEY = re.compile(r'^("[^"]*"|\'[^\']*\'|[^\s"\'\[{#:-][^:#]*?|-[^\s:][^:#]*?)\s*:(?:\s+(.*))?$')


def _key_split(s):
    m = _KEY.match(s)
    if not m:
        return None
    k = m.group(1)
    if k[0] in "'\"":
        k = k[1:-1]
    return k, (m.group(2) or "").strip()


def _scalar(s):
    s = s.strip()
    if s == "" or s in ("~", "null"):
        return None
    if s[0] == "[" and s.endswith("]"):
        try:
            return json.loads(s)
        except ValueError:
            return _flow_list(s)
    if s[0] in "{\"":
        return json.loads(s)
    if s[0] == "'" and s.endswith("'") and len(s) > 1:
        return s[1:-1].replace("''", "'")
    if s in ("true", "false"):
        return s == "true"
    if re.fullmatch(r"-?\d+", s):
        return int(s)
    return s


def _flow_list(s):
    """[a, 'b', "c", [d, e]] without JSON quoting: one level of nesting."""
    out, stack, cur, q, quoted = [], [], "", None, False
    items = out
    for ch in s[1:-1] + ",":
        if q:
            if ch == q:
                q = None
            else:
                cur += ch
            continue
        if ch in "'\"":
            q, quoted, cur = ch, True, ""
        elif ch == "[":
            stack.append(items)
            new = []
            items.append(new)
            items = new
        elif ch in ",]":
            v = cur if quoted else cur.strip()
            if v or quoted:
                items.append(int(v) if not quoted and re.fullmatch(r"-?\d+", v) else v)
            cur, quoted = "", False
            if ch == "]":
                items = stack.pop() if stack else out
        else:
            cur += ch
    return out


def parse_yaml(text):
    lines = []
    for raw in text.splitlines():
        if raw.strip() == "---":
            continue
        line = _strip_comment(raw)
        if not line.strip():
            continue
        ind = len(line) - len(line.lstrip(" "))
        if line[ind] == "\t":
            raise ValueError("tabs are not allowed for indentation")
        body = line.strip()
        if body.startswith("- ") and _key_split(body[2:].strip()):
            rest = body[2:]
            off = len(rest) - len(rest.lstrip())
            lines.append((ind, "-"))
            lines.append((ind + 2 + off, rest.strip()))
        else:
            lines.append((ind, body))
    if not lines:
        return {}
    val, i = _block(lines, 0, lines[0][0])
    if i != len(lines):
        raise ValueError("bad indentation near: %s" % lines[i][1])
    return val


def _is_item(b):
    return b == "-" or b.startswith("- ")


def _block(lines, i, ind):
    return (_list if _is_item(lines[i][1]) else _map)(lines, i, ind)


def _child(lines, i, ind, allow_same_list):
    if i < len(lines) and (lines[i][0] > ind or (allow_same_list and lines[i][0] == ind and _is_item(lines[i][1]))):
        return _block(lines, i, lines[i][0])
    return None, i


def _map(lines, i, ind):
    d = {}
    while i < len(lines) and lines[i][0] == ind and not _is_item(lines[i][1]):
        kv = _key_split(lines[i][1])
        if not kv:
            raise ValueError("expected 'key: value', got: %s" % lines[i][1])
        k, rest = kv
        i += 1
        if rest:
            d[k] = _scalar(rest)
        else:
            d[k], i = _child(lines, i, ind, True)
    return d, i


def _list(lines, i, ind):
    out = []
    while i < len(lines) and lines[i][0] == ind and _is_item(lines[i][1]):
        body = lines[i][1][1:].strip()
        i += 1
        if body:
            out.append(_scalar(body))
        else:
            v, i = _child(lines, i, ind, False)
            out.append(v)
    return out, i


# ---------------------------------------------------------------- config

def config_path(cwd=None):
    env = os.environ.get("GUARDRAILS_CONFIG")
    if env:
        return env
    if cwd:
        p = os.path.join(cwd, PROJECT_CONFIG)
        if os.path.isfile(p):
            return p
    return DEFAULT_CONFIG


def load_config(cwd=None):
    p = config_path(cwd)
    with open(p, encoding="utf-8") as f:
        cfg = parse_yaml(f.read()) or {}
    cfg["_path"] = p
    return cfg


# ---------------------------------------------------------------- paths

def _norm(p, cwd=None):
    p = os.path.expanduser(os.path.expandvars(p))
    if cwd and not os.path.isabs(p):
        p = os.path.join(cwd, p)
    p = os.path.normpath(os.path.abspath(p)).replace("\\", "/")
    return p.lower() if os.name == "nt" else p


def _pat(pattern):
    if "/" not in pattern:
        return None
    return _norm(pattern).replace("**", "*")


def path_verdict(path, cfg, cwd=None, key="deny_read"):
    """Return (blocked, reason) for touching `path` under list `key`."""
    full = _norm(path, cwd)
    base = full.rsplit("/", 1)[-1]
    ci = os.name == "nt"

    def hit(pats):
        for pat in pats or []:
            pp = _pat(pat)
            if pp is not None:
                if fnmatch.fnmatchcase(full, pp):
                    return pat
            elif fnmatch.fnmatchcase(base, pat.lower() if ci else pat):
                return pat
        return None

    pat = hit(cfg.get(key))
    if pat and not hit(cfg.get("allow_read")):
        verb = "read" if key == "deny_read" else "change"
        return True, "%s matches the %s rule '%s' in %s. Agents may not %s it; ask the user to do it." % (
            path, key, pat, os.path.basename(cfg.get("_path", "guardrails.yaml")), verb)
    return False, ""


# ---------------------------------------------------------------- commands

def _newlines_to_semicolons(cmd):
    out, q, esc = [], None, False
    for ch in cmd:
        if esc:
            esc = False
        elif ch == "\\" and q != "'":
            esc = True
        elif q:
            if ch == q:
                q = None
        elif ch in "'\"":
            q = ch
        elif ch == "\n":
            ch = ";"
        out.append(ch)
    return "".join(out)


def split_segments(cmd, powershell=False):
    """-> list of (argv, op_before). Quoted text stays one token."""
    text = _newlines_to_semicolons(cmd)
    try:
        lex = shlex.shlex(text, posix=True, punctuation_chars=";&|")
        lex.whitespace_split = True
        if powershell or os.name == "nt":
            lex.escape = ""
        toks = list(lex)
    except ValueError:
        toks = text.split()
    segs, cur, op = [], [], None
    for t in toks:
        if t and set(t) <= set(";&|"):
            if cur:
                segs.append((cur, op))
            cur, op = [], t
        else:
            cur.append(t)
    if cur:
        segs.append((cur, op))
    return segs


# wrapper -> its options that take a value; positional = leading non-option args it eats
WRAPPERS = {
    "sudo": ({"-u", "-g", "-C", "-h", "-p", "-r", "-t", "-U", "-D"}, 0),
    "doas": ({"-u", "-C"}, 0),
    "env": ({"-u", "-C", "-S", "--unset", "--chdir"}, 0),
    "nice": ({"-n", "--adjustment"}, 0),
    "timeout": ({"-s", "-k", "--signal", "--kill-after"}, 1),
    "xargs": ({"-I", "-n", "-P", "-L", "-d", "-E", "-s", "-a"}, 0),
    "nohup": (set(), 0), "time": (set(), 0), "command": (set(), 0), "exec": (set(), 0),
    "stdbuf": ({"-i", "-o", "-e"}, 0), "ionice": ({"-c", "-n"}, 0),
}
KEYWORDS = {"if", "then", "else", "elif", "do", "while", "until", "!", "{", "}", "fi", "done", "time"}
SHELLS_C = {"sh", "bash", "zsh", "dash", "ksh"}
PWSH = {"powershell", "pwsh"}
# Programs whose file arguments are read and shown to the agent.
READERS = {"cat", "less", "more", "head", "tail", "bat", "batcat", "strings", "xxd", "od", "hexdump",
           "base64", "nl", "tac", "type", "get-content", "gc", "grep", "egrep", "fgrep", "rg", "ag",
           "awk", "sed", "jq", "yq", "source", ".", "select-string", "sls", "findstr", "diff", "vim", "vi",
           "nano", "code", "scp", "curl"}
PATTERN_FIRST = {"grep", "egrep", "fgrep", "rg", "ag", "awk", "sed", "jq", "yq", "findstr"}


def _prog(tok):
    p = tok.replace("\\", "/").rsplit("/", 1)[-1].lower()
    return p[:-4] if p.endswith(".exe") else p


def _unwrap(argv):
    """Strip VAR=x prefixes, shell keywords and wrappers. Returns (argv, nested_command|None)."""
    argv = [a for a in argv]
    while argv and argv[0].startswith("("):
        argv[0] = argv[0].lstrip("(")
        if not argv[0]:
            argv.pop(0)
    argv = [a.rstrip(")") if a.endswith(")") and "(" not in a else a for a in argv]
    i = 0
    while i < len(argv):
        t = argv[i]
        if re.match(r"^[A-Za-z_][A-Za-z0-9_]*=", t) or t in KEYWORDS:
            i += 1
        elif _prog(t) in WRAPPERS:
            with_val, positional = WRAPPERS[_prog(t)]
            i += 1
            while i < len(argv) and argv[i].startswith("-"):
                i += 2 if argv[i] in with_val else 1
            while i < len(argv) and re.match(r"^[A-Za-z_][A-Za-z0-9_]*=", argv[i]):
                i += 1
            i += positional
        else:
            break
    argv = argv[i:]
    if not argv:
        return argv, None
    p = _prog(argv[0])
    if p in SHELLS_C or p == "eval":
        for j, a in enumerate(argv[1:], 1):
            if p == "eval":
                return argv, " ".join(argv[1:])
            if a.startswith("-") and "c" in a[1:] and not a.startswith("--") and j + 1 < len(argv):
                return argv, argv[j + 1]
    if p in PWSH:
        for j, a in enumerate(argv[1:], 1):
            if a.lower() in ("-c", "-command") and j + 1 < len(argv):
                return argv, " ".join(argv[j + 1:])
    return argv, None


def _flag_present(want, flags, ci, prefix):
    for x in flags:
        xx = x.split("=", 1)[0]
        a, b = (xx.lower(), want.lower()) if ci else (xx, want)
        if a == b:
            return True
        if prefix and len(a) >= 2 and a != "-" and b.startswith(a):
            return True
        # short-flag cluster: -f inside -rf / -fu
        if (len(want) == 2 and want[0] == "-" and want[1] != "-" and not x.startswith("--")
                and len(x) > 2 and x[1:].isalpha() and want[1] in x[1:]):
            return True
    return False


GIT_GLOBAL_WITH_VALUE = {"-C", "-c", "--git-dir", "--work-tree", "--namespace"}


def rule_matches(rule, argv):
    cmd = rule.get("command") or []
    if not cmd or not argv:
        return False
    ci = bool(rule.get("ignore_case"))
    progs = cmd[0] if isinstance(cmd[0], list) else [cmd[0]]
    if _prog(argv[0]) not in [p.lower() for p in progs]:
        return False
    rest = argv[1:]
    if len(cmd) > 1:
        j = 0
        while j < len(rest) and rest[j].startswith("-"):
            j += 2 if rest[j] in GIT_GLOBAL_WITH_VALUE else 1
        sub = rest[j:j + len(cmd) - 1]
        want = cmd[1:]
        if ci:
            sub, want = [s.lower() for s in sub], [w.lower() for w in want]
        if sub != want:
            return False
        rest = rest[j + len(cmd) - 1:]
    flags = [a for a in rest if a.startswith("-") and a != "-"]
    args = [a for a in rest if not a.startswith("-") or a == "-"]
    for group in rule.get("flags") or []:
        group = group if isinstance(group, list) else [group]
        if not any(_flag_present(g, flags, ci, bool(rule.get("prefix"))) for g in group):
            return False
    norm = [a.replace("\\", "/") for a in args]
    pats = rule.get("args")
    if pats and not any(fnmatch.fnmatchcase(a.lower() if ci else a, p.lower() if ci else p)
                        for a in norm for p in pats):
        return False
    rx = rule.get("args_regex")
    if rx and not any(re.search(r, a, re.I if ci else 0) for a in norm for r in rx):
        return False
    return True


def _reads(argv):
    """File arguments a reader program will show to the agent."""
    p = _prog(argv[0])
    if p not in READERS:
        return []
    out, skipped_pattern = [], p not in PATTERN_FIRST
    for tok in argv[1:]:
        t = tok.lstrip("<@")
        if t.startswith("-"):
            if "=" in t:
                out.append(t.split("=", 1)[1])
            continue
        if not skipped_pattern:
            skipped_pattern = True
            continue
        if t and "\n" not in t:
            out.append(t)
    return out


def check_command(cmd, cfg, cwd=None, powershell=False, _depth=0):
    """Return (blocked, rule_id, reason)."""
    segs = split_segments(cmd, powershell)
    unwrapped = []
    for argv, op in segs:
        argv, nested = _unwrap(argv)
        if nested and _depth < 3:
            r = check_command(nested, cfg, cwd, powershell, _depth + 1)
            if r[0]:
                return r
        unwrapped.append((argv, op))
    pipe = cfg.get("pipe_to_shell") or {}
    for k, (argv, op) in enumerate(unwrapped):
        if not argv:
            continue
        for rule in cfg.get("deny_commands") or []:
            if rule_matches(rule, argv):
                return True, rule.get("id", "rule"), "Blocked by rule '%s': %s" % (
                    rule.get("id", "rule"), rule.get("reason", "destructive command"))
        if pipe:
            frm = [p.lower() for p in pipe.get("from", [])]
            to = [p.lower() for p in pipe.get("to", [])]
            why = "Blocked by rule 'pipe-to-shell': %s" % pipe.get("reason", "download the script, read it, then run it")
            # curl ... | [tee ... |] sh  : any later segment of the same pipeline
            if _prog(argv[0]) in frm:
                for argv2, op2 in unwrapped[k + 1:]:
                    if op2 != "|":
                        break
                    if argv2 and _prog(argv2[0]) in to:
                        return True, "pipe-to-shell", why
            # bash -c "$(curl ...)", bash <(curl ...), iex (irm ...)
            if _prog(argv[0]) in to or _prog(argv[0]) in SHELLS_C:
                for tok in argv[1:]:
                    for piece in re.split(r"[\s\"']+", tok):
                        if _prog(piece.lstrip("$<(`")) in frm and piece[:1] in "$<(`":
                            return True, "pipe-to-shell", why
        for t in _reads(argv):
            blocked, why = path_verdict(t, cfg, cwd)
            if blocked:
                return True, "deny-read", why
        # The project's own rules file: no shell edits either. Readers may look
        # at it (sed and awk excepted: they edit in place); a redirect into it never.
        reader = _prog(argv[0]) in READERS - {"sed", "awk"}
        prev = ""
        for tok in argv[1:]:
            redirect = tok.startswith(">") or prev in (">", ">>", "1>", "2>")
            prev = tok
            t = tok.lstrip("<>&|0123456789")
            if t and (redirect or not reader):
                blocked, why = path_verdict(t, cfg, cwd, "deny_write")
                if blocked:
                    return True, "deny-write", why
    return False, "", ""


# ---------------------------------------------------------------- state

def home():
    h = os.environ.get("GUARDRAILS_HOME") or os.path.join(os.path.expanduser("~"), ".agent-guardrails")
    os.makedirs(h, exist_ok=True)
    return h


class _Mutex:
    def __init__(self):
        self.p = os.path.join(home(), "locks.json.lock")

    def __enter__(self):
        deadline = time.time() + 3
        while True:
            try:
                self.fd = os.open(self.p, os.O_CREAT | os.O_EXCL | os.O_WRONLY)
                return self
            except FileExistsError:
                try:
                    if time.time() - os.path.getmtime(self.p) > 10:
                        os.remove(self.p)
                        continue
                except OSError:
                    continue  # the holder just released it: try again at once
                if time.time() > deadline:
                    raise TimeoutError("lock store busy")
                time.sleep(0.02)

    def __exit__(self, *a):
        os.close(self.fd)
        try:
            os.remove(self.p)
        except OSError as e:
            # A leftover mutex is cleared as stale after 10 s; say so rather than hide it.
            sys.stderr.write("guardrails: could not remove %s: %s\n" % (self.p, e))


def _store():
    return os.path.join(home(), "locks.json")


def _read_locks():
    try:
        with open(_store(), encoding="utf-8") as f:
            locks = json.load(f)
    except (OSError, ValueError):
        locks = {}
    now = time.time()
    return {k: v for k, v in locks.items() if v.get("expires", 0) > now}


def _write_locks(locks):
    tmp = _store() + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(locks, f, indent=1)
    os.replace(tmp, _store())


def acquire(path, owner, ttl_minutes=30, note="", cwd=None, max_ttl=120):
    key = _norm(path, cwd)
    ttl = max(1.0, min(float(ttl_minutes or 30), float(max_ttl)))
    with _Mutex():
        locks = _read_locks()
        cur = locks.get(key)
        if cur and cur["owner"] != owner:
            return False, cur
        locks[key] = {"path": key, "owner": owner, "note": note or (cur or {}).get("note", ""),
                      "since": (cur or {}).get("since", time.time()), "expires": time.time() + ttl * 60}
        _write_locks(locks)
        return True, locks[key]


def release(path, owner, cwd=None):
    key = _norm(path, cwd)
    with _Mutex():
        locks = _read_locks()
        cur = locks.get(key)
        if not cur or (owner is not None and cur["owner"] != owner):
            return False
        del locks[key]
        _write_locks(locks)
        return True


def release_owner(owner):
    with _Mutex():
        locks = _read_locks()
        keep = {k: v for k, v in locks.items() if v["owner"] != owner}
        _write_locks(keep)
        return len(locks) - len(keep)


def list_locks():
    with _Mutex():
        return sorted(_read_locks().values(), key=lambda v: v["path"])


def _hhmm(ts):
    return time.strftime("%H:%M", time.localtime(ts))


def lock_reason(path, cur):
    return ("%s is locked by %s until %s%s. Another agent is editing it: work on something else, "
            "or ask the user. A human can free it with: guardrails.py unlock \"%s\"" % (
                path, cur["owner"], _hhmm(cur["expires"]),
                (" (" + cur["note"] + ")") if cur.get("note") else "", path))


def log(event):
    try:
        event["ts"] = time.strftime("%Y-%m-%dT%H:%M:%S")
        p = os.path.join(home(), "decisions.jsonl")
        with open(p, "a", encoding="utf-8") as f:
            f.write(json.dumps(event) + "\n")
        if os.path.getsize(p) > 512 * 1024:
            with open(p, encoding="utf-8") as f:
                tail = f.readlines()[-500:]
            with open(p, "w", encoding="utf-8") as f:
                f.writelines(tail)
    except OSError as e:
        sys.stderr.write("guardrails: decision log not written: %s\n" % e)


# ---------------------------------------------------------------- one decision for any agent

READ_TOOLS = {"Read": "file_path", "Grep": "path", "NotebookRead": "notebook_path"}
EDIT_TOOLS = {"Edit": "file_path", "Write": "file_path", "MultiEdit": "file_path",
              "NotebookEdit": "notebook_path"}
SHELL_TOOLS = {"Bash": False, "PowerShell": True}


def decide(tool, tool_input, owner, cwd, cfg):
    """Return (blocked, reason, rule). tool is a Claude Code tool name."""
    ti = tool_input or {}
    if tool in SHELL_TOOLS:
        b, rid, why = check_command(ti.get("command", ""), cfg, cwd, SHELL_TOOLS[tool])
        return b, why, rid
    if tool == "apply_patch":  # Codex: file names sit inside the patch text
        text = " ".join(v for v in ti.values() if isinstance(v, str)) if isinstance(ti, dict) else str(ti)
        for path in re.findall(r"^\*\*\* (?:Update|Add|Delete) File: (.+)$", text, re.M):
            r = decide("Edit", {"file_path": path.strip()}, owner, cwd, cfg)
            if r[0]:
                return r
        return False, "", ""
    path = ti.get(READ_TOOLS.get(tool) or EDIT_TOOLS.get(tool) or "", "")
    if not path:
        return False, "", ""
    b, why = path_verdict(path, cfg, cwd)
    if b:
        return True, why, "deny-read"
    if tool in EDIT_TOOLS:
        b, why = path_verdict(path, cfg, cwd, "deny_write")
        if b:
            return True, why, "deny-write"
        lk = cfg.get("locks") or {}
        if lk.get("auto_lock_on_edit", True):
            ok, cur = acquire(path, owner, lk.get("auto_ttl_minutes", 10), "editing", cwd,
                              lk.get("max_ttl_minutes", 120))
            if not ok:
                return True, lock_reason(path, cur), "lock"
    return False, "", ""


# ---------------------------------------------------------------- hook adapters

def _stdin_json():
    try:
        raw = sys.stdin.buffer.read().decode("utf-8", "replace")  # Windows defaults to cp1252
        return json.loads(raw or "{}")
    except ValueError:
        return {}


def _agent_name(p):
    for i, a in enumerate(sys.argv):
        if a == "--agent" and i + 1 < len(sys.argv):
            return sys.argv[i + 1]
    return "codex" if "turn_id" in p else "claude"


def claude_hook():
    """PreToolUse hook. Claude Code and Codex CLI share this payload and output."""
    p = _stdin_json()
    if p.get("hook_event_name") == "SessionEnd":
        return claude_end(p)
    sid = p.get("session_id") or os.environ.get("CLAUDE_CODE_SESSION_ID") or "unknown"
    cwd = p.get("cwd") or os.getcwd()
    cfg = load_config(cwd)
    tool = p.get("tool_name", "")
    agent = _agent_name(p)
    ti = p.get("tool_input")
    if isinstance(ti, str):
        try:
            ti = json.loads(ti)
        except ValueError:
            ti = {"input": ti}
    blocked, why, rule = decide(tool, ti, "%s:%s" % (agent, sid[:8]), cwd, cfg)
    log({"agent": agent, "tool": tool, "blocked": blocked, "rule": rule})
    if blocked:
        print(json.dumps({"hookSpecificOutput": {
            "hookEventName": "PreToolUse", "permissionDecision": "deny",
            "permissionDecisionReason": "Guardrails: " + why}}))
    return 0


def claude_end(p=None):
    p = p if p is not None else _stdin_json()
    sid = p.get("session_id") or os.environ.get("CLAUDE_CODE_SESSION_ID")
    if sid:
        release_owner("%s:%s" % (_agent_name(p), sid[:8]))
    return 0


def cursor_hook():
    """Cursor hooks: beforeShellExecution, beforeReadFile, afterFileEdit."""
    p = _stdin_json()
    ev = p.get("hook_event_name", "")
    cwd = (p.get("workspace_roots") or [None])[0] or p.get("cwd") or os.getcwd()
    cfg = load_config(cwd)
    owner = "cursor:" + str(p.get("conversation_id", "unknown"))[:8]
    blocked, why = False, ""
    if ev == "beforeShellExecution":
        blocked, _, why = check_command(p.get("command", ""), cfg, p.get("cwd") or cwd)
    elif ev == "beforeReadFile":
        blocked, why = path_verdict(p.get("file_path", ""), cfg, cwd)
    elif ev == "afterFileEdit":
        # Cursor cannot block an edit before it happens; take the lock so
        # other agents are stopped, and warn if someone else held it.
        ok, cur = acquire(p.get("file_path", ""), owner, 10, "editing", cwd)
        if not ok:
            log({"agent": "cursor", "event": ev, "blocked": False, "rule": "lock-overlap"})
        return 0
    log({"agent": "cursor", "event": ev, "blocked": blocked})
    if ev in ("beforeShellExecution", "beforeReadFile"):
        out = {"permission": "deny" if blocked else "allow"}
        if blocked:
            out["user_message"] = "Guardrails: " + why
            if ev == "beforeShellExecution":  # beforeReadFile takes no agent_message
                out["agent_message"] = "Guardrails: " + why
        print(json.dumps(out))
    return 0


# ---------------------------------------------------------------- MCP server

TOOLS = [
    {"name": "acquire_lock",
     "description": "Lock a file before editing it so other agents do not edit it at the same time. "
                    "Returns ok=false with the holder if another agent holds it. Re-acquiring your own lock renews it.",
     "inputSchema": {"type": "object", "required": ["path", "owner"], "properties": {
         "path": {"type": "string"}, "owner": {"type": "string", "description": "a stable name for you, e.g. codex-auth-refactor"},
         "ttl_minutes": {"type": "integer", "default": 30}, "note": {"type": "string"}}}},
    {"name": "release_lock", "description": "Release a lock you hold.",
     "inputSchema": {"type": "object", "required": ["path", "owner"], "properties": {
         "path": {"type": "string"}, "owner": {"type": "string"}}}},
    {"name": "list_locks", "description": "List live locks held by any agent.",
     "inputSchema": {"type": "object", "properties": {}}},
    {"name": "check_command",
     "description": "Ask whether a shell command is allowed by the guardrails before running it.",
     "inputSchema": {"type": "object", "required": ["command"], "properties": {
         "command": {"type": "string"}, "shell": {"type": "string", "enum": ["bash", "powershell"]},
         "cwd": {"type": "string"}}}},
    {"name": "check_path", "description": "Ask whether reading a file is allowed (secrets are not).",
     "inputSchema": {"type": "object", "required": ["path"], "properties": {
         "path": {"type": "string"}, "cwd": {"type": "string"}}}},
]


def mcp_call(name, a):
    cwd = a.get("cwd") or os.getcwd()
    if name == "acquire_lock":
        cfg = load_config(cwd)
        ok, cur = acquire(a["path"], a["owner"], a.get("ttl_minutes", 30), a.get("note", ""), cwd,
                          (cfg.get("locks") or {}).get("max_ttl_minutes", 120))
        res = {"ok": ok, "lock": cur} if ok else {"ok": False, "holder": cur, "reason": lock_reason(a["path"], cur)}
    elif name == "release_lock":
        res = {"released": release(a["path"], a["owner"], cwd)}
    elif name == "list_locks":
        res = {"locks": list_locks()}
    elif name == "check_command":
        b, rid, why = check_command(a["command"], load_config(cwd), cwd, a.get("shell") == "powershell")
        res = {"allowed": not b, "rule": rid, "reason": why}
    elif name == "check_path":
        b, why = path_verdict(a["path"], load_config(cwd), cwd)
        res = {"allowed": not b, "reason": why}
    else:
        raise KeyError(name)
    log({"agent": "mcp", "tool": name, "blocked": res.get("allowed") is False or res.get("ok") is False})
    return res


def mcp_handle(msg):
    mid, method = msg.get("id"), msg.get("method", "")
    if mid is None:
        return None  # notification
    if method == "initialize":
        result = {"protocolVersion": (msg.get("params") or {}).get("protocolVersion", "2025-06-18"),
                  "capabilities": {"tools": {}},
                  "serverInfo": {"name": "agent-guardrails", "version": VERSION}}
    elif method == "ping":
        result = {}
    elif method == "tools/list":
        result = {"tools": TOOLS}
    elif method == "tools/call":
        prm = msg.get("params") or {}
        try:
            res = mcp_call(prm.get("name"), prm.get("arguments") or {})
            result = {"content": [{"type": "text", "text": json.dumps(res)}], "structuredContent": res, "isError": False}
        except KeyError as e:
            return {"jsonrpc": "2.0", "id": mid, "error": {"code": -32602, "message": "unknown tool or missing argument: %s" % e}}
        except Exception as e:  # report, do not crash the server
            result = {"content": [{"type": "text", "text": "error: %s" % e}], "isError": True}
    else:
        return {"jsonrpc": "2.0", "id": mid, "error": {"code": -32601, "message": "method not found: " + method}}
    return {"jsonrpc": "2.0", "id": mid, "result": result}


def mcp_serve():
    for line in sys.stdin:
        line = line.strip()
        if not line:
            continue
        try:
            msg = json.loads(line)
            if not isinstance(msg, dict):
                raise ValueError("not a JSON-RPC object")
            reply = mcp_handle(msg)
        except ValueError as e:
            reply = {"jsonrpc": "2.0", "id": None, "error": {"code": -32700, "message": "parse error: %s" % e}}
        except Exception as e:  # never let one bad message kill the server
            reply = {"jsonrpc": "2.0", "id": msg.get("id") if isinstance(msg, dict) else None,
                     "error": {"code": -32603, "message": "internal error: %s" % e}}
        if reply is not None:
            sys.stdout.write(json.dumps(reply) + "\n")
            sys.stdout.flush()
    return 0


# ---------------------------------------------------------------- CLI

def health():
    cfg = load_config(os.getcwd())
    print("guardrails %s  config: %s" % (VERSION, cfg["_path"]))
    print("rules: %d command rules, %d deny_read patterns, auto-lock on edit: %s" % (
        len(cfg.get("deny_commands") or []), len(cfg.get("deny_read") or []),
        (cfg.get("locks") or {}).get("auto_lock_on_edit", True)))
    p = os.path.join(home(), "decisions.jsonl")
    if not os.path.exists(p):
        print("The guard has never run. If you installed the hook, it is not wired.")
        return 0
    with open(p, encoding="utf-8") as f:
        rows = [json.loads(x) for x in f.readlines()[-10:] if x.strip()]
    for r in rows:
        print("  %s %-7s %-14s %s %s" % (r.get("ts"), r.get("agent"), r.get("tool") or r.get("event", ""),
                                         "BLOCKED" if r.get("blocked") else "allowed", r.get("rule", "")))
    print("live locks: %d" % len(list_locks()))
    return 0


def main(argv):
    mode = argv[1] if len(argv) > 1 else ""
    hooks = {"hook": claude_hook, "end": claude_end, "cursor-hook": cursor_hook}
    if mode in hooks:
        try:
            return hooks[mode]()
        except Exception as e:  # fail open: a broken guard must never stop work, but say so
            log({"agent": mode, "error": repr(e)[:300]})
            msg = "Guardrails is OFF for this call (%s). Fix it, then check with: guardrails.py health" % (
                repr(e)[:200])
            if mode == "hook":
                print(json.dumps({"systemMessage": msg}))
            elif mode == "cursor-hook":
                print(json.dumps({"permission": "allow", "user_message": msg}))
            return 0
    if mode == "mcp":
        return mcp_serve()
    if mode == "check-command":
        b, rid, why = check_command(" ".join(argv[2:]), load_config(os.getcwd()), os.getcwd())
        print("BLOCKED: " + why if b else "allowed")
        return 1 if b else 0
    if mode == "check-path":
        b, why = path_verdict(argv[2], load_config(os.getcwd()), os.getcwd())
        print("BLOCKED: " + why if b else "allowed")
        return 1 if b else 0
    if mode == "locks":
        for v in list_locks():
            print("%s  %s  until %s  %s" % (v["path"], v["owner"], _hhmm(v["expires"]), v.get("note", "")))
        return 0
    if mode == "unlock":
        print("released" if release(argv[2], None, os.getcwd()) else "no lock on that path")
        return 0
    if mode == "health":
        return health()
    print(__doc__)
    return 0 if mode in ("", "-h", "--help") else 64


if __name__ == "__main__":
    sys.exit(main(sys.argv))
