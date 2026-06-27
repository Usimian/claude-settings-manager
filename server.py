#!/usr/bin/env python3
"""
Claude Settings Manager — a local web app to audit and edit Claude Code
permission rules across the whole settings hierarchy.

Zero external dependencies: pure Python stdlib (http.server) backend that
serves index.html and a small JSON API. Run with `./start.sh` or
`python3 server.py [--port 8787] [--root ~]`.

Settings precedence (highest wins for scalar keys; permission rule arrays are
unioned and then evaluated deny > ask > allow):

    managed  >  project-local  >  project-shared  >  user-local  >  user
"""

import argparse
import json
import os
import re
import shutil
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlparse

HERE = Path(__file__).resolve().parent

# Scope metadata: key -> (label, precedence rank). Higher rank = higher precedence.
SCOPES = {
    "managed": ("Managed (enterprise)", 50),
    "project-local": ("Project local", 40),
    "project-shared": ("Project shared", 30),
    "user-local": ("User local", 20),
    "user": ("User (global)", 10),
}

RULE_TYPES = ("deny", "ask", "allow")  # evaluation order: first match wins

# Directories we never descend into when hunting for project settings.
PRUNE = {
    "node_modules", ".venv", "venv", "site-packages", "build", "install",
    ".git", "__pycache__", ".cache", "dist", ".tox", "log",
}

MANAGED_CANDIDATES = [
    Path("/etc/claude-code/managed-settings.json"),
    Path("/Library/Application Support/ClaudeCode/managed-settings.json"),
]


# --------------------------------------------------------------------------- #
# Discovery
# --------------------------------------------------------------------------- #
def discover_files(root: Path):
    """Return a list of {path, scope, project} dicts for every settings file."""
    root = root.expanduser().resolve()
    files = []

    # Global / user scope
    user_dir = root / ".claude"
    _add(files, user_dir / "settings.json", "user", "(global)")
    _add(files, user_dir / "settings.local.json", "user-local", "(global)")

    # Managed
    for mc in MANAGED_CANDIDATES:
        _add(files, mc, "managed", "(managed)")

    # Project scope: <root>/*/.claude and <root>/*/*/.claude (depth-limited)
    seen = {f["path"] for f in files}
    for claude_dir in _find_project_claude_dirs(root):
        project = claude_dir.parent.name
        for name, scope in (("settings.json", "project-shared"),
                            ("settings.local.json", "project-local")):
            p = claude_dir / name
            if p.exists() and str(p) not in seen:
                _add(files, p, scope, project)
                seen.add(str(p))
    return files


def _find_project_claude_dirs(root: Path, max_depth: int = 3):
    """Walk root up to max_depth dirs deep, pruning heavy dirs, find .claude dirs."""
    results = []
    root_depth = len(root.parts)
    for dirpath, dirnames, _files in os.walk(root):
        depth = len(Path(dirpath).parts) - root_depth
        if depth >= max_depth:
            dirnames[:] = []
            continue
        # Keep .claude (we look for it by name just below) plus ordinary,
        # non-hidden, non-heavy dirs. Parenthesised so the intent is unambiguous.
        dirnames[:] = [d for d in dirnames
                       if d == ".claude" or (d not in PRUNE and not d.startswith("."))]
        if ".claude" in dirnames:
            cd = Path(dirpath) / ".claude"
            # skip the user-global one (handled above)
            if cd != (root / ".claude"):
                results.append(cd)
    return results


def _add(files, path: Path, scope: str, project: str):
    if path.exists():
        files.append({"path": str(path), "scope": scope, "project": project})


# --------------------------------------------------------------------------- #
# Parsing
# --------------------------------------------------------------------------- #
RULE_RE = re.compile(r"^(?P<tool>[A-Za-z_]+)(?:\((?P<pattern>.*)\))?$")


def parse_rule(raw: str):
    """Split 'Bash(git log:*)' -> ('Bash', 'git log:*'). Pattern None if absent."""
    m = RULE_RE.match(raw.strip())
    if not m:
        return raw.strip(), None
    return m.group("tool"), m.group("pattern")


def load_json(path: str):
    try:
        with open(path) as f:
            return json.load(f)
    except (json.JSONDecodeError, OSError):
        return None


def collect_rules(files):
    """Flatten all permission rules across all files into a list of rule dicts."""
    rules = []
    rid = 0
    for fmeta in files:
        data = load_json(fmeta["path"])
        if not data:
            continue
        perms = data.get("permissions")
        if not isinstance(perms, dict):
            continue
        for rtype in RULE_TYPES:
            arr = perms.get(rtype)
            if not isinstance(arr, list):
                continue
            for raw in arr:
                if not isinstance(raw, str):
                    continue
                tool, pattern = parse_rule(raw)
                rules.append({
                    "id": rid,
                    "raw": raw,
                    "tool": tool,
                    "pattern": pattern,
                    "type": rtype,
                    "scope": fmeta["scope"],
                    "scope_label": SCOPES[fmeta["scope"]][0],
                    "scope_rank": SCOPES[fmeta["scope"]][1],
                    "project": fmeta["project"],
                    "file": fmeta["path"],
                })
                rid += 1
    return rules


# --------------------------------------------------------------------------- #
# Coverage / shadowing logic
# --------------------------------------------------------------------------- #
def covers(broad, narrow):
    """Does a same-tool rule with `broad` pattern subsume the `narrow` one?

    Coverage requires a real boundary so that `ls:*` does NOT swallow `lsblk:*`
    and `pip:*` does NOT swallow `pip3:*` — those are different commands.
    """
    if broad is None:
        return True  # tool-level rule (e.g. "Bash") covers everything for that tool
    if narrow is None:
        return False
    if broad == narrow:
        return True
    # path glob: "//home/marc/**" covers "//home/marc/.claude/**"
    if broad.endswith("/**"):
        p = broad[:-3]
        return narrow == p or narrow.startswith(p + "/")
    # command prefix: "git log:*" covers "git log --oneline" but not "git logfoo"
    if broad.endswith(":*"):
        p = broad[:-2]
        return narrow == p or narrow.startswith(p + " ") or narrow.startswith(p + ":")
    # generic trailing wildcard (rare)
    if broad.endswith("*"):
        return narrow.startswith(broad[:-1])
    return False


def rule_key(r):
    return (r["type"], r["tool"], r["pattern"])


# --------------------------------------------------------------------------- #
# Danger classification — "what can auto-run, and could it hurt?"
# --------------------------------------------------------------------------- #
SEV_RANK = {"critical": 0, "high": 1, "medium": 2, "low": 3}

PRIV = {"sudo", "doas", "pkexec"}
GENERIC_WRAP = {"env", "time", "nice", "ionice", "nohup", "timeout",
                "watch", "stdbuf", "setsid", "unbuffer"}
SHELLS = {"bash", "sh", "zsh", "dash", "ksh", "fish", "csh", "tcsh"}
INTERP = {"python", "python3", "node", "nodejs", "ruby", "perl", "php",
          "lua", "deno", "bun", "rscript"}
BUILD = {"make", "cmake", "ninja", "gcc", "g++", "clang", "clang++", "rustc",
         "go", "cargo", "colcon", "pio", "platformio", "meson", "bazel"}


def _worse(a, b):
    """Return the higher-severity of two (sev, cat, why) tuples (or the non-None one)."""
    if a is None:
        return b
    if b is None:
        return a
    return a if SEV_RANK[a[0]] <= SEV_RANK[b[0]] else b


def _strip_opts(toks):
    """Drop leading option / VAR=val / numeric tokens (for wrappers like env, timeout)."""
    i = 0
    while i < len(toks) and (toks[i].startswith("-") or "=" in toks[i] or toks[i].isdigit()):
        i += 1
    return toks[i:]


def classify_command(head, depth=0):
    """Classify a bash command string -> (severity, category, why) or None if benign.

    Recurses through wrappers (sudo, ssh <host>, xargs, env, …) so that
    `sudo rm` is critical and `ssh host cat` is harmless.
    """
    WILDCARD = ("critical", "shell-wildcard",
                "Allows ANY bash command with no prompt (rm, sudo, dd, …)")
    if depth > 4:
        return None
    if head is None:
        return WILDCARD
    head = head.strip()
    if head in ("", "*", ":*"):
        return WILDCARD
    # strip a trailing prefix-wildcard so "rm:*" and "ssh rider *" classify on the real command
    if head.endswith(":*"):
        head = head[:-2].strip()
    elif head.endswith(" *"):
        head = head[:-2].strip()
    elif head.endswith("*"):
        head = head[:-1].strip()
    if not head:
        return WILDCARD
    toks = head.split()
    base = toks[0].rsplit("/", 1)[-1].lower()
    rest = toks[1:]

    # privilege escalation — recurse into the elevated command
    if base == "su":
        return ("critical", "privilege-escalation", "Switches user (root by default)")
    if base in PRIV:
        inner = classify_command(" ".join(_strip_opts(rest)), depth + 1) if rest else None
        why = "Runs commands as root" + (f" — inner: {inner[2]}" if inner else "")
        return ("critical", "privilege-escalation", why)

    # remote execution — ssh [opts] host [command...]
    if base in {"ssh", "dbclient"}:
        after = _strip_opts(rest)
        if len(after) >= 2:                       # a remote command is pinned
            inner = classify_command(" ".join(after[1:]), depth + 1)
            if inner:
                return (inner[0], "remote-exec", f"On a remote host: {inner[2]}")
            return ("low", "remote-exec", "Runs a fixed command on a remote host")
        return ("high", "remote-exec", "Runs ANY command on a remote host")

    # generic wrappers — strip and recurse
    if base in GENERIC_WRAP:
        return classify_command(" ".join(_strip_opts(rest)), depth + 1) if rest else None
    if base == "xargs":
        inner = classify_command(" ".join(_strip_opts(rest)), depth + 1) if rest else None
        return _worse(("medium", "arbitrary-exec", "Runs an arbitrary command per input line"), inner)

    sub = rest[0] if rest else ""
    flags = {t for t in toks if t.startswith("-")}
    recursive = any(t in ("-R", "-r", "--recursive") for t in toks)

    if base in {"rm", "rmdir", "shred", "unlink"}:
        hard = recursive or "-f" in flags or "-rf" in toks or "-fr" in toks
        return ("critical", "file-deletion",
                "Deletes files" + (" recursively/forced" if hard else ""))
    if base.startswith("mkfs") or base in {"dd", "fdisk", "parted", "wipefs", "blkdiscard", "sgdisk"}:
        return ("critical", "disk-write", "Can overwrite disks/filesystems")
    if base in {"shutdown", "reboot", "halt", "poweroff"}:
        return ("high", "system-power", "Powers off or reboots the machine")
    if base in {"mount", "umount"}:
        return ("high", "mount", "Mounts/unmounts filesystems")
    if base == "systemctl" and sub in {"start", "stop", "restart", "reload", "enable",
                                       "disable", "mask", "unmask", "kill", "isolate"}:
        return ("high", "service-control", f"systemctl {sub}: controls system services")
    if base == "service" and rest:
        return ("high", "service-control", "Controls system services")
    if base in {"kill", "pkill", "killall"}:
        return ("medium", "process-kill", f"Terminates processes ({base})")
    if base in {"chmod", "chown", "chgrp", "chattr", "setfacl"}:
        return ("high" if recursive else "medium", "permission-change",
                f"Changes permissions/ownership ({base})" + (" recursively" if recursive else ""))
    if base in {"curl", "wget"}:
        return ("high", "network-fetch", "Downloads from the internet (RCE risk if piped to a shell)")
    if base in {"nc", "ncat", "netcat", "socat", "telnet"}:
        return ("high", "network-raw", "Raw network connection / can serve a shell")
    if base in {"iptables", "ip6tables", "nft", "ufw", "firewall-cmd"}:
        return ("high", "network-config", "Changes firewall/network config")
    if base in {"scp", "sftp", "rsync"}:
        return ("medium", "file-transfer", f"Transfers files to/from remote hosts ({base})")
    if base in {"apt", "apt-get", "aptitude", "dpkg", "dnf", "yum", "pacman", "snap", "flatpak", "zypper"}:
        if any(s in toks for s in ("install", "remove", "purge", "reinstall", "autoremove")) or "-i" in flags:
            return ("high", "package-mutation", f"Installs/removes system packages ({base})")
        return None
    if base in {"pip", "pip3", "uv", "pipx", "conda"}:
        if any(s in toks for s in ("install", "uninstall")):
            return ("medium", "package-mutation", f"Installs/removes packages ({base})")
        return None
    if base in {"npm", "yarn", "pnpm"}:
        if any(s in toks for s in ("install", "i", "add", "ci")) or {"-g", "--global"} & flags:
            return ("medium", "package-mutation", f"Installs JS packages ({base})")
        return None
    if base == "git":
        if sub == "push" and ("--force" in toks or "-f" in flags):
            return ("high", "git-destructive", "Force-push can overwrite remote history")
        if sub == "reset" and "--hard" in toks:
            return ("high", "git-destructive", "reset --hard discards local changes")
        if sub == "clean" and any("f" in t for t in flags):
            return ("medium", "git-destructive", "clean -f deletes untracked files")
        if sub in {"rebase", "filter-branch", "filter-repo"}:
            return ("medium", "git-history", "Rewrites git history")
        if sub == "branch" and "-D" in toks:
            return ("low", "git-destructive", "Force-deletes a branch")
        if sub in {"checkout", "restore", "switch"}:
            return ("low", "git-overwrite", "Can overwrite working-tree files")
        return None
    if base in SHELLS:
        return ("high", "arbitrary-exec", f"Runs an arbitrary shell ({base})")
    if base in {"eval", "exec", "source"} or base == ".":
        return ("high", "arbitrary-exec", f"Executes arbitrary code ({base})")
    if base in INTERP:
        return ("medium", "arbitrary-exec", f"Runs arbitrary code via {base}")
    if base in BUILD:
        return ("medium", "build-exec", f"Build tools execute arbitrary code from build files ({base})")
    if base in {"docker", "podman", "nerdctl", "docker-compose"}:
        if sub in {"run", "exec", "compose"}:
            inner = None
            if sub == "exec" and len(rest) >= 3:   # docker exec <container> <cmd...>
                inner = classify_command(" ".join(rest[2:]), depth + 1)
            return _worse(("high", "container",
                           f"Containers run as root & can mount the host ({base} {sub})"), inner)
        if sub == "build":
            return ("medium", "container", "docker build runs arbitrary Dockerfile steps")
        if sub in {"rm", "rmi"}:
            return ("low", "container", "Removes containers/images")
        return None
    if base == "find" and "-delete" in toks:
        return ("high", "file-deletion", "find -delete removes matched files")
    if base == "find" and ("-exec" in toks or "-execdir" in toks):
        return ("high", "arbitrary-exec", "find -exec runs arbitrary commands")
    if base in {"tee", "truncate"}:
        return ("medium", "file-write", f"Writes/overwrites files ({base})")
    if base == "crontab":
        return ("medium", "scheduled-exec", "Schedules commands to run later")
    return None


def classify_rule(r):
    if r["tool"] == "Bash":
        return classify_command(r["pattern"])
    if r["tool"] == "Write":
        return ("high", "file-write", "Writes/overwrites files" + (" anywhere" if r["pattern"] is None else ""))
    if r["tool"] in {"Edit", "MultiEdit"}:
        return ("medium", "file-write", "Modifies files" + (" anywhere" if r["pattern"] is None else ""))
    return None


def build_risk(rules):
    """Flag rules that let something potentially harmful run. Skips `deny` (protective)."""
    out = []
    keep = ("id", "raw", "tool", "pattern", "type", "scope", "scope_label", "project", "file")
    for r in rules:
        if r["type"] == "deny":
            continue
        c = classify_rule(r)
        if not c:
            continue
        sev, cat, why = c
        out.append({**{k: r[k] for k in keep}, "severity": sev, "category": cat, "why": why})
    out.sort(key=lambda x: (SEV_RANK[x["severity"]], 0 if x["type"] == "allow" else 1, x["project"]))
    return out


# --------------------------------------------------------------------------- #
# Suggestions engine
# --------------------------------------------------------------------------- #
def build_suggestions(rules):
    out = []

    # 1. Exact duplicates within the same file
    by_file = {}
    for r in rules:
        by_file.setdefault(r["file"], []).append(r)
    for f, rs in by_file.items():
        seen = {}
        for r in rs:
            k = (r["type"], r["raw"])
            if k in seen:
                out.append({
                    "kind": "duplicate-in-file",
                    "severity": "low",
                    "title": f"Duplicate '{r['raw']}' ({r['type']}) listed twice",
                    "detail": f"in {f}",
                    "rule_ids": [seen[k]["id"], r["id"]],
                })
            else:
                seen[k] = r

    # 2. Same rule across many project files -> promote to global
    proj_rules = [r for r in rules if r["scope"].startswith("project")]
    global_keys = {rule_key(r) for r in rules if r["scope"].startswith("user")}
    groups = {}
    for r in proj_rules:
        groups.setdefault(rule_key(r), []).append(r)
    for key, rs in groups.items():
        files = {r["file"] for r in rs}
        if len(files) >= 3 and key not in global_keys:
            rtype, tool, pattern = key
            out.append({
                "kind": "promote-to-global",
                "severity": "medium",
                "title": f"'{rs[0]['raw']}' ({rtype}) appears in {len(files)} projects",
                "detail": "Consider promoting to ~/.claude/settings.json and removing the copies.",
                "rule_ids": [r["id"] for r in rs],
            })

    # 3. Rule shadowed by a broader same-type rule visible to the same project
    for r in rules:
        for s in rules:
            if s["id"] == r["id"] or s["type"] != r["type"] or s["tool"] != r["tool"]:
                continue
            # s must be visible to r: same project, or s is global
            if not (s["scope"].startswith("user") or s["project"] == r["project"]):
                continue
            if s["pattern"] == r["pattern"]:
                continue  # exact dup handled elsewhere / different files
            if covers(s["pattern"], r["pattern"]):
                out.append({
                    "kind": "shadowed",
                    "severity": "low",
                    "title": f"'{r['raw']}' is redundant",
                    "detail": f"already covered by broader '{s['raw']}' ({s['scope_label']})",
                    "rule_ids": [r["id"]],
                })
                break

    # 4. Conflicts: same tool+pattern in conflicting types for a project
    eff = {}
    for r in rules:
        scope_proj = r["project"] if r["scope"].startswith("project") else "*"
        eff.setdefault((scope_proj, r["tool"], r["pattern"]), set()).add(r["type"])
    for (proj, tool, pat), types in eff.items():
        if len(types) > 1:
            winner = next(t for t in RULE_TYPES if t in types)
            losers = [t for t in RULE_TYPES if t in types and t != winner]
            sig = f"{tool}({pat})" if pat else tool
            losing_ids = [r["id"] for r in rules if r["tool"] == tool
                          and r["pattern"] == pat and r["type"] in losers]
            out.append({
                "kind": "conflict",
                "severity": "high",
                "title": f"'{sig}' is both {', '.join(sorted(types))}",
                "detail": f"'{winner}' wins (deny>ask>allow); the {', '.join(losers)} entry is dead"
                          + (f" for project {proj}" if proj != "*" else ""),
                "rule_ids": [r["id"] for r in rules
                             if r["tool"] == tool and r["pattern"] == pat],
                "fix": {"remove_ids": losing_ids},
            })

    # 4b. Allow rules that never apply because a higher-precedence ask/deny covers them
    #     (e.g. allow Bash(env) is dead under ask Bash(env:*) — deny>ask>allow).
    def _visible(a, b):  # does rule a's scope affect rule b's evaluation?
        return a["scope"].startswith("user") or b["scope"].startswith("user") \
            or a["project"] == b["project"]

    allows = [r for r in rules if r["type"] == "allow"]
    asks = [r for r in rules if r["type"] == "ask"]
    denies = [r for r in rules if r["type"] == "deny"]
    for al in allows:
        overrider = None
        for hp in denies + asks:   # deny outranks ask, both outrank allow
            if hp["tool"] == al["tool"] and _visible(hp, al) and covers(hp["pattern"], al["pattern"]):
                overrider = hp
                break
        if overrider:
            same_file = " (same file)" if overrider["file"] == al["file"] else ""
            out.append({
                "kind": "overridden-allow",
                "severity": "medium",
                "title": f"allow '{al['raw']}' never applies",
                "detail": f"overridden by higher-precedence {overrider['type']} "
                          f"'{overrider['raw']}' ({overrider['scope_label']}){same_file} — deny>ask>allow.",
                "rule_ids": [al["id"]],
                "fix": {"dead_allow": al["id"], "overrider": overrider["id"]},
            })

    # 4c. Label every ask rule: guardrail (overrides an allow) vs redundant (overrides nothing)
    redundant_ask, guardrails = [], []
    for a in asks:
        hits = [al for al in allows if al["tool"] == a["tool"]
                and _visible(a, al) and covers(a["pattern"], al["pattern"])]
        (guardrails if hits else redundant_ask).append((a, hits))
    if guardrails:
        out.append({
            "kind": "ask-guardrail",
            "severity": "info",
            "title": f"{len(guardrails)} ask rules are active guardrails",
            "detail": "These force a prompt over an allow rule (the useful kind of ask). Leave them: "
                      + "; ".join(f"{a['raw']} → over {h[0]['raw']}" for a, h in guardrails),
            "rule_ids": [a["id"] for a, _ in guardrails],
        })
    if redundant_ask:
        out.append({
            "kind": "ask-redundant",
            "severity": "low",
            "title": f"{len(redundant_ask)} ask rules are redundant under the default mode",
            "detail": "They don't override any allow, and unmatched tools already prompt by default — so "
                      "they're no-ops right now. They only do something if you launch with "
                      "--permission-mode acceptEdits/bypassPermissions (then they become guardrails).",
            "rule_ids": [a["id"] for a, _ in redundant_ask],
        })

    # 5. Machine-local-only grants (informational)
    local_count = sum(1 for r in rules if r["scope"].endswith("local"))
    if local_count:
        out.append({
            "kind": "local-only",
            "severity": "info",
            "title": f"{local_count} rules live only in *.local.json files",
            "detail": "These are machine-local and not shared/committed. Promote to shared if you want them everywhere.",
            "rule_ids": [r["id"] for r in rules if r["scope"].endswith("local")],
        })

    order = {"high": 0, "medium": 1, "low": 2, "info": 3}
    out.sort(key=lambda s: order.get(s["severity"], 9))
    return out


# --------------------------------------------------------------------------- #
# Writes (with backup, preserving non-permission keys)
# --------------------------------------------------------------------------- #
def _backup(path: str):
    # Guarantee a unique name: two ops on the same file within one second (common
    # in a batch Apply) must NOT clobber each other's backups.
    base = f"{path}.bak-{time.strftime('%Y%m%d-%H%M%S')}"
    bak, n = base, 1
    while os.path.exists(bak):
        bak = f"{base}-{n}"
        n += 1
    shutil.copy2(path, bak)
    return bak


def _save(path: str, data: dict):
    with open(path, "w") as f:
        json.dump(data, f, indent=2, ensure_ascii=False)
        f.write("\n")


def _ensure_perms(data: dict, rtype: str):
    data.setdefault("permissions", {})
    data["permissions"].setdefault(rtype, [])


def remove_rule(path: str, rtype: str, raw: str):
    if rtype not in RULE_TYPES:
        return False, f"invalid rule type: {rtype}"
    data = load_json(path) or {}
    arr = (data.get("permissions") or {}).get(rtype, [])
    if raw not in arr:
        return False, "rule not found"
    bak = _backup(path)
    arr.remove(raw)
    data["permissions"][rtype] = arr
    _save(path, data)
    return True, bak


def add_rule(path: str, rtype: str, raw: str):
    if rtype not in RULE_TYPES:
        return False, f"invalid rule type: {rtype}"
    data = load_json(path)
    if data is None and not os.path.exists(path):
        os.makedirs(os.path.dirname(path), exist_ok=True)
        data = {}
    elif data is None:
        return False, "file unreadable"
    _ensure_perms(data, rtype)
    if raw in data["permissions"][rtype]:
        return False, "rule already present"
    bak = _backup(path) if os.path.exists(path) else None
    data["permissions"][rtype].append(raw)
    _save(path, data)
    return True, bak


def change_type(path: str, old_type: str, new_type: str, raw: str):
    if old_type not in RULE_TYPES or new_type not in RULE_TYPES:
        return False, f"invalid rule type: {old_type}->{new_type}"
    data = load_json(path) or {}
    arr = (data.get("permissions") or {}).get(old_type, [])
    if raw not in arr:
        return False, "rule not found"
    bak = _backup(path)
    arr.remove(raw)
    data["permissions"][old_type] = arr
    _ensure_perms(data, new_type)
    if raw not in data["permissions"][new_type]:
        data["permissions"][new_type].append(raw)
    _save(path, data)
    return True, bak


def move_rule(from_path, to_path, rtype, raw, new_type=None):
    new_type = new_type or rtype
    ok, info = add_rule(to_path, new_type, raw)
    if not ok:
        return False, f"add failed: {info}"
    ok2, info2 = remove_rule(from_path, rtype, raw)
    if not ok2:
        return False, f"added to target but remove failed: {info2}"
    return True, {"added_to": to_path, "removed_from": from_path}


# --------------------------------------------------------------------------- #
# Memory (Claude's auto-memory files) — discover, parse, edit
# --------------------------------------------------------------------------- #
MEM_TYPES = ("user", "feedback", "project", "reference")


def _root_slug(root):
    return "-" + str(root.expanduser().resolve()).strip("/").replace("/", "-")


def discover_memory_dirs(root):
    base = root.expanduser().resolve() / ".claude" / "projects"
    dirs = []
    if base.exists():
        for projdir in sorted(base.iterdir()):
            md = projdir / "memory"
            if md.is_dir():
                dirs.append(md)
    return dirs


def _mem_scope(memdir, root_slug):
    slug = memdir.parent.name
    if slug == root_slug:
        return "global"
    if slug.startswith(root_slug + "-"):
        return slug[len(root_slug) + 1:]
    return slug


def parse_memory(text):
    """Pull description, type, and body out of a memory file's frontmatter."""
    fm, body = "", text
    if text.startswith("---"):
        end = text.find("\n---", 3)
        if end != -1:
            fm = text[3:end]
            body = text[end + 4:]

    def grab(pat):
        m = re.search(pat, fm, re.M)
        if not m:
            return ""
        v = m.group(1).strip()
        # symmetric with edit_memory's json.dumps: properly unescape a quoted value
        if len(v) >= 2 and v[0] == '"' and v[-1] == '"':
            try:
                return json.loads(v)
            except ValueError:
                pass
        return v.strip('"').strip("'")

    return {"description": grab(r'^description:\s*(.+)$'),
            "type": grab(r'^\s*type:\s*(.+)$'),
            "body": body.strip("\n")}


def build_memories(root):
    root = root.expanduser().resolve()
    rslug = _root_slug(root)
    out, mid = [], 0
    for md in discover_memory_dirs(root):
        scope = _mem_scope(md, rslug)
        for f in sorted(md.glob("*.md")):
            if f.name == "MEMORY.md":
                continue
            try:
                text = f.read_text(encoding="utf-8")
            except OSError:
                continue
            p = parse_memory(text)
            links = sorted(set(re.findall(r'\[\[([^\]]+)\]\]', p["body"])))
            out.append({"id": f"m{mid}", "name": f.stem, "scope": scope,
                        "description": p["description"], "type": p["type"] or "—",
                        "body": p["body"], "links": links, "file": str(f)})
            mid += 1
    return out


def edit_memory(path, description=None, mtype=None, body=None):
    if not os.path.exists(path):
        return False, "memory not found"
    raw = Path(path).read_text(encoding="utf-8")
    # Guard BEFORE backup/write: a body edit must never blow away frontmatter that
    # is present but doesn't match our parser (e.g. CRLF / odd delimiters).
    fm_match = re.match(r'^(---\n.*?\n---\n)', raw, re.S)
    if body is not None and not fm_match and raw.lstrip().startswith("---"):
        return False, "frontmatter present but unparseable; refusing to overwrite body"
    bak = _backup(path)
    if description is not None:
        raw = re.sub(r'(?m)^description:\s*.*$',
                     lambda m: "description: " + json.dumps(description, ensure_ascii=False),
                     raw, count=1)
    if mtype is not None:
        raw = re.sub(r'(?m)^(\s*type:\s*).*$', lambda m: m.group(1) + mtype, raw, count=1)
    if body is not None:
        # re-match on the (possibly description/type-edited) text so those edits survive
        m2 = re.match(r'^(---\n.*?\n---\n)', raw, re.S)
        new_body = body.rstrip("\n") + "\n"
        raw = (m2.group(1) + "\n" + new_body) if m2 else new_body
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(raw)
    return True, bak


def delete_memory(path):
    if not os.path.exists(path):
        return False, "memory not found"
    bak = _backup(path)
    base = os.path.basename(path)
    os.remove(path)
    idx = os.path.join(os.path.dirname(path), "MEMORY.md")
    if os.path.exists(idx):
        _backup(idx)
        lines = Path(idx).read_text(encoding="utf-8").splitlines(keepends=True)
        kept = [ln for ln in lines if f"]({base})" not in ln]
        with open(idx, "w", encoding="utf-8") as fh:
            fh.writelines(kept)
    return True, bak


# --------------------------------------------------------------------------- #
# HTTP handler
# --------------------------------------------------------------------------- #
class Handler(BaseHTTPRequestHandler):
    root = Path.home()

    def log_message(self, *a):
        pass  # quiet

    def _json(self, obj, code=200):
        body = json.dumps(obj).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Cache-Control", "no-store")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _state(self):
        files = discover_files(self.root)
        rules = collect_rules(files)
        return files, rules

    def _guard(self, post=False):
        """Refuse requests not actually addressed to localhost (DNS-rebinding) and
        cross-origin writes (CSRF). This server can modify your settings files, so
        a malicious page in your browser must not be able to drive it."""
        host = (self.headers.get("Host") or "").split(":")[0]
        if host and host not in ("127.0.0.1", "localhost"):
            self._json({"ok": False, "error": "host not allowed"}, 403)
            return False
        if post:
            origin = self.headers.get("Origin")
            if origin and urlparse(origin).hostname not in ("127.0.0.1", "localhost"):
                self._json({"ok": False, "error": "cross-origin request rejected"}, 403)
                return False
        return True

    def _in_root(self, p):
        """True only if path p resolves to inside the scanned root — blocks writes
        anywhere else (e.g. a crafted /etc/... target)."""
        if not p:
            return False
        try:
            root = os.path.realpath(self.root.expanduser())
            rp = os.path.realpath(p)
            return rp == root or rp.startswith(root + os.sep)
        except OSError:
            return False

    def do_GET(self):
        if not self._guard():
            return
        path = urlparse(self.path).path
        if path in ("/", "/index.html"):
            html = (HERE / "index.html").read_bytes()
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Cache-Control", "no-store")
            self.send_header("Content-Length", str(len(html)))
            self.end_headers()
            self.wfile.write(html)
            return
        if path == "/api/scan":
            files, rules = self._state()
            self._json({
                "root": str(self.root.expanduser().resolve()),
                "files": files,
                "rules": rules,
                "scopes": {k: {"label": v[0], "rank": v[1]} for k, v in SCOPES.items()},
                "suggestions": build_suggestions(rules),
                "risks": build_risk(rules),
            })
            return
        if path == "/api/memories":
            self._json({"memories": build_memories(self.root),
                        "memTypes": list(MEM_TYPES)})
            return
        self._json({"error": "not found"}, 404)

    def do_POST(self):
        if not self._guard(post=True):
            return
        path = urlparse(self.path).path
        length = int(self.headers.get("Content-Length", 0))
        try:
            payload = json.loads(self.rfile.read(length) or "{}")
        except json.JSONDecodeError:
            return self._json({"ok": False, "error": "bad json"}, 400)

        # Single batch endpoint: nothing is written to disk except via /api/apply.
        if path != "/api/apply":
            return self._json({"ok": False, "error": "unknown endpoint"}, 404)

        results = []
        for op in payload.get("ops", []):
            kind = op.get("kind")
            # Confine every write to the scanned root — never write outside it.
            targets = [op.get(k) for k in ("file", "from", "to") if op.get(k)]
            if targets and not all(self._in_root(t) for t in targets):
                results.append({"label": op.get("label", kind), "ok": False,
                                "error": "path outside scanned root — refused"})
                continue
            try:
                if kind == "delete":
                    ok, info = remove_rule(op["file"], op["type"], op["raw"])
                elif kind == "add":
                    ok, info = add_rule(op["file"], op["type"], op["raw"])
                elif kind == "change-type":
                    ok, info = change_type(op["file"], op["type"], op["new_type"], op["raw"])
                elif kind == "move":
                    ok, info = move_rule(op["from"], op["to"], op["type"],
                                         op["raw"], op.get("new_type"))
                elif kind == "mem-edit":
                    ok, info = edit_memory(op["file"], op.get("description"),
                                           op.get("type"), op.get("body"))
                elif kind == "mem-delete":
                    ok, info = delete_memory(op["file"])
                else:
                    ok, info = False, f"unknown op kind: {kind}"
            except KeyError as e:
                ok, info = False, f"missing field {e}"
            results.append({"label": op.get("label", kind), "ok": ok,
                            "error": None if ok else info})

        self._json({"ok": all(r["ok"] for r in results), "results": results})


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--port", type=int, default=8787)
    ap.add_argument("--root", default=str(Path.home()),
                    help="home/root to scan for project .claude dirs")
    args = ap.parse_args()
    Handler.root = Path(args.root)
    srv = ThreadingHTTPServer(("127.0.0.1", args.port), Handler)
    url = f"http://127.0.0.1:{args.port}"
    print(f"Claude Settings Manager → {url}")
    print(f"Scanning root: {Handler.root.expanduser().resolve()}")
    print("Ctrl-C to stop.")
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        print("\nbye")


if __name__ == "__main__":
    main()
