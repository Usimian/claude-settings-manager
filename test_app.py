#!/usr/bin/env python3
"""
Test suite for Claude Settings Manager (server.py).

Zero external deps — stdlib unittest. Run: python3 test_app.py [-v]

Every test works on throwaway temp directories; it never touches real
settings or memory files.
"""

import json
import os
import shutil
import tempfile
import unittest
from pathlib import Path

import server as S


def write(path, obj_or_text):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        f.write(obj_or_text if isinstance(obj_or_text, str) else json.dumps(obj_or_text))


def read(path):
    return Path(path).read_text(encoding="utf-8")


class Base(unittest.TestCase):
    def setUp(self):
        self.root = Path(tempfile.mkdtemp(prefix="csm-test-"))
        self.addCleanup(shutil.rmtree, self.root, ignore_errors=True)

    def gfile(self, scope="settings.json"):
        return str(self.root / ".claude" / scope)

    def pfile(self, project, scope="settings.local.json"):
        return str(self.root / project / ".claude" / scope)


# --------------------------------------------------------------------------- #
class TestParsing(Base):
    def test_parse_rule_variants(self):
        cases = {
            "Bash(git log:*)": ("Bash", "git log:*"),
            "Read": ("Read", None),
            "Read(//var/**)": ("Read", "//var/**"),
            "Skill(claude-api)": ("Skill", "claude-api"),
            "WebSearch": ("WebSearch", None),
            "Bash(echo (nested))": ("Bash", "echo (nested)"),
            "Bash(grep \"x y\":*)": ("Bash", 'grep "x y":*'),
        }
        for raw, exp in cases.items():
            self.assertEqual(S.parse_rule(raw), exp, raw)

    def test_load_json_malformed(self):
        p = self.gfile()
        write(p, "{ this is not json ,,, }")
        self.assertIsNone(S.load_json(p))  # must not raise


class TestDiscovery(Base):
    def test_finds_all_scopes_and_prunes(self):
        write(self.gfile("settings.json"), {"permissions": {"allow": ["Read"]}})
        write(self.gfile("settings.local.json"), {"permissions": {"allow": ["Glob"]}})
        write(self.pfile("projA", "settings.json"), {"permissions": {"allow": ["Bash(ls:*)"]}})
        write(self.pfile("projA", "settings.local.json"), {"permissions": {"allow": ["Bash(cat:*)"]}})
        # a .claude buried in node_modules must be pruned
        write(str(self.root / "projB" / "node_modules" / "x" / ".claude" / "settings.json"),
              {"permissions": {"allow": ["Bash(rm:*)"]}})

        files = S.discover_files(self.root)
        scopes = {f["scope"] for f in files}
        self.assertEqual(scopes, {"user", "user-local", "project-shared", "project-local"})
        self.assertFalse(any("node_modules" in f["path"] for f in files))

    def test_collect_rules_handles_corrupt_permissions(self):
        write(self.gfile(), {"permissions": "not a dict"})            # perms not a dict
        write(self.pfile("p"), {"permissions": {"allow": "Bash(rm)"}})  # allow not a list
        write(self.pfile("q"), {"permissions": {"allow": ["ok", 123, None]}})  # mixed types
        rules = S.collect_rules(S.discover_files(self.root))           # must not raise
        self.assertEqual([r["raw"] for r in rules], ["ok"])           # only valid strings

    def test_collect_rules_skips_missing_arrays(self):
        write(self.gfile(), {"permissions": {"allow": ["Read"]}})  # no ask/deny keys
        write(self.pfile("p"), {"env": {"X": "1"}})  # no permissions at all
        rules = S.collect_rules(S.discover_files(self.root))
        self.assertEqual([r["raw"] for r in rules], ["Read"])
        self.assertTrue(all("id" in r for r in rules))
        self.assertEqual(len({r["id"] for r in rules}), len(rules))  # ids unique


class TestCovers(Base):
    def test_no_false_prefix_match(self):
        # The bug that started it all: ls must NOT cover lsblk
        for broad, narrow in [("ls:*", "lsblk:*"), ("pip:*", "pip3:*"),
                              ("python:*", "python3:*"), ("git log:*", "git logfoo")]:
            self.assertFalse(S.covers(broad, narrow), f"{broad} should NOT cover {narrow}")

    def test_real_coverage(self):
        for broad, narrow in [(None, "anything"), ("git log:*", "git log --oneline"),
                              ("cat:*", "cat"), ("//home/m/**", "//home/m/.claude/**"),
                              ("ssh rider *", "ssh rider cat:*")]:
            self.assertTrue(S.covers(broad, narrow), f"{broad} should cover {narrow}")
        self.assertFalse(S.covers("//home/m/**", "//home/msecret/**"))


class TestClassifier(Base):
    def test_severities(self):
        cases = {
            "rm:*": "critical", "rm -rf /:*": "critical", "sudo dmesg": "critical",
            "sudo rm -rf /:*": "critical", "ssh rider *": "high", "ssh rider cat:*": "low",
            "ssh rider rm:*": "critical", "git push --force:*": "high",
            "git log:*": None, "docker exec c grep:*": "high", "cat:*": None,
            "ls:*": None, "chmod -R 777 /:*": "high", "curl:*": "high",
            "xargs rm:*": "critical", "apt install:*": "high", "apt search:*": None,
            "python3:*": "medium", "find . -delete:*": "high", "dd:*": "critical",
            "make:*": "medium", "kill:*": "medium",
        }
        for pat, exp in cases.items():
            got = S.classify_command(pat)
            self.assertEqual(got[0] if got else None, exp, f"{pat!r} -> {got}")

    def test_wildcard_and_tool_rules(self):
        self.assertEqual(S.classify_command(None)[0], "critical")
        self.assertEqual(S.classify_command("*")[0], "critical")
        self.assertEqual(S.classify_rule({"tool": "Write", "pattern": None})[0], "high")
        self.assertEqual(S.classify_rule({"tool": "Edit", "pattern": None})[0], "medium")
        self.assertIsNone(S.classify_rule({"tool": "Read", "pattern": None}))


class TestWrites(Base):
    def setUp(self):
        super().setUp()
        self.f = self.gfile()
        write(self.f, {"permissions": {"allow": ["Read", "Bash(ls:*)"]},
                       "model": "opus", "voice": {"enabled": True}})

    def _load(self):
        return S.load_json(self.f)

    def test_add_dup_and_preserve(self):
        ok, _ = S.add_rule(self.f, "allow", "Bash(cat:*)")
        self.assertTrue(ok)
        self.assertIn("Bash(cat:*)", self._load()["permissions"]["allow"])
        # non-permission keys preserved
        self.assertEqual(self._load()["model"], "opus")
        self.assertEqual(self._load()["voice"], {"enabled": True})
        # duplicate rejected
        ok2, info = S.add_rule(self.f, "allow", "Bash(cat:*)")
        self.assertFalse(ok2)

    def test_remove(self):
        ok, _ = S.remove_rule(self.f, "allow", "Read")
        self.assertTrue(ok)
        self.assertNotIn("Read", self._load()["permissions"]["allow"])
        ok2, info = S.remove_rule(self.f, "allow", "DoesNotExist")
        self.assertFalse(ok2)

    def test_edit_rule(self):
        # edits in place, preserving order and non-permission keys
        ok, _ = S.edit_rule(self.f, "allow", "Bash(ls:*)", "Bash(ls -la:*)")
        self.assertTrue(ok)
        d = self._load()
        self.assertEqual(d["permissions"]["allow"], ["Read", "Bash(ls -la:*)"])
        self.assertEqual(d["model"], "opus")
        # unchanged text is a no-op (no backup churn needed)
        self.assertEqual(S.edit_rule(self.f, "allow", "Read", "Read"), (True, None))
        # empty / missing rejected
        self.assertFalse(S.edit_rule(self.f, "allow", "Read", "  ")[0])
        self.assertFalse(S.edit_rule(self.f, "allow", "Nope", "X")[0])
        # editing to a value that already exists just drops the duplicate
        ok2, _ = S.edit_rule(self.f, "allow", "Bash(ls -la:*)", "Read")
        self.assertTrue(ok2)
        self.assertEqual(self._load()["permissions"]["allow"], ["Read"])

    def test_change_type_creates_array(self):
        ok, _ = S.change_type(self.f, "allow", "deny", "Bash(ls:*)")
        self.assertTrue(ok)
        d = self._load()
        self.assertNotIn("Bash(ls:*)", d["permissions"]["allow"])
        self.assertIn("Bash(ls:*)", d["permissions"]["deny"])

    def test_move_between_files(self):
        g2 = self.pfile("p")
        write(g2, {"permissions": {"allow": []}})
        ok, _ = S.move_rule(self.f, g2, "allow", "Read")
        self.assertTrue(ok)
        self.assertNotIn("Read", self._load()["permissions"]["allow"])
        self.assertIn("Read", S.load_json(g2)["permissions"]["allow"])

    def test_add_creates_new_file(self):
        newf = self.pfile("brand-new")
        ok, _ = S.add_rule(newf, "ask", "Bash(npm run:*)")
        self.assertTrue(ok)
        self.assertIn("Bash(npm run:*)", S.load_json(newf)["permissions"]["ask"])

    def test_backup_created(self):
        S.remove_rule(self.f, "allow", "Read")
        baks = list(Path(self.f).parent.glob("settings.json.bak-*"))
        self.assertTrue(baks)
        # backup holds the ORIGINAL content
        self.assertIn("Read", S.load_json(str(baks[0]))["permissions"]["allow"])

    def test_invalid_rtype_rejected(self):
        self.assertFalse(S.add_rule(self.f, "bogus", "X")[0])
        self.assertFalse(S.change_type(self.f, "allow", "bogus", "Read")[0])
        self.assertFalse(S.remove_rule(self.f, "bogus", "Read")[0])
        self.assertNotIn("bogus", self._load().get("permissions", {}))  # no spurious key

    def test_backup_unique_within_second(self):
        b1 = S._backup(self.f)
        b2 = S._backup(self.f)   # same second
        self.assertNotEqual(b1, b2)
        self.assertTrue(os.path.exists(b1) and os.path.exists(b2))

    def test_unicode_preserved(self):
        S.add_rule(self.f, "allow", "Bash(echo café—✓:*)")
        raw = read(self.f)
        self.assertIn("café—✓", raw)  # not \u-escaped


class TestSuggestions(Base):
    def _rules(self):
        return S.collect_rules(S.discover_files(self.root))

    def test_env_overridden_allow(self):
        write(self.gfile(), {"permissions": {"allow": ["Bash(env)"], "ask": ["Bash(env:*)"]}})
        sg = S.build_suggestions(self._rules())
        oa = [s for s in sg if s["kind"] == "overridden-allow"]
        self.assertEqual(len(oa), 1)
        self.assertIn("env", oa[0]["title"])
        self.assertIn("dead_allow", oa[0]["fix"])

    def test_ask_labels(self):
        write(self.gfile(), {"permissions": {
            "allow": ["Bash(xargs cat:*)"],
            "ask": ["Bash(xargs:*)", "Bash(python:*)"]}})
        sg = S.build_suggestions(self._rules())
        guard = [s for s in sg if s["kind"] == "ask-guardrail"]
        redun = [s for s in sg if s["kind"] == "ask-redundant"]
        self.assertEqual(len(guard), 1)   # xargs overrides the allow
        self.assertEqual(len(redun), 1)   # python overrides nothing

    def test_promote_threshold(self):
        for p in ("p1", "p2", "p3"):
            write(self.pfile(p), {"permissions": {"allow": ["Bash(tree:*)"]}})
        sg = S.build_suggestions(self._rules())
        self.assertTrue(any(s["kind"] == "promote-to-global" for s in sg))
        # only 2 projects -> NOT promoted
        self.setUp()
        for p in ("p1", "p2"):
            write(self.pfile(p), {"permissions": {"allow": ["Bash(tree:*)"]}})
        sg = S.build_suggestions(self._rules())
        self.assertFalse(any(s["kind"] == "promote-to-global" for s in sg))

    def test_conflict_has_fix(self):
        write(self.gfile(), {"permissions": {"allow": ["Bash(foo:*)"], "deny": ["Bash(foo:*)"]}})
        sg = S.build_suggestions(self._rules())
        cf = [s for s in sg if s["kind"] == "conflict"]
        self.assertEqual(len(cf), 1)
        self.assertTrue(cf[0]["fix"]["remove_ids"])


class TestRisk(Base):
    def test_only_allow_and_ask(self):
        write(self.gfile(), {"permissions": {
            "allow": ["Bash(sudo dmesg)"], "deny": ["Bash(rm:*)"]}})
        risks = S.build_risk(S.collect_rules(S.discover_files(self.root)))
        # the denied rm must NOT appear (deny is protective)
        self.assertFalse(any("rm" in r["raw"] for r in risks))
        self.assertTrue(any(r["severity"] == "critical" for r in risks))


# --------------------------------------------------------------------------- #
class TestMemory(Base):
    def memdir(self, slug):
        d = self.root / ".claude" / "projects" / slug / "memory"
        d.mkdir(parents=True, exist_ok=True)
        return d

    MEM = ('---\nname: feedback_x\ndescription: "old desc"\n'
           'metadata:\n  node_type: memory\n  type: feedback\n'
           '  originSessionId: abc-123\n---\n\nBody line one.\nSee [[other_mem]].\n')

    def test_parse(self):
        p = S.parse_memory(self.MEM)
        self.assertEqual(p["description"], "old desc")
        self.assertEqual(p["type"], "feedback")
        self.assertIn("Body line one.", p["body"])

    def test_parse_no_frontmatter(self):
        p = S.parse_memory("just a body, no frontmatter")
        self.assertEqual(p["type"], "")
        self.assertIn("just a body", p["body"])

    def test_build_memories_scopes(self):
        rslug = S._root_slug(self.root)
        write(str(self.memdir(rslug) / "feedback_x.md"), self.MEM)
        write(str(self.memdir(rslug + "-projA") / "project_y.md"),
              '---\nname: project_y\ndescription: "p"\nmetadata:\n  type: project\n---\n\nbody\n')
        write(str(self.memdir(rslug) / "MEMORY.md"), "# index\n- [X](feedback_x.md) — hook\n")
        mems = S.build_memories(self.root)
        scopes = {m["scope"] for m in mems}
        self.assertEqual(scopes, {"global", "projA"})
        self.assertNotIn("MEMORY", [m["name"] for m in mems])  # index excluded
        fx = next(m for m in mems if m["name"] == "feedback_x")
        self.assertEqual(fx["links"], ["other_mem"])

    def test_edit_preserves_frontmatter(self):
        rslug = S._root_slug(self.root)
        p = str(self.memdir(rslug) / "feedback_x.md")
        write(p, self.MEM)
        ok, _ = S.edit_memory(p, description="new desc", mtype="reference",
                              body="Brand new body.")
        self.assertTrue(ok)
        parsed = S.parse_memory(read(p))
        self.assertEqual(parsed["description"], "new desc")
        self.assertEqual(parsed["type"], "reference")
        self.assertEqual(parsed["body"], "Brand new body.")
        raw = read(p)
        self.assertIn("name: feedback_x", raw)          # name preserved
        self.assertIn("originSessionId: abc-123", raw)  # session id preserved

    def test_edit_desc_and_body_together(self):
        rslug = S._root_slug(self.root)
        p = str(self.memdir(rslug) / "feedback_x.md")
        write(p, self.MEM)
        S.edit_memory(p, description="D2", body="B2")   # regression: both must survive
        parsed = S.parse_memory(read(p))
        self.assertEqual(parsed["description"], "D2")
        self.assertEqual(parsed["body"], "B2")
        self.assertEqual(parsed["type"], "feedback")  # untouched

    def test_edit_refuses_unparseable_frontmatter(self):
        rslug = S._root_slug(self.root)
        p = str(self.memdir(rslug) / "m.md")
        # opening delimiter but NO closing '---' -> genuinely unparseable
        write(p, "---\nname: m\ntype: feedback\nbody started without closing delim\n")
        before = read(p)
        ok, info = S.edit_memory(p, body="NEW BODY")
        self.assertFalse(ok)             # refused, not destroyed
        self.assertEqual(read(p), before)

    def test_edit_only_one_field(self):
        rslug = S._root_slug(self.root)
        p = str(self.memdir(rslug) / "feedback_x.md")
        write(p, self.MEM)
        S.edit_memory(p, body="only body changed")
        parsed = S.parse_memory(read(p))
        self.assertEqual(parsed["description"], "old desc")   # unchanged
        self.assertEqual(parsed["type"], "feedback")          # unchanged
        self.assertEqual(parsed["body"], "only body changed")

    def test_edit_special_chars_in_description(self):
        rslug = S._root_slug(self.root)
        p = str(self.memdir(rslug) / "feedback_x.md")
        write(p, self.MEM)
        tricky = 'has "quotes" and: colons and — em dash'
        S.edit_memory(p, description=tricky)
        parsed = S.parse_memory(read(p))
        self.assertEqual(parsed["description"], tricky)

    def test_delete_removes_file_and_index(self):
        rslug = S._root_slug(self.root)
        d = self.memdir(rslug)
        p = str(d / "feedback_x.md")
        write(p, self.MEM)
        write(str(d / "MEMORY.md"),
              "# index\n- [X](feedback_x.md) — hook\n- [Y](other.md) — keep\n")
        ok, _ = S.delete_memory(p)
        self.assertTrue(ok)
        self.assertFalse(os.path.exists(p))
        idx = read(str(d / "MEMORY.md"))
        self.assertNotIn("feedback_x.md", idx)
        self.assertIn("other.md", idx)  # other lines kept

    def test_delete_no_index(self):
        rslug = S._root_slug(self.root)
        p = str(self.memdir(rslug) / "feedback_x.md")
        write(p, self.MEM)
        ok, _ = S.delete_memory(p)  # no MEMORY.md present
        self.assertTrue(ok)
        self.assertFalse(os.path.exists(p))


if __name__ == "__main__":
    unittest.main(verbosity=2)
