#!/usr/bin/env python3
"""Unit and end-to-end tests for apply_my_rules.py (stdlib unittest only)."""

from __future__ import annotations

import shutil
import sys
import tempfile
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

import apply_my_rules as amr  # noqa: E402


class TestSimpleYamlParser(unittest.TestCase):
    def test_nested_dicts_lists_comments_and_quotes(self) -> None:
        sample = """
# top comment
github:
  owner: "alice" # inline comment
  repo: 'my-zju'
  raw_mirror_prefix: ""
  note: "keep # hash inside quotes"
rules:
  direct:
    - example.com # trailing comment
    - "=www.example.com"
  proxy: []
  zju:
    # only comments here
  ai: [claude.ai, "openai.com"]
custom_groups:
  "Ⓜ️ 微软服务":
    - login.microsoftonline.com
"""
        parsed = amr._parse_simple_yaml(sample)
        self.assertEqual(parsed["github"]["owner"], "alice")
        self.assertEqual(parsed["github"]["repo"], "my-zju")
        self.assertEqual(parsed["github"]["raw_mirror_prefix"], "")
        self.assertEqual(parsed["github"]["note"], "keep # hash inside quotes")
        self.assertEqual(parsed["rules"]["direct"], ["example.com", "=www.example.com"])
        self.assertEqual(parsed["rules"]["proxy"], [])
        self.assertIsNone(parsed["rules"]["zju"])
        self.assertEqual(parsed["rules"]["ai"], ["claude.ai", "openai.com"])
        self.assertEqual(parsed["custom_groups"]["Ⓜ️ 微软服务"], ["login.microsoftonline.com"])

    def test_empty_custom_groups(self) -> None:
        parsed = amr._parse_simple_yaml("custom_groups: {}\n")
        self.assertEqual(parsed, {"custom_groups": {}})


class TestNormalizeRuleEntry(unittest.TestCase):
    def test_all_shorthands_and_native(self) -> None:
        cases = [
            ("example.com", "DOMAIN-SUFFIX,example.com"),
            (".example.com", "DOMAIN-SUFFIX,example.com"),
            ("*.example.com", "DOMAIN-SUFFIX,example.com"),
            ("=www.example.com", "DOMAIN,www.example.com"),
            ("=https://www.example.com:443/path?a=1", "DOMAIN,www.example.com"),
            ("*openai", "DOMAIN-KEYWORD,openai"),
            ("https://sub.example.com:8443/a?b=1", "DOMAIN-SUFFIX,sub.example.com"),
            ("http://192.168.1.10:8080/admin", "IP-CIDR,192.168.1.10/32,no-resolve"),
            ("1.2.3.4", "IP-CIDR,1.2.3.4/32,no-resolve"),
            ("10.20.0.0/16", "IP-CIDR,10.20.0.0/16,no-resolve"),
            ("2001:db8::1", "IP-CIDR6,2001:db8::1/128,no-resolve"),
            ("2001:db8::/32", "IP-CIDR6,2001:db8::/32,no-resolve"),
            ("domain-suffix,custom.org", "DOMAIN-SUFFIX,custom.org"),
            ("IP-CIDR,198.51.100.0/24,no-resolve", "IP-CIDR,198.51.100.0/24,no-resolve"),
        ]
        for raw, expected in cases:
            with self.subTest(raw=raw):
                self.assertEqual(amr.normalize_rule_entry(raw), expected)

    def test_invalid_entries(self) -> None:
        for bad in ("", "   ", "bad domain.com", "a,b", "="):
            with self.subTest(bad=bad):
                with self.assertRaises(ValueError):
                    amr.normalize_rule_entry(bad)


class TestGitMetadataDetection(unittest.TestCase):
    def test_detect_branch_and_origin_https_and_ssh(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            git_dir = root / ".git"
            git_dir.mkdir()
            (git_dir / "HEAD").write_text("ref: refs/heads/my-rules\n", encoding="utf-8")
            (git_dir / "config").write_text(
                '[remote "origin"]\n\turl = https://github.com/alice/my-zju-rule.git\n',
                encoding="utf-8",
            )
            meta = amr.detect_git_metadata(root)
            self.assertEqual(meta, {"owner": "alice", "repo": "my-zju-rule", "branch": "my-rules"})

            (git_dir / "config").write_text(
                '[remote "origin"]\n\turl = git@github.com:bob/custom-zju.git\n',
                encoding="utf-8",
            )
            meta_ssh = amr.detect_git_metadata(root)
            self.assertEqual(meta_ssh, {"owner": "bob", "repo": "custom-zju", "branch": "my-rules"})

            # SubConv/ZJU-Rule should be ignored as origin
            (git_dir / "config").write_text(
                '[remote "origin"]\n\turl = https://github.com/SubConv/ZJU-Rule.git\n',
                encoding="utf-8",
            )
            meta_upstream = amr.detect_git_metadata(root)
            self.assertEqual(meta_upstream, {"owner": "", "repo": "", "branch": "my-rules"})


class TestEndToEndGeneration(unittest.TestCase):
    def setUp(self) -> None:
        self.real_zju_ini = REPO_ROOT / "Clash" / "config" / "ZJU.ini"
        self.assertTrue(self.real_zju_ini.is_file(), "Upstream Clash/config/ZJU.ini must exist")

    def _prepare_temp_repo(self, tmp: str) -> Path:
        root = Path(tmp)
        cfg_dir = root / "Clash" / "config"
        cfg_dir.mkdir(parents=True)
        shutil.copy2(self.real_zju_ini, cfg_dir / "ZJU.ini")
        return root

    def test_group_validation_us_flag_exact_match(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = self._prepare_temp_repo(tmp)
            # Valid exact US group (U+1F1FA U+1F1F2)
            cfg_ok = root / "my_rules.yaml"
            cfg_ok.write_text(
                'rules:\n  region_us:\n    - us-site.example.com\ncustom_groups:\n  "🇺🇲 美国节点":\n    - us2.example.com\n',
                encoding="utf-8",
            )
            res = amr.generate_custom_rules(
                root, cfg_ok, root / "Clash/config/ZJU.ini", root / "Clash/config/MyZJU.ini"
            )
            self.assertEqual(res["total_rules"], 2)

            # Wrong US flag (U+1F1FA U+1F1F8) must fail loudly
            cfg_bad = root / "bad.yaml"
            cfg_bad.write_text('custom_groups:\n  "🇺🇸 美国节点":\n    - wrong.example.com\n', encoding="utf-8")
            with self.assertRaises(ValueError):
                amr.generate_custom_rules(
                    root, cfg_bad, root / "Clash/config/ZJU.ini", root / "Clash/config/MyZJU.ini"
                )

    def test_inline_mode_dedup_conflict_and_cleanup(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = self._prepare_temp_repo(tmp)
            base_ini = root / "Clash" / "config" / "ZJU.ini"
            out_ini = root / "Clash" / "config" / "MyZJU.ini"
            original_bytes = base_ini.read_bytes()

            cfg = root / "my_rules.yaml"
            cfg.write_text(
                """
github:
  ruleset_mode: "inline"
  upstream_mode: "upstream"
rules:
  direct:
    - foo.com
    - *.foo.com
    - https://bar.cn/test
  proxy:
    - foo.com
    - =exact.org
""",
                encoding="utf-8",
            )
            res = amr.generate_custom_rules(root, cfg, base_ini, out_ini)
            # foo.com deduped inside direct; conflict warning emitted for proxy
            self.assertEqual(res["total_rules"], 4)
            self.assertEqual(len(res["warnings"]), 1)
            self.assertIn("DOMAIN-SUFFIX,foo.com", res["warnings"][0])

            # Upstream ZJU.ini must remain byte-identical
            self.assertEqual(base_ini.read_bytes(), original_bytes)

            ini_text = out_ini.read_text(encoding="utf-8")
            self.assertIn(amr.BEGIN_BLOCK, ini_text)
            self.assertIn("ruleset=🎯 全球直连,[]DOMAIN-SUFFIX,foo.com", ini_text)
            self.assertIn("ruleset=🚀 节点选择,[]DOMAIN,exact.org", ini_text)
            self.assertLess(
                ini_text.index("ruleset=🎯 全球直连,[]DOMAIN-SUFFIX,foo.com"),
                ini_text.index("PrivateTracker.list"),
            )

            # Custom .list and Providers/*.yaml files generated
            direct_list = root / "Clash" / "Custom" / "CustomDirect.list"
            direct_yaml = root / "Clash" / "Providers" / "Custom" / "CustomDirect.yaml"
            self.assertTrue(direct_list.is_file())
            self.assertTrue(direct_yaml.is_file())
            self.assertIn("payload:\n  - DOMAIN-SUFFIX,foo.com\n", direct_yaml.read_text(encoding="utf-8"))

            # Remove proxy rules and re-run -> stale CustomProxy files cleaned up
            cfg.write_text("rules:\n  direct:\n    - bar.cn\n", encoding="utf-8")
            res2 = amr.generate_custom_rules(root, cfg, base_ini, out_ini)
            self.assertEqual(res2["total_rules"], 1)
            self.assertFalse((root / "Clash" / "Custom" / "CustomProxy.list").exists())
            self.assertFalse((root / "Clash" / "Providers" / "Custom" / "CustomProxy.yaml").exists())

            # Remove all rules -> Custom dirs removed cleanly
            cfg.write_text("rules: {}\n", encoding="utf-8")
            amr.generate_custom_rules(root, cfg, base_ini, out_ini)
            self.assertFalse((root / "Clash" / "Custom").exists())
            self.assertFalse((root / "Clash" / "Providers" / "Custom").exists())

    def test_url_mode_self_upstream_and_mirror(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = self._prepare_temp_repo(tmp)
            base_ini = root / "Clash" / "config" / "ZJU.ini"
            out_ini = root / "Clash" / "config" / "MyZJU.ini"
            cfg = root / "my_rules.yaml"
            cfg.write_text(
                """
github:
  owner: "alice"
  repo: "myzjurule"
  branch: "my-rules"
  ruleset_mode: "url"
  upstream_mode: "self"
  raw_mirror_prefix: "https://gh-proxy.com/"
rules:
  proxy:
    - example.org
""",
                encoding="utf-8",
            )
            amr.generate_custom_rules(root, cfg, base_ini, out_ini)
            ini_text = out_ini.read_text(encoding="utf-8")
            self.assertIn(
                "ruleset=🚀 节点选择,https://gh-proxy.com/https://raw.githubusercontent.com/alice/myzjurule/my-rules/Clash/Custom/CustomProxy.list",
                ini_text,
            )
            self.assertIn(
                "ruleset=🎯 全球直连,https://gh-proxy.com/https://raw.githubusercontent.com/alice/myzjurule/my-rules/Clash/Ruleset/PrivateTracker.list",
                ini_text,
            )

    def test_real_template_config_runs_cleanly(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = self._prepare_temp_repo(tmp)
            res = amr.generate_custom_rules(
                root,
                REPO_ROOT / "my_rules.yaml",
                root / "Clash" / "config" / "ZJU.ini",
                root / "Clash" / "config" / "MyZJU.ini",
            )
            self.assertEqual(res["total_rules"], 0)
            self.assertTrue((root / "Clash" / "config" / "MyZJU.ini").is_file())


if __name__ == "__main__":
    unittest.main()
