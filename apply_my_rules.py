#!/usr/bin/env python3
"""Generate custom Clash/Subconverter rules from my_rules.yaml without modifying upstream files."""

from __future__ import annotations

import argparse
import ipaddress
import json
import re
import sys
from collections import OrderedDict
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

UPSTREAM_RAW_PREFIX = "https://raw.githubusercontent.com/SubConv/ZJU-Rule/main/"
MARKER_LINE = ";设置规则标志位"
BEGIN_BLOCK = "; === BEGIN MY CUSTOM RULES (generated from my_rules.yaml) ==="
END_BLOCK = "; === END MY CUSTOM RULES ==="

NATIVE_PREFIXES = (
    "DOMAIN-SUFFIX",
    "DOMAIN-KEYWORD",
    "DOMAIN-REGEX",
    "DOMAIN",
    "IP-CIDR6",
    "IP-CIDR",
    "GEOIP",
    "PROCESS-NAME",
    "SRC-IP-CIDR",
    "DST-PORT",
    "SRC-PORT",
    "USER-AGENT",
    "URL-REGEX",
)

# Exact proxy group names from Clash/config/ZJU.ini (note region_us uses U+1F1FA U+1F1F2).
GROUP_ALIASES: "OrderedDict[str, tuple[str, str]]" = OrderedDict(
    [
        ("direct", ("🎯 全球直连", "CustomDirect")),
        ("proxy", ("🚀 节点选择", "CustomProxy")),
        ("zju", ("✔ ZJU内网", "CustomZJU")),
        ("scholar", ("📃 ZJU More Scholar", "CustomScholar")),
        ("ai", ("💬 Ai平台", "CustomAI")),
        ("foreign_media", ("🌍 国外媒体", "CustomForeignMedia")),
        ("china_media", ("🌏 国内媒体", "CustomChinaMedia")),
        ("youtube", ("📹 油管视频", "CustomYouTube")),
        ("netflix", ("🎥 奈飞视频", "CustomNetflix")),
        ("bilibili", ("📺 哔哩哔哩", "CustomBilibili")),
        ("telegram", ("📲 电报消息", "CustomTelegram")),
        ("games", ("🎮 游戏平台", "CustomGames")),
        ("reject", ("🛑 广告拦截", "CustomReject")),
        ("region_hk", ("🇭🇰 香港节点", "CustomRegionHK")),
        ("region_jp", ("🇯🇵 日本节点", "CustomRegionJP")),
        ("region_us", ("🇺🇲 美国节点", "CustomRegionUS")),
        ("region_tw", ("🇨🇳 台湾节点", "CustomRegionTW")),
        ("region_sg", ("🇸🇬 狮城节点", "CustomRegionSG")),
        ("region_kr", ("🇰🇷 韩国节点", "CustomRegionKR")),
    ]
)


def _strip_inline_comment(line: str) -> str:
    """Remove # comments outside single or double quotes."""
    in_single = False
    in_double = False
    escaped = False
    for idx, ch in enumerate(line):
        if in_double:
            if escaped:
                escaped = False
            elif ch == "\\":
                escaped = True
            elif ch == '"':
                in_double = False
        elif in_single:
            if ch == "'":
                in_single = False
        else:
            if ch == '"':
                in_double = True
            elif ch == "'":
                in_single = True
            elif ch == "#":
                if idx == 0 or line[idx - 1].isspace():
                    return line[:idx].rstrip()
    return line.rstrip()


def _unquote_scalar(token: str, line_no: int) -> str:
    token = token.strip()
    if len(token) >= 2 and token[0] == '"' and token[-1] == '"':
        try:
            return json.loads(token)
        except json.JSONDecodeError as exc:
            raise ValueError(f"Line {line_no}: invalid double-quoted string {token!r}: {exc}") from exc
    if len(token) >= 2 and token[0] == "'" and token[-1] == "'":
        return token[1:-1].replace("''", "'")
    if (token.startswith('"') and not token.endswith('"')) or (
        token.startswith("'") and not token.endswith("'")
    ):
        raise ValueError(f"Line {line_no}: unclosed quote in {token!r}")
    return token


def _split_top_level_colon(content: str, line_no: int) -> tuple[str, str]:
    in_single = False
    in_double = False
    escaped = False
    for idx, ch in enumerate(content):
        if in_double:
            if escaped:
                escaped = False
            elif ch == "\\":
                escaped = True
            elif ch == '"':
                in_double = False
        elif in_single:
            if ch == "'":
                in_single = False
        else:
            if ch == '"':
                in_double = True
            elif ch == "'":
                in_single = True
            elif ch == ":":
                if idx + 1 == len(content) or content[idx + 1].isspace():
                    return content[:idx].strip(), content[idx + 1 :].strip()
    raise ValueError(f"Line {line_no}: expected 'key: value' mapping entry, got {content!r}")


def _parse_inline_list(text: str, line_no: int) -> list[Any]:
    inner = text[1:-1].strip()
    if not inner:
        return []
    items: list[str] = []
    buf: list[str] = []
    in_single = False
    in_double = False
    escaped = False
    for ch in inner:
        if in_double:
            buf.append(ch)
            if escaped:
                escaped = False
            elif ch == "\\":
                escaped = True
            elif ch == '"':
                in_double = False
        elif in_single:
            buf.append(ch)
            if ch == "'":
                in_single = False
        else:
            if ch == '"':
                in_double = True
                buf.append(ch)
            elif ch == "'":
                in_single = True
                buf.append(ch)
            elif ch == ",":
                items.append("".join(buf).strip())
                buf.clear()
            else:
                buf.append(ch)
    if in_single or in_double:
        raise ValueError(f"Line {line_no}: unclosed quote inside inline list")
    tail = "".join(buf).strip()
    if tail:
        items.append(tail)
    return [_parse_scalar_value(item, line_no) for item in items]


def _parse_scalar_value(val: str, line_no: int) -> Any:
    val = val.strip()
    if val == "{}":
        return {}
    if val == "[]":
        return []
    if val.startswith("["):
        if not val.endswith("]"):
            raise ValueError(f"Line {line_no}: unclosed inline list {val!r}")
        return _parse_inline_list(val, line_no)
    if val in ("null", "~", "Null", "NULL"):
        return None
    if val in ("true", "True", "TRUE"):
        return True
    if val in ("false", "False", "FALSE"):
        return False
    return _unquote_scalar(val, line_no)


def _is_seq_line(content: str) -> bool:
    return content == "-" or content.startswith("- ")


def _parse_simple_yaml(text: str) -> dict[str, Any]:
    """Parse the subset of YAML used by my_rules.yaml using stdlib only."""
    cleaned: list[tuple[int, int, str]] = []
    for line_no, raw_line in enumerate(text.splitlines(), start=1):
        stripped_comment = _strip_inline_comment(raw_line)
        if not stripped_comment.strip():
            continue
        if "\t" in stripped_comment[: len(stripped_comment) - len(stripped_comment.lstrip(" \t"))]:
            raise ValueError(f"Line {line_no}: tabs are not allowed in indentation")
        indent = len(stripped_comment) - len(stripped_comment.lstrip(" "))
        cleaned.append((line_no, indent, stripped_comment.strip()))

    if not cleaned:
        return {}

    def parse_block(idx: int, expected_indent: int) -> tuple[Any, int]:
        line_no, indent, content = cleaned[idx]
        if indent != expected_indent:
            raise ValueError(f"Line {line_no}: unexpected indentation {indent} (expected {expected_indent})")
        if _is_seq_line(content):
            seq: list[Any] = []
            while idx < len(cleaned):
                ln, ind, cnt = cleaned[idx]
                if ind < expected_indent:
                    break
                if ind > expected_indent:
                    raise ValueError(f"Line {ln}: unexpected indentation in list")
                if not _is_seq_line(cnt):
                    break
                item_str = cnt[1:].strip()
                if not item_str:
                    if idx + 1 < len(cleaned) and cleaned[idx + 1][1] > ind:
                        val, idx = parse_block(idx + 1, cleaned[idx + 1][1])
                        seq.append(val)
                        continue
                    seq.append(None)
                    idx += 1
                else:
                    seq.append(_parse_scalar_value(item_str, ln))
                    idx += 1
            return seq, idx

        mapping: dict[str, Any] = {}
        while idx < len(cleaned):
            ln, ind, cnt = cleaned[idx]
            if ind < expected_indent:
                break
            if ind > expected_indent:
                raise ValueError(f"Line {ln}: unexpected indentation in mapping")
            if _is_seq_line(cnt):
                break
            raw_key, raw_val = _split_top_level_colon(cnt, ln)
            key = _unquote_scalar(raw_key, ln)
            if not raw_val:
                if idx + 1 < len(cleaned):
                    next_ln, next_ind, next_cnt = cleaned[idx + 1]
                    if next_ind > ind:
                        val, idx = parse_block(idx + 1, next_ind)
                        mapping[key] = val
                        continue
                    if next_ind == ind and _is_seq_line(next_cnt):
                        val, idx = parse_block(idx + 1, next_ind)
                        mapping[key] = val
                        continue
                mapping[key] = None
                idx += 1
            else:
                mapping[key] = _parse_scalar_value(raw_val, ln)
                idx += 1
        return mapping, idx

    result, next_idx = parse_block(0, cleaned[0][1])
    if next_idx != len(cleaned):
        ln, _, _ = cleaned[next_idx]
        raise ValueError(f"Line {ln}: unexpected trailing content")
    if not isinstance(result, dict):
        raise ValueError("Top-level YAML structure must be a mapping")
    return result


def load_yaml_config(path: Path) -> dict[str, Any]:
    """Load my_rules.yaml with PyYAML if available, otherwise stdlib fallback parser."""
    text = path.read_text(encoding="utf-8")
    try:
        import yaml  # type: ignore

        data = yaml.safe_load(text)
    except ImportError:
        data = _parse_simple_yaml(text)
    if data is None:
        return {}
    if not isinstance(data, dict):
        raise ValueError(f"{path} top-level must be a YAML mapping")
    return data


def _parse_github_owner_repo(remote_url: str) -> tuple[str, str] | None:
    url = remote_url.strip()
    patterns = (
        r"^https?://github\.com/([^/]+)/([^/]+?)(?:\.git)?/?$",
        r"^git@github\.com:([^/]+)/([^/]+?)(?:\.git)?$",
        r"^ssh://git@github\.com/([^/]+)/([^/]+?)(?:\.git)?/?$",
    )
    for pattern in patterns:
        match = re.match(pattern, url)
        if match:
            owner, repo = match.group(1), match.group(2)
            if owner.lower() == "subconv" and repo.lower() == "zju-rule":
                return None
            return owner, repo
    return None


def detect_git_metadata(repo_root: Path) -> dict[str, str]:
    """Read .git/HEAD and .git/config in pure Python without requiring git in PATH."""
    meta = {"owner": "", "repo": "", "branch": ""}
    git_dir = repo_root / ".git"
    if not git_dir.is_dir():
        return meta

    head_file = git_dir / "HEAD"
    if head_file.is_file():
        head_text = head_file.read_text(encoding="utf-8", errors="ignore").strip()
        if head_text.startswith("ref: refs/heads/"):
            meta["branch"] = head_text[len("ref: refs/heads/") :].strip()

    config_file = git_dir / "config"
    if config_file.is_file():
        in_origin = False
        for raw_line in config_file.read_text(encoding="utf-8", errors="ignore").splitlines():
            line = raw_line.strip()
            if line.startswith("["):
                in_origin = line.lower() == '[remote "origin"]'
                continue
            if in_origin and line.lower().startswith("url"):
                _, _, value = line.partition("=")
                parsed = _parse_github_owner_repo(value)
                if parsed:
                    meta["owner"], meta["repo"] = parsed
                break
    return meta


def parse_valid_groups(ini_text: str) -> list[str]:
    """Extract all custom_proxy_group names from ZJU.ini plus DIRECT and REJECT."""
    groups: list[str] = []
    seen: set[str] = set()
    for line in ini_text.splitlines():
        stripped = line.strip()
        if stripped.startswith("custom_proxy_group="):
            rest = stripped[len("custom_proxy_group=") :]
            group_name = rest.split("`", 1)[0].strip()
            if group_name and group_name not in seen:
                groups.append(group_name)
                seen.add(group_name)
    for builtin in ("DIRECT", "REJECT"):
        if builtin not in seen:
            groups.append(builtin)
            seen.add(builtin)
    return groups


def _extract_host(raw: str) -> str:
    candidate = raw.strip()
    if "://" in candidate:
        parsed = urlsplit(candidate)
        host = parsed.hostname or ""
    else:
        host = candidate.split("/", 1)[0]
        if host.count(":") == 1 and not host.startswith("["):
            host = host.split(":", 1)[0]
    host = host.strip().lstrip(".").rstrip(".").lower()
    if not host or any(ch.isspace() for ch in host) or "," in host:
        raise ValueError(f"Invalid domain/host: {raw!r}")
    return host


def _try_ip_rule(candidate: str) -> str | None:
    cleaned = candidate.strip()
    if cleaned.startswith("[") and cleaned.endswith("]"):
        cleaned = cleaned[1:-1]
    try:
        addr = ipaddress.ip_address(cleaned)
        if addr.version == 4:
            return f"IP-CIDR,{addr}/32,no-resolve"
        return f"IP-CIDR6,{addr}/128,no-resolve"
    except ValueError:
        pass
    if "/" in cleaned:
        try:
            net = ipaddress.ip_network(cleaned, strict=False)
            if net.version == 4:
                return f"IP-CIDR,{net},no-resolve"
            return f"IP-CIDR6,{net},no-resolve"
        except ValueError:
            pass
    return None


def normalize_rule_entry(raw: Any) -> str:
    """Normalize a user-written shorthand or native Clash rule into canonical Clash syntax."""
    if not isinstance(raw, str):
        raise ValueError(f"Rule entry must be a string, got {type(raw).__name__}: {raw!r}")
    s = raw.strip()
    if not s:
        raise ValueError("Empty rule entry is not allowed")

    upper = s.upper()
    for prefix in NATIVE_PREFIXES:
        if upper.startswith(prefix + ","):
            rest = s[len(prefix) + 1 :].strip()
            if not rest:
                raise ValueError(f"Native rule missing target: {raw!r}")
            return f"{prefix},{rest}"

    if s.startswith("="):
        host = _extract_host(s[1:])
        return f"DOMAIN,{host}"

    # Check "*." BEFORE "*" keyword so "*.example.com" becomes DOMAIN-SUFFIX, not DOMAIN-KEYWORD.
    if s.startswith("*."):
        domain = _extract_host(s[2:])
        return f"DOMAIN-SUFFIX,{domain}"

    if s.startswith("*"):
        keyword = s[1:].strip().lower()
        if not keyword or any(ch.isspace() for ch in keyword) or "," in keyword:
            raise ValueError(f"Invalid keyword rule: {raw!r}")
        return f"DOMAIN-KEYWORD,{keyword}"

    if "://" in s:
        parsed = urlsplit(s)
        host = (parsed.hostname or "").strip().lower()
        if not host:
            raise ValueError(f"Could not extract hostname from URL: {raw!r}")
        ip_rule = _try_ip_rule(host)
        if ip_rule:
            return ip_rule
        return f"DOMAIN-SUFFIX,{host}"

    ip_rule = _try_ip_rule(s)
    if ip_rule:
        return ip_rule

    domain = _extract_host(s)
    return f"DOMAIN-SUFFIX,{domain}"


def _build_custom_slug(group_name: str, index: int) -> str:
    ascii_part = re.sub(r"[^A-Za-z0-9]+", "", group_name)
    if ascii_part:
        return f"CustomExtra_{index}_{ascii_part}"
    return f"CustomExtra_{index}"


def _format_provider_yaml(rules: list[str]) -> str:
    lines = ["payload:"]
    for rule in rules:
        if rule.startswith(("USER-AGENT,", "URL-REGEX,", "PROCESS-NAME,")):
            lines.append(f"  # {rule}")
        else:
            lines.append(f"  - {rule}")
    return "\n".join(lines) + "\n"


def _format_list_file(group_name: str, rules: list[str]) -> str:
    lines = [f"# Custom rules for {group_name} (generated from my_rules.yaml)"]
    lines.extend(rules)
    return "\n".join(lines) + "\n"


def _apply_mirror(url: str, mirror_prefix: str) -> str:
    if not mirror_prefix:
        return url
    prefix = mirror_prefix.rstrip("/") + "/"
    if url.startswith("https://raw.githubusercontent.com/"):
        return prefix + url
    return url


def _resolve_raw_base(
    github_cfg: dict[str, Any], git_meta: dict[str, str], require_owner_repo: bool
) -> tuple[str, str, str, str]:
    owner = str(github_cfg.get("owner") or "").strip() or git_meta.get("owner", "")
    repo = str(github_cfg.get("repo") or "").strip() or git_meta.get("repo", "")
    branch = str(github_cfg.get("branch") or "").strip() or git_meta.get("branch", "") or "my-rules"
    if not repo and owner:
        repo = "ZJU-Rule"
    if require_owner_repo and (not owner or not repo):
        raise ValueError(
            "ruleset_mode='url' 或 upstream_mode='self' 需要有效的 GitHub owner/repo。\n"
            "请在 my_rules.yaml 的 github.owner / github.repo 中填写，或先执行:\n"
            "  git remote add origin https://github.com/<你的用户名>/<仓库名>.git"
        )
    raw_base = f"https://raw.githubusercontent.com/{owner}/{repo}/{branch}" if owner and repo else ""
    return owner, repo, branch, raw_base


def generate_custom_rules(
    repo_root: Path,
    config_path: Path,
    base_ini_path: Path,
    out_ini_path: Path,
    dry_run: bool = False,
) -> dict[str, Any]:
    """Validate config, normalize rules, generate MyZJU.ini and Clash/Custom artifacts."""
    if not config_path.is_file():
        raise FileNotFoundError(f"Config file not found: {config_path}")
    if not base_ini_path.is_file():
        raise FileNotFoundError(f"Base INI file not found: {base_ini_path}")

    cfg = load_yaml_config(config_path)
    base_ini_text = base_ini_path.read_text(encoding="utf-8")
    valid_groups = parse_valid_groups(base_ini_text)
    valid_group_set = set(valid_groups)

    github_cfg = cfg.get("github") or {}
    if not isinstance(github_cfg, dict):
        raise ValueError("'github' section in my_rules.yaml must be a mapping")
    ruleset_mode = str(github_cfg.get("ruleset_mode") or "inline").strip().lower()
    upstream_mode = str(github_cfg.get("upstream_mode") or "upstream").strip().lower()
    raw_mirror_prefix = str(github_cfg.get("raw_mirror_prefix") or "").strip()

    if ruleset_mode not in ("inline", "url"):
        raise ValueError(f"Invalid github.ruleset_mode: {ruleset_mode!r} (must be 'inline' or 'url')")
    if upstream_mode not in ("upstream", "self"):
        raise ValueError(f"Invalid github.upstream_mode: {upstream_mode!r} (must be 'upstream' or 'self')")

    git_meta = detect_git_metadata(repo_root)
    require_owner_repo = ruleset_mode == "url" or upstream_mode == "self"
    owner, repo, branch, raw_base = _resolve_raw_base(github_cfg, git_meta, require_owner_repo)

    rules_section = cfg.get("rules") or {}
    if not isinstance(rules_section, dict):
        raise ValueError("'rules' section in my_rules.yaml must be a mapping")
    custom_groups_section = cfg.get("custom_groups") or {}
    if not isinstance(custom_groups_section, dict):
        raise ValueError("'custom_groups' section in my_rules.yaml must be a mapping")

    unknown_aliases = [k for k in rules_section if k not in GROUP_ALIASES]
    if unknown_aliases:
        raise ValueError(
            f"Unknown group alias(es) in 'rules': {', '.join(unknown_aliases)}. "
            "Run with --list-groups to see valid aliases."
        )

    # Ordered list of (group_name, file_stem, raw_entries)
    ordered_targets: list[tuple[str, str, list[Any]]] = []
    for alias, (group_name, file_stem) in GROUP_ALIASES.items():
        entries = rules_section.get(alias)
        if entries is None:
            continue
        if not isinstance(entries, list):
            raise ValueError(f"rules.{alias} must be a list")
        if entries:
            ordered_targets.append((group_name, file_stem, entries))

    for idx, (group_name, entries) in enumerate(custom_groups_section.items(), start=1):
        if entries is None:
            continue
        if not isinstance(entries, list):
            raise ValueError(f"custom_groups[{group_name!r}] must be a list")
        if not entries:
            continue
        if group_name not in valid_group_set:
            raise ValueError(
                f"Group {group_name!r} in custom_groups does not exist in {base_ini_path.name}.\n"
                f"Valid groups: {', '.join(valid_groups)}"
            )
        ordered_targets.append((group_name, _build_custom_slug(group_name, idx), entries))

    for group_name, _, _ in ordered_targets:
        if group_name not in valid_group_set:
            raise ValueError(
                f"Target group {group_name!r} does not exist in {base_ini_path.name}.\n"
                f"Valid groups: {', '.join(valid_groups)}"
            )

    warnings: list[str] = []
    seen_global: dict[str, str] = {}
    # Merge normalized rules by (group_name, file_stem) while preserving first-seen order.
    grouped_rules: list[tuple[str, str, list[str]]] = []
    for group_name, file_stem, raw_entries in ordered_targets:
        deduped: list[str] = []
        seen_local: set[str] = set()
        for entry in raw_entries:
            norm = normalize_rule_entry(entry)
            if norm in seen_local:
                continue
            seen_local.add(norm)
            if norm in seen_global and seen_global[norm] != group_name:
                warnings.append(
                    f"规则 {norm!r} 同时出现在 {seen_global[norm]} 和 {group_name} 中，"
                    f"将优先命中 {seen_global[norm]}。"
                )
            else:
                seen_global[norm] = group_name
            deduped.append(norm)
        if deduped:
            grouped_rules.append((group_name, file_stem, deduped))

    # Build custom ruleset lines for MyZJU.ini.
    custom_ini_lines: list[str] = [BEGIN_BLOCK]
    if not grouped_rules:
        custom_ini_lines.append("; (my_rules.yaml 当前未配置自定义规则)")
    elif ruleset_mode == "inline":
        for group_name, _, rules in grouped_rules:
            for rule in rules:
                custom_ini_lines.append(f"ruleset={group_name},[]{rule}")
    else:
        for group_name, file_stem, _ in grouped_rules:
            list_url = _apply_mirror(f"{raw_base}/Clash/Custom/{file_stem}.list", raw_mirror_prefix)
            custom_ini_lines.append(f"ruleset={group_name},{list_url}")
    custom_ini_lines.append(END_BLOCK)

    # Inject after the first `;设置规则标志位` marker and optionally rewrite upstream URLs.
    base_lines = base_ini_text.splitlines()
    marker_idx: int | None = None
    for idx, line in enumerate(base_lines):
        if line.strip() == MARKER_LINE:
            marker_idx = idx
            break
    if marker_idx is None:
        raise ValueError(f"Could not find marker line {MARKER_LINE!r} in {base_ini_path}")

    out_lines: list[str] = []
    for idx, line in enumerate(base_lines):
        processed_line = line
        if line.startswith("ruleset="):
            if upstream_mode == "self" and UPSTREAM_RAW_PREFIX in processed_line:
                processed_line = processed_line.replace(UPSTREAM_RAW_PREFIX, f"{raw_base}/")
            if raw_mirror_prefix and "https://raw.githubusercontent.com/" in processed_line:
                processed_line = processed_line.replace(
                    "https://raw.githubusercontent.com/",
                    raw_mirror_prefix.rstrip("/") + "/https://raw.githubusercontent.com/",
                )
        out_lines.append(processed_line)
        if idx == marker_idx:
            out_lines.extend(custom_ini_lines)

    out_ini_text = "\n".join(out_lines) + "\n"

    custom_list_dir = repo_root / "Clash" / "Custom"
    custom_provider_dir = repo_root / "Clash" / "Providers" / "Custom"
    expected_list_files = {f"{stem}.list": (grp, rules) for grp, stem, rules in grouped_rules}
    expected_yaml_files = {f"{stem}.yaml": rules for _, stem, rules in grouped_rules}

    written_files: list[Path] = []
    removed_files: list[Path] = []

    if not dry_run:
        out_ini_path.parent.mkdir(parents=True, exist_ok=True)
        out_ini_path.write_text(out_ini_text, encoding="utf-8", newline="\n")
        written_files.append(out_ini_path)

        if expected_list_files:
            custom_list_dir.mkdir(parents=True, exist_ok=True)
            for fname, (grp, rules) in expected_list_files.items():
                p = custom_list_dir / fname
                p.write_text(_format_list_file(grp, rules), encoding="utf-8", newline="\n")
                written_files.append(p)
        if custom_list_dir.is_dir():
            for existing in list(custom_list_dir.glob("*.list")):
                if existing.name not in expected_list_files:
                    existing.unlink()
                    removed_files.append(existing)
            if not any(custom_list_dir.iterdir()):
                custom_list_dir.rmdir()

        if expected_yaml_files:
            custom_provider_dir.mkdir(parents=True, exist_ok=True)
            for fname, rules in expected_yaml_files.items():
                p = custom_provider_dir / fname
                p.write_text(_format_provider_yaml(rules), encoding="utf-8", newline="\n")
                written_files.append(p)
        if custom_provider_dir.is_dir():
            for existing in list(custom_provider_dir.glob("*.yaml")):
                if existing.name not in expected_yaml_files:
                    existing.unlink()
                    removed_files.append(existing)
            if not any(custom_provider_dir.iterdir()):
                custom_provider_dir.rmdir()

    return {
        "grouped_rules": grouped_rules,
        "total_rules": sum(len(rules) for _, _, rules in grouped_rules),
        "warnings": warnings,
        "ruleset_mode": ruleset_mode,
        "upstream_mode": upstream_mode,
        "owner": owner,
        "repo": repo,
        "branch": branch,
        "raw_base": raw_base,
        "written_files": written_files,
        "removed_files": removed_files,
        "out_ini_path": out_ini_path,
    }


def main(argv: list[str] | None = None) -> int:
    for stream in (sys.stdout, sys.stderr):
        if hasattr(stream, "reconfigure"):
            try:
                stream.reconfigure(errors="replace")
            except Exception:
                pass
    default_root = Path(__file__).resolve().parent
    parser = argparse.ArgumentParser(
        description="Apply custom website VPN rules from my_rules.yaml to Clash/config/MyZJU.ini."
    )
    parser.add_argument("--repo-root", type=Path, default=default_root, help="Repository root path")
    parser.add_argument("--config", type=Path, default=None, help="Path to my_rules.yaml")
    parser.add_argument("--base-ini", type=Path, default=None, help="Path to upstream Clash/config/ZJU.ini")
    parser.add_argument("--out-ini", type=Path, default=None, help="Output path for MyZJU.ini")
    parser.add_argument("--dry-run", action="store_true", help="Validate and preview without writing files")
    parser.add_argument("--list-groups", action="store_true", help="List supported aliases and valid ZJU.ini groups")
    args = parser.parse_args(argv)

    repo_root = args.repo_root.resolve()
    config_path = (args.config or (repo_root / "my_rules.yaml")).resolve()
    base_ini_path = (args.base_ini or (repo_root / "Clash" / "config" / "ZJU.ini")).resolve()
    out_ini_path = (args.out_ini or (repo_root / "Clash" / "config" / "MyZJU.ini")).resolve()

    if args.list_groups:
        ini_text = base_ini_path.read_text(encoding="utf-8")
        valid_groups = parse_valid_groups(ini_text)
        print("=== my_rules.yaml 内置别名 -> ZJU.ini 策略组 ===")
        for alias, (group_name, _) in GROUP_ALIASES.items():
            print(f"  {alias:<15} -> {group_name}")
        print("\n=== ZJU.ini 全部可用策略组（可用于 custom_groups） ===")
        for grp in valid_groups:
            print(f"  - {grp}")
        return 0

    try:
        result = generate_custom_rules(
            repo_root=repo_root,
            config_path=config_path,
            base_ini_path=base_ini_path,
            out_ini_path=out_ini_path,
            dry_run=args.dry_run,
        )
    except (FileNotFoundError, ValueError) as exc:
        print(f"错误: {exc}", file=sys.stderr)
        return 1

    mode_tag = "[DRY-RUN] " if args.dry_run else ""
    print(f"{mode_tag}已处理完成：共 {result['total_rules']} 条自定义规则，分布于 {len(result['grouped_rules'])} 个分组。")
    for group_name, _, rules in result["grouped_rules"]:
        print(f"  - {group_name}: {len(rules)} 条")
    if result["warnings"]:
        print("\n警告:")
        for w in result["warnings"]:
            print(f"  ! {w}")
    if result["written_files"]:
        print("\n生成/更新的文件:")
        for p in result["written_files"]:
            print(f"  + {p.relative_to(repo_root)}")
    if result["removed_files"]:
        print("\n已清理的旧规则文件:")
        for p in result["removed_files"]:
            print(f"  - {p.relative_to(repo_root)}")

    branch = result["branch"] or "my-rules"
    if result["raw_base"]:
        ini_url = f"{result['raw_base']}/Clash/config/MyZJU.ini"
    else:
        ini_url = f"https://raw.githubusercontent.com/<你的GitHub用户名>/<你的仓库名>/{branch}/Clash/config/MyZJU.ini"
    print(f"\nSubconverter 远程配置链接（推送分支后使用）:\n  {ini_url}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
