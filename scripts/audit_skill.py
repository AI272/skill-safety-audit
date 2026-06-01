#!/usr/bin/env python3
"""Static security auditor for SKILL.md-based Agent Skills."""

from __future__ import annotations

import argparse
import ast
from dataclasses import dataclass, field
from datetime import datetime, timezone
import fnmatch
import hashlib
import json
import math
import os
from pathlib import Path
import re
import subprocess
import sys
import tempfile
import urllib.parse
import urllib.request
import zipfile


TOOL_VERSION = "1.1.0"
TEXT_EXTENSIONS = {
    ".md",
    ".txt",
    ".py",
    ".sh",
    ".bash",
    ".zsh",
    ".js",
    ".ts",
    ".tsx",
    ".jsx",
    ".json",
    ".yaml",
    ".yml",
    ".toml",
    ".ini",
    ".cfg",
    ".env",
    ".lock",
}
MAX_TEXT_BYTES = 1_000_000
SEVERITY_POINTS = {"critical": 40, "high": 20, "medium": 10, "low": 3}
EXIT_CODES = {"SAFE": 0, "REVIEW": 1, "DANGEROUS": 2}
CAPABILITY_BY_CATEGORY = {
    "network": "network",
    "secret_access": "secrets",
    "shell": "shell",
    "install": "install",
    "persistence": "persistence",
}
COMMON_TYPOSQUATS = {
    "reqeusts": "requests",
    "requestes": "requests",
    "python-dateuti1": "python-dateutil",
    "beautifulsoup": "beautifulsoup4",
    "yaml": "pyyaml",
    "node-fetchs": "node-fetch",
    "expres": "express",
}


@dataclass
class ScanOptions:
    rules_files: list[Path]
    ignore_file: Path | None = None
    online_deps: bool = False
    since: str | None = None
    target_ref: str | None = None
    target_sha256: str | None = None


@dataclass
class ScanState:
    declared_capabilities: set[str] = field(default_factory=set)
    observed_capabilities: set[str] = field(default_factory=set)
    suppressed_findings: list[dict] = field(default_factory=list)
    metadata: dict = field(default_factory=dict)


def load_rule_payload(path: Path) -> dict:
    with path.open("r", encoding="utf-8") as handle:
        return json.load(handle)


def load_rules(script_dir: Path, extra_rules: list[str] | None = None) -> tuple[list[dict], dict]:
    rules_files = [script_dir / "rules.yaml"]
    rules_files.extend(Path(item).expanduser().resolve() for item in extra_rules or [])
    merged: dict[str, dict] = {}
    versions: list[str] = []
    for path in rules_files:
        payload = load_rule_payload(path)
        if "version" in payload:
            versions.append(str(payload["version"]))
        for rule in payload.get("rules", []):
            merged[rule["id"]] = rule
    rules = list(merged.values())
    rules_hash = hashlib.sha256(
        json.dumps(rules, sort_keys=True, separators=(",", ":")).encode("utf-8")
    ).hexdigest()
    return rules, {
        "rules_hash": rules_hash,
        "rules_files": [str(path) for path in rules_files],
        "rules_versions": versions,
    }


def parse_github_url(raw_url: str) -> tuple[str, str, str, str]:
    parsed = urllib.parse.urlparse(raw_url)
    if parsed.netloc.lower() != "github.com":
        raise ValueError("only github.com URLs are supported")
    parts = [part for part in parsed.path.split("/") if part]
    if len(parts) < 2:
        raise ValueError("GitHub URL must include owner and repo")
    owner, repo = parts[0], parts[1]
    ref = "main"
    subpath = ""
    if len(parts) > 2:
        if parts[2] not in {"tree", "blob"}:
            subpath = "/".join(parts[2:])
        else:
            if len(parts) < 4:
                raise ValueError("GitHub tree/blob URL must include a ref")
            ref = parts[3]
            subpath = "/".join(parts[4:])
    return owner, repo, ref, subpath


def safe_extract(zip_file: zipfile.ZipFile, dest_dir: Path) -> None:
    dest_root = dest_dir.resolve()
    for info in zip_file.infolist():
        target = (dest_dir / info.filename).resolve()
        if target != dest_root and not str(target).startswith(str(dest_root) + os.sep):
            raise ValueError("archive contains files outside extraction directory")
    zip_file.extractall(dest_dir)


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def download_github_source(raw_url: str, ref_override: str | None = None) -> tuple[Path, tempfile.TemporaryDirectory, dict]:
    owner, repo, ref, subpath = parse_github_url(raw_url)
    if ref_override:
        ref = ref_override
    tmp = tempfile.TemporaryDirectory(prefix="skill-audit-")
    tmp_path = Path(tmp.name)
    zip_url = f"https://codeload.github.com/{owner}/{repo}/zip/{ref}"
    archive_path = tmp_path / "repo.zip"
    urllib.request.urlretrieve(zip_url, archive_path)
    archive_sha = sha256_file(archive_path)
    with zipfile.ZipFile(archive_path) as zip_file:
        safe_extract(zip_file, tmp_path)
        roots = {name.split("/")[0] for name in zip_file.namelist() if name}
    if len(roots) != 1:
        tmp.cleanup()
        raise ValueError("unexpected GitHub archive layout")
    root = tmp_path / next(iter(roots))
    target = root / subpath if subpath else root
    if not target.exists():
        tmp.cleanup()
        raise FileNotFoundError(f"GitHub path not found: {subpath or '.'}")
    metadata = {
        "github_owner": owner,
        "github_repo": repo,
        "target_ref": ref,
        "target_sha256": archive_sha,
        "source_archive": zip_url,
    }
    return target, tmp, metadata


def resolve_target(target: str, ref_override: str | None = None) -> tuple[Path, tempfile.TemporaryDirectory | None, str, dict]:
    if target.startswith("https://github.com/"):
        path, tmp, metadata = download_github_source(target, ref_override)
        return path, tmp, target, metadata
    path = Path(target).expanduser().resolve()
    if not path.exists():
        raise FileNotFoundError(f"target not found: {target}")
    metadata = {
        "target_ref": ref_override,
        "target_sha256": sha256_file(path) if path.is_file() else directory_hash(path),
    }
    return path, None, str(path), metadata


def directory_hash(root: Path) -> str:
    digest = hashlib.sha256()
    for path in sorted(item for item in root.rglob("*") if item.is_file()):
        try:
            rel = str(path.relative_to(root))
            digest.update(rel.encode("utf-8"))
            digest.update(path.read_bytes())
        except OSError:
            continue
    return digest.hexdigest()


def is_probably_binary(data: bytes) -> bool:
    if b"\0" in data:
        return True
    if not data:
        return False
    sample = data[:4096]
    text_chars = sum(1 for byte in sample if byte in b"\n\r\t" or 32 <= byte <= 126)
    return text_chars / len(sample) < 0.75


def iter_files(target: Path) -> list[Path]:
    if target.is_file():
        return [target]
    ignored_dirs = {".git", "__pycache__", ".pytest_cache"}
    return [
        path
        for path in target.rglob("*")
        if path.is_file() and not any(part in ignored_dirs for part in path.parts)
    ]


def read_text_file(path: Path) -> tuple[str | None, str | None]:
    try:
        data = path.read_bytes()
    except OSError as exc:
        return None, f"could not read file: {exc}"
    if len(data) > MAX_TEXT_BYTES:
        return None, "large file skipped"
    if is_probably_binary(data):
        return None, "binary file skipped"
    try:
        return data.decode("utf-8"), None
    except UnicodeDecodeError:
        return data.decode("utf-8", errors="replace"), None


def relpath(path: Path, root: Path) -> str:
    try:
        return str(path.relative_to(root))
    except ValueError:
        return path.name


def line_for_offset(text: str, offset: int) -> int:
    return text.count("\n", 0, offset) + 1


def evidence_at(text: str, offset: int) -> str:
    line_start = text.rfind("\n", 0, offset) + 1
    line_end = text.find("\n", offset)
    if line_end == -1:
        line_end = len(text)
    return text[line_start:line_end].strip()[:220]


def finding(
    severity: str,
    category: str,
    file_name: str,
    line: int,
    evidence: str,
    recommendation: str,
    rule_id: str,
) -> dict:
    return {
        "severity": severity,
        "category": category,
        "file": file_name,
        "line": line,
        "evidence": evidence,
        "recommendation": recommendation,
        "rule_id": rule_id,
    }


def parse_frontmatter(text: str) -> dict[str, str | list[str]]:
    frontmatter_match = re.match(r"^---\s*\n(.*?)\n---\s*", text, re.DOTALL)
    if not frontmatter_match:
        return {}
    data: dict[str, str | list[str]] = {}
    key: str | None = None
    for raw_line in frontmatter_match.group(1).splitlines():
        line = raw_line.rstrip()
        if not line.strip():
            continue
        list_match = re.match(r"^\s*-\s*(.+)$", line)
        if list_match and key:
            if not isinstance(data.get(key), list):
                data[key] = []
            if isinstance(data[key], list):
                data[key].append(list_match.group(1).strip().strip("\"'"))
            continue
        match = re.match(r"^([A-Za-z0-9_-]+)\s*:\s*(.*)$", line)
        if match:
            key = match.group(1)
            value = match.group(2).strip().strip("\"'")
            if value.startswith("[") and value.endswith("]"):
                data[key] = [item.strip().strip("\"'") for item in value[1:-1].split(",") if item.strip()]
            else:
                data[key] = value
    return data


def validate_skill_structure(target: Path, root: Path, state: ScanState) -> list[dict]:
    findings: list[dict] = []
    skill_md = target if target.is_file() and target.name == "SKILL.md" else target / "SKILL.md"
    if not skill_md.exists():
        findings.append(
            finding(
                "high",
                "structure",
                "SKILL.md",
                1,
                "SKILL.md not found in selected target.",
                "Confirm the target points to a skill directory before installing.",
                "missing_skill_md",
            )
        )
        return findings

    text, error = read_text_file(skill_md)
    file_name = relpath(skill_md, root)
    if error or text is None:
        findings.append(
            finding(
                "medium",
                "structure",
                file_name,
                1,
                error or "could not read SKILL.md",
                "Review the SKILL.md manually before installing.",
                "unreadable_skill_md",
            )
        )
        return findings

    frontmatter = parse_frontmatter(text)
    if not frontmatter:
        findings.append(
            finding(
                "medium",
                "structure",
                file_name,
                1,
                "SKILL.md has no YAML frontmatter block.",
                "Add standard frontmatter with name and description.",
                "invalid_frontmatter",
            )
        )
        return findings
    expected = frontmatter.get("expected-capabilities", [])
    if isinstance(expected, str) and expected:
        expected = [expected]
    if isinstance(expected, list):
        state.declared_capabilities.update(item.strip().lower() for item in expected if item.strip())
    if not frontmatter.get("name"):
        findings.append(
            finding(
                "medium",
                "structure",
                file_name,
                1,
                "SKILL.md frontmatter is missing name.",
                "Add a clear skill name.",
                "missing_name",
            )
        )
    if not frontmatter.get("description"):
        findings.append(
            finding(
                "medium",
                "structure",
                file_name,
                1,
                "SKILL.md frontmatter is missing description.",
                "Add a trigger-oriented description.",
                "missing_description",
            )
        )
    return findings


def read_ignore_rules(root: Path, explicit: Path | None) -> list[tuple[str, str]]:
    ignore_path = explicit or root / ".skillaudit-ignore"
    if not ignore_path.exists():
        return []
    entries: list[tuple[str, str]] = []
    text, error = read_text_file(ignore_path)
    if error or text is None:
        return entries
    for raw_line in text.splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        parts = line.split()
        rule_id = parts[0]
        pattern = parts[1] if len(parts) > 1 else "*"
        entries.append((rule_id, pattern))
    return entries


def should_suppress(item: dict, ignore_rules: list[tuple[str, str]], state: ScanState) -> bool:
    for rule_id, pattern in ignore_rules:
        if rule_id in {item["rule_id"], "*"} and fnmatch.fnmatch(item["file"], pattern):
            return True
    capability = CAPABILITY_BY_CATEGORY.get(item["category"])
    if capability in state.declared_capabilities and item["severity"] in {"low", "medium"}:
        return True
    return False


def apply_suppression(findings: list[dict], ignore_rules: list[tuple[str, str]], state: ScanState) -> list[dict]:
    active: list[dict] = []
    for item in findings:
        if should_suppress(item, ignore_rules, state):
            suppressed = dict(item)
            suppressed["suppressed"] = True
            state.suppressed_findings.append(suppressed)
        else:
            active.append(item)
    return active


def observe_from_finding(item: dict, state: ScanState) -> None:
    capability = CAPABILITY_BY_CATEGORY.get(item["category"])
    if capability:
        state.observed_capabilities.add(capability)


def scan_python_ast(text: str, file_name: str, state: ScanState) -> list[dict]:
    findings: list[dict] = []
    try:
        tree = ast.parse(text)
    except SyntaxError:
        return findings
    for node in ast.walk(tree):
        if isinstance(node, (ast.Import, ast.ImportFrom)):
            names = [alias.name.split(".")[0] for alias in getattr(node, "names", [])]
            if isinstance(node, ast.ImportFrom) and node.module:
                names.append(node.module.split(".")[0])
            if any(name in {"requests", "urllib", "httpx", "socket"} for name in names):
                state.observed_capabilities.add("network")
                findings.append(
                    finding(
                        "medium",
                        "network",
                        file_name,
                        getattr(node, "lineno", 1),
                        "Python imports outbound network-capable module.",
                        "Confirm the network access is declared and does not transmit secrets.",
                        "python_network_import",
                    )
                )
        if not isinstance(node, ast.Call):
            continue
        call_name = ast_call_name(node.func)
        line = getattr(node, "lineno", 1)
        if call_name in {"os.system", "subprocess.call", "subprocess.run", "subprocess.Popen", "subprocess.check_output"}:
            state.observed_capabilities.add("shell")
            severity = "high" if has_shell_true(node) or call_name == "os.system" else "medium"
            findings.append(
                finding(
                    severity,
                    "shell",
                    file_name,
                    line,
                    f"Python AST call detected: {call_name}",
                    "Review command construction and avoid shell execution for untrusted inputs.",
                    "python_shell_call",
                )
            )
        elif call_name in {"eval", "exec"}:
            state.observed_capabilities.add("shell")
            findings.append(
                finding(
                    "high",
                    "shell",
                    file_name,
                    line,
                    f"Python AST dynamic execution detected: {call_name}",
                    "Remove dynamic execution or make the payload explicit and constrained.",
                    "python_dynamic_exec",
                )
            )
        elif call_name == "__import__":
            findings.append(
                finding(
                    "medium",
                    "install",
                    file_name,
                    line,
                    "Python AST dynamic import detected: __import__",
                    "Review dynamic import targets and avoid importing hidden modules.",
                    "python_dynamic_import",
                )
            )
    return findings


def ast_call_name(func: ast.AST) -> str:
    if isinstance(func, ast.Name):
        return func.id
    if isinstance(func, ast.Attribute):
        parent = ast_call_name(func.value)
        return f"{parent}.{func.attr}" if parent else func.attr
    return ""


def has_shell_true(node: ast.Call) -> bool:
    for keyword in node.keywords:
        if keyword.arg == "shell" and isinstance(keyword.value, ast.Constant) and keyword.value.value is True:
            return True
    return False


def shannon_entropy(value: str) -> float:
    if not value:
        return 0.0
    counts = {char: value.count(char) for char in set(value)}
    return -sum((count / len(value)) * math.log2(count / len(value)) for count in counts.values())


def scan_obfuscation(text: str, file_name: str) -> list[dict]:
    findings: list[dict] = []
    strings = re.findall(r"['\"]([A-Za-z0-9+/=_-]{80,})['\"]", text)
    has_decode = re.search(r"(base64|b64decode|fromhex|decode\s*\()", text, re.IGNORECASE)
    has_exec_sink = re.search(r"\b(eval|exec|os\.system|subprocess\.|bash|sh)\b", text)
    for value in strings[:5]:
        if shannon_entropy(value) < 4.2 or not has_decode:
            continue
        findings.append(
            finding(
                "high" if has_exec_sink else "medium",
                "shell" if has_exec_sink else "install",
                file_name,
                1,
                f"High-entropy encoded string with decode path ({len(value)} chars).",
                "Decode and review the payload before trusting this skill.",
                "high_entropy_decode",
            )
        )
    return findings


def scan_dependencies(path: Path, text: str, file_name: str) -> list[dict]:
    findings: list[dict] = []
    if path.name in {"requirements.txt", "requirements-dev.txt"}:
        for line_no, raw_line in enumerate(text.splitlines(), 1):
            line = raw_line.strip()
            if not line or line.startswith("#"):
                continue
            package = re.split(r"[<>=!~\\[;\\s]", line, maxsplit=1)[0].lower().replace("_", "-")
            if package in COMMON_TYPOSQUATS:
                findings.append(
                    finding(
                        "medium",
                        "install",
                        file_name,
                        line_no,
                        f"Possible typosquatting package `{package}`; did you mean `{COMMON_TYPOSQUATS[package]}`?",
                        "Verify dependency names before installing.",
                        "dependency_typosquat",
                    )
                )
    if path.name == "package.json":
        try:
            payload = json.loads(text)
        except json.JSONDecodeError:
            return findings
        scripts = payload.get("scripts", {})
        for script_name in {"preinstall", "install", "postinstall", "prepare"} & set(scripts):
            findings.append(
                finding(
                    "high",
                    "install",
                    file_name,
                    1,
                    f"npm lifecycle script `{script_name}` can execute during install.",
                    "Review lifecycle scripts before running npm install.",
                    "npm_lifecycle_script",
                )
            )
        deps = {}
        for key in ("dependencies", "devDependencies", "optionalDependencies"):
            deps.update(payload.get(key, {}))
        for name in deps:
            normalized = name.lower()
            if normalized in COMMON_TYPOSQUATS:
                findings.append(
                    finding(
                        "medium",
                        "install",
                        file_name,
                        1,
                        f"Possible typosquatting npm package `{name}`; did you mean `{COMMON_TYPOSQUATS[normalized]}`?",
                        "Verify dependency names before installing.",
                        "dependency_typosquat",
                    )
                )
    return findings


def scan_claude_config(path: Path, text: str, file_name: str) -> list[dict]:
    if path.name not in {"settings.json", "claude_desktop_config.json"}:
        return []
    findings: list[dict] = []
    try:
        payload = json.loads(text)
    except json.JSONDecodeError:
        return findings
    serialized = json.dumps(payload, ensure_ascii=False)
    if re.search(r'"hooks"|\bPreToolUse\b|\bPostToolUse\b', serialized):
        findings.append(
            finding(
                "high",
                "shell",
                file_name,
                1,
                "Claude Code hook configuration can run local commands.",
                "Review hook commands before trusting this skill or plugin.",
                "claude_hook_command",
            )
        )
    if re.search(r'"mcpServers"|\bcommand\b', serialized) and re.search(r"(bash|sh|node|python|npx|uvx)", serialized):
        findings.append(
            finding(
                "high",
                "shell",
                file_name,
                1,
                "MCP server configuration includes executable command fields.",
                "Review MCP command, args, and environment before enabling.",
                "mcp_command_config",
            )
        )
    return findings


def detect_diff_scope(target: Path, since: str | None, state: ScanState) -> set[str] | None:
    if not since or not target.is_dir():
        return None
    try:
        result = subprocess.run(
            ["git", "-C", str(target), "diff", "--name-only", since, "--"],
            check=True,
            capture_output=True,
            text=True,
        )
    except (OSError, subprocess.CalledProcessError) as exc:
        state.metadata["diff_warning"] = f"could not calculate diff from {since}: {exc}"
        return None
    changed = {line.strip() for line in result.stdout.splitlines() if line.strip()}
    state.metadata["since"] = since
    state.metadata["changed_files"] = sorted(changed)
    return changed


def scan_files(target: Path, rules: list[dict], options: ScanOptions | None = None) -> tuple[list[dict], Path, ScanState]:
    options = options or ScanOptions(rules_files=[])
    root = target.parent if target.is_file() else target
    state = ScanState(metadata={
        "tool_version": TOOL_VERSION,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "target_ref": options.target_ref,
        "target_sha256": options.target_sha256,
    })
    findings = validate_skill_structure(target, root, state)
    changed_files = detect_diff_scope(target, options.since, state)
    for path in iter_files(target):
        file_name = relpath(path, root)
        if changed_files is not None and file_name not in changed_files and path.name != "SKILL.md":
            continue
        if any(part.startswith(".") for part in Path(file_name).parts):
            if path.name not in {".gitignore", ".skillaudit-ignore"}:
                findings.append(
                    finding(
                        "low",
                        "structure",
                        file_name,
                        1,
                        "Hidden file or directory inside skill package.",
                        "Review hidden files before installation.",
                        "hidden_file",
                    )
                )

        text, error = read_text_file(path)
        if error:
            severity = "medium" if "binary" in error or "large" in error else "low"
            findings.append(
                finding(
                    severity,
                    "structure",
                    file_name,
                    1,
                    error,
                    "Review skipped files manually before installation.",
                    "skipped_file",
                )
            )
            continue
        if text is None:
            continue
        if path.suffix.lower() not in TEXT_EXTENSIONS and len(text) > 5000:
            findings.append(
                finding(
                    "low",
                    "structure",
                    file_name,
                    1,
                    "Large text file with uncommon extension.",
                    "Review this file if it can affect installation or execution.",
                    "uncommon_large_text",
                )
            )
        for rule in rules:
            regex = re.compile(rule["pattern"], re.IGNORECASE)
            for match in regex.finditer(text):
                findings.append(
                    finding(
                        rule["severity"],
                        rule["category"],
                        file_name,
                        line_for_offset(text, match.start()),
                        evidence_at(text, match.start()),
                        rule["recommendation"],
                        rule["id"],
                    )
                )
        if path.suffix == ".py":
            findings.extend(scan_python_ast(text, file_name, state))
        findings.extend(scan_obfuscation(text, file_name))
        findings.extend(scan_dependencies(path, text, file_name))
        findings.extend(scan_claude_config(path, text, file_name))

    for item in findings:
        observe_from_finding(item, state)
    findings.extend(capability_mismatch_findings(state))
    ignore_rules = read_ignore_rules(root, options.ignore_file)
    active = apply_suppression(dedupe_findings(findings), ignore_rules, state)
    return dedupe_findings(active), root, state


def capability_mismatch_findings(state: ScanState) -> list[dict]:
    if not state.observed_capabilities:
        return []
    undeclared = sorted(state.observed_capabilities - state.declared_capabilities)
    if not undeclared:
        return []
    return [
        finding(
            "low",
            "mismatch",
            "SKILL.md",
            1,
            "Observed capabilities not declared in expected-capabilities: " + ", ".join(undeclared),
            "Declare expected capabilities or remove surprising behavior.",
            "capability_mismatch",
        )
    ]


def dedupe_findings(findings: list[dict]) -> list[dict]:
    seen: set[tuple[str, str, int, str]] = set()
    unique: list[dict] = []
    for item in findings:
        key = (item["rule_id"], item["file"], item["line"], item["evidence"])
        if key in seen:
            continue
        seen.add(key)
        unique.append(item)
    return unique


def score_findings(findings: list[dict]) -> int:
    return sum(SEVERITY_POINTS.get(item["severity"], 0) for item in findings)


def verdict_for(findings: list[dict], score: int) -> str:
    if any(item["severity"] == "critical" for item in findings) or score >= 60:
        return "DANGEROUS"
    if any(item["severity"] == "high" for item in findings) or 20 <= score <= 59:
        return "REVIEW"
    return "SAFE"


def recommendation_for(verdict: str) -> str:
    if verdict == "SAFE":
        return "install"
    if verdict == "REVIEW":
        return "review manually"
    return "do not install"


def summarize(verdict: str, findings: list[dict]) -> str:
    if verdict == "SAFE":
        return "No high or critical static risks were detected."
    top = sorted(findings, key=lambda item: SEVERITY_POINTS.get(item["severity"], 0), reverse=True)[:3]
    categories = ", ".join(dict.fromkeys(item["category"] for item in top))
    return f"Static audit found {len(findings)} finding(s); highest-risk categories: {categories}."


def build_report(target_label: str, findings: list[dict], state: ScanState | None = None, rules_meta: dict | None = None) -> dict:
    state = state or ScanState()
    rules_meta = rules_meta or {}
    score = score_findings(findings)
    verdict = verdict_for(findings, score)
    metadata = {
        "tool_version": TOOL_VERSION,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        **state.metadata,
        **rules_meta,
    }
    report = {
        "tool_version": TOOL_VERSION,
        "target": target_label,
        "verdict": verdict,
        "risk_score": score,
        "exit_code": EXIT_CODES[verdict],
        "summary": summarize(verdict, findings),
        "declared_capabilities": sorted(state.declared_capabilities),
        "observed_capabilities": sorted(state.observed_capabilities),
        "capability_mismatches": sorted(state.observed_capabilities - state.declared_capabilities),
        "findings": findings,
        "suppressed_findings": state.suppressed_findings,
        "recommendation": recommendation_for(verdict),
        "metadata": metadata,
    }
    return report


def render_markdown(report: dict) -> str:
    lines = [
        "# Skill Security Report",
        "",
        f"**Target:** `{report['target']}`",
        f"**Tool version:** `{report['tool_version']}`",
        f"**Verdict:** `{report['verdict']}`",
        f"**Risk score:** `{report['risk_score']}`",
        f"**Exit code:** `{report['exit_code']}`",
        f"**Recommendation:** `{report['recommendation']}`",
        "",
        report["summary"],
        "",
        "## Reproducibility Metadata",
        "",
        f"- Target ref: `{report['metadata'].get('target_ref') or 'local'}`",
        f"- Target SHA256: `{report['metadata'].get('target_sha256') or 'unknown'}`",
        f"- Rules hash: `{report['metadata'].get('rules_hash') or 'unknown'}`",
        f"- Generated at: `{report['metadata'].get('generated_at')}`",
        "",
        "## Capability Declaration vs Observed Behavior",
        "",
        "| Declared capabilities | Observed capabilities | Mismatches |",
        "|---|---|---|",
        f"| {', '.join(report['declared_capabilities']) or 'none'} | "
        f"{', '.join(report['observed_capabilities']) or 'none'} | "
        f"{', '.join(report['capability_mismatches']) or 'none'} |",
        "",
        "## Findings",
        "",
    ]
    if not report["findings"]:
        lines.append("No active findings.")
    else:
        lines.append("| Severity | Category | Rule | File | Line | Evidence | Recommendation |")
        lines.append("|---|---|---|---|---:|---|---|")
        for item in report["findings"]:
            evidence = str(item["evidence"]).replace("|", "\\|")
            recommendation = str(item["recommendation"]).replace("|", "\\|")
            lines.append(
                f"| {item['severity']} | {item['category']} | `{item['rule_id']}` | `{item['file']}` | "
                f"{item['line']} | {evidence} | {recommendation} |"
            )
    if report.get("suppressed_findings"):
        lines.extend(["", "## Suppressed Findings", ""])
        lines.append("| Severity | Category | Rule | File | Line | Evidence |")
        lines.append("|---|---|---|---|---:|---|")
        for item in report["suppressed_findings"]:
            evidence = str(item["evidence"]).replace("|", "\\|")
            lines.append(
                f"| {item['severity']} | {item['category']} | `{item['rule_id']}` | `{item['file']}` | "
                f"{item['line']} | {evidence} |"
            )
    lines.extend(
        [
            "",
            "## Limitations",
            "",
            "This is a static, conservative scan. It does not execute the target skill or prove runtime behavior.",
        ]
    )
    return "\n".join(lines) + "\n"


def write_outputs(report: dict, output_dir: Path) -> tuple[Path, Path]:
    output_dir.mkdir(parents=True, exist_ok=True)
    json_path = output_dir / "skill_security_report.json"
    md_path = output_dir / "SKILL_SECURITY_REPORT.md"
    json_path.write_text(json.dumps(report, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    md_path.write_text(render_markdown(report), encoding="utf-8")
    return json_path, md_path


def parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Static security auditor for Agent Skills.")
    parser.add_argument("target", help="Local path, SKILL.md file, GitHub repo URL, or GitHub tree URL")
    parser.add_argument("--format", choices=["markdown", "json"], default="markdown")
    parser.add_argument("--output-dir", default=".", help="Directory for report files")
    parser.add_argument("--rules", action="append", default=[], help="Additional JSON/YAML-subset rules file; may be repeated")
    parser.add_argument("--ref", dest="ref", help="GitHub ref or commit SHA to download and record")
    parser.add_argument("--online-deps", action="store_true", help="Reserved opt-in for future OSV/deps.dev dependency checks")
    parser.add_argument("--since", help="For local Git targets, scan only files changed since this ref")
    parser.add_argument("--ignore-file", help="Path to .skillaudit-ignore baseline file")
    return parser.parse_args(argv)


def main(argv: list[str]) -> int:
    args = parse_args(argv)
    tmp: tempfile.TemporaryDirectory | None = None
    try:
        target, tmp, target_label, target_meta = resolve_target(args.target, args.ref)
        rules, rules_meta = load_rules(Path(__file__).resolve().parent, args.rules)
        options = ScanOptions(
            rules_files=[Path(path) for path in rules_meta.get("rules_files", [])],
            ignore_file=Path(args.ignore_file).expanduser().resolve() if args.ignore_file else None,
            online_deps=args.online_deps,
            since=args.since,
            target_ref=target_meta.get("target_ref"),
            target_sha256=target_meta.get("target_sha256"),
        )
        findings, _root, state = scan_files(target, rules, options)
        state.metadata.update(target_meta)
        if args.online_deps:
            state.metadata["online_deps"] = "requested"
        report = build_report(target_label, findings, state, rules_meta)
        write_outputs(report, Path(args.output_dir).resolve())
        if args.format == "json":
            print(json.dumps(report, indent=2, ensure_ascii=False))
        else:
            print(render_markdown(report))
        return EXIT_CODES[report["verdict"]]
    except Exception as exc:  # noqa: BLE001 - CLI should return readable failures.
        print(f"error: {exc}", file=sys.stderr)
        return 3
    finally:
        if tmp is not None:
            tmp.cleanup()


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
