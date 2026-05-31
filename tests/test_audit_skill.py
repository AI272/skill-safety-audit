from __future__ import annotations

import importlib.util
import json
from pathlib import Path
import sys


ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "audit_skill.py"


def load_module():
    spec = importlib.util.spec_from_file_location("audit_skill", SCRIPT)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module


def run_audit(target: Path):
    module = load_module()
    rules = module.load_rules(ROOT / "scripts")
    findings, _root = module.scan_files(target, rules)
    return module.build_report(str(target), findings)


def test_benign_skill_is_safe():
    report = run_audit(ROOT / "examples" / "benign-skill")
    assert report["verdict"] == "SAFE"
    assert report["recommendation"] == "install"


def test_curl_pipe_bash_is_dangerous():
    report = run_audit(ROOT / "examples" / "dangerous-skill")
    assert report["verdict"] == "DANGEROUS"
    assert any(item["rule_id"] == "curl_pipe_shell" for item in report["findings"])


def test_secret_path_is_dangerous():
    report = run_audit(ROOT / "examples" / "dangerous-skill")
    assert report["verdict"] == "DANGEROUS"
    assert any(item["rule_id"] == "secret_path_access" for item in report["findings"])


def test_prompt_injection_is_at_least_review():
    report = run_audit(ROOT / "examples" / "suspicious-skill")
    assert report["verdict"] in {"REVIEW", "DANGEROUS"}
    assert any(item["category"] == "prompt_injection" for item in report["findings"])


def test_missing_skill_md_returns_review(tmp_path: Path):
    (tmp_path / "README.md").write_text("not a skill\n", encoding="utf-8")
    report = run_audit(tmp_path)
    assert report["verdict"] == "REVIEW"
    assert any(item["rule_id"] == "missing_skill_md" for item in report["findings"])


def test_json_output_contains_required_keys(tmp_path: Path):
    module = load_module()
    target = ROOT / "examples" / "benign-skill"
    exit_code = module.main([str(target), "--format", "json", "--output-dir", str(tmp_path)])
    assert exit_code == 0
    payload = json.loads((tmp_path / "skill_security_report.json").read_text(encoding="utf-8"))
    for key in {"verdict", "risk_score", "summary", "findings", "recommendation"}:
        assert key in payload


def test_markdown_output_contains_required_sections(tmp_path: Path):
    module = load_module()
    target = ROOT / "examples" / "dangerous-skill"
    exit_code = module.main([str(target), "--format", "markdown", "--output-dir", str(tmp_path)])
    assert exit_code == 0
    text = (tmp_path / "SKILL_SECURITY_REPORT.md").read_text(encoding="utf-8")
    assert "Verdict" in text
    assert "Risk score" in text
    assert "Findings" in text
    assert "Recommendation" in text


def test_github_url_parser_handles_root_and_tree():
    module = load_module()
    assert module.parse_github_url("https://github.com/user/repo") == ("user", "repo", "main", "")
    assert module.parse_github_url("https://github.com/user/repo/tree/dev/skills/foo") == (
        "user",
        "repo",
        "dev",
        "skills/foo",
    )
