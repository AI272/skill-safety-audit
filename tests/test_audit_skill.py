from __future__ import annotations

import importlib.util
import json
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "audit_skill.py"


def load_module():
    spec = importlib.util.spec_from_file_location("audit_skill", SCRIPT)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    import sys

    sys.modules["audit_skill"] = module
    spec.loader.exec_module(module)
    return module


def run_audit(target: Path):
    module = load_module()
    rules, rules_meta = module.load_rules(ROOT / "scripts")
    findings, _root, state = module.scan_files(target, rules)
    return module.build_report(str(target), findings, state, rules_meta)


def write_skill(root: Path, skill_md: str | None = None) -> Path:
    root.mkdir()
    (root / "SKILL.md").write_text(
        skill_md
        or """---
name: test-skill
description: Test skill.
---

# Test
""",
        encoding="utf-8",
    )
    return root


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
    for key in {
        "tool_version",
        "verdict",
        "risk_score",
        "exit_code",
        "summary",
        "findings",
        "metadata",
        "recommendation",
    }:
        assert key in payload


def test_markdown_output_contains_required_sections(tmp_path: Path):
    module = load_module()
    target = ROOT / "examples" / "dangerous-skill"
    exit_code = module.main([str(target), "--format", "markdown", "--output-dir", str(tmp_path)])
    assert exit_code == 2
    text = (tmp_path / "SKILL_SECURITY_REPORT.md").read_text(encoding="utf-8")
    assert "Verdict" in text
    assert "Risk score" in text
    assert "Findings" in text
    assert "Recommendation" in text
    assert "Capability Declaration vs Observed Behavior" in text
    assert "Tool version" in text


def test_github_url_parser_handles_root_and_tree():
    module = load_module()
    assert module.parse_github_url("https://github.com/user/repo") == ("user", "repo", "main", "")
    assert module.parse_github_url("https://github.com/user/repo/tree/dev/skills/foo") == (
        "user",
        "repo",
        "dev",
        "skills/foo",
    )


def test_python_ast_detects_shell_and_dynamic_execution(tmp_path: Path):
    skill = write_skill(tmp_path / "ast-skill")
    (skill / "tool.py").write_text(
        "import os\nimport subprocess\nos.system('whoami')\nsubprocess.run('id', shell=True)\nexec('print(1)')\n__import__('socket')\n",
        encoding="utf-8",
    )
    report = run_audit(skill)
    assert report["verdict"] in {"REVIEW", "DANGEROUS"}
    rule_ids = {item["rule_id"] for item in report["findings"]}
    assert "python_shell_call" in rule_ids
    assert "python_dynamic_exec" in rule_ids
    assert "python_dynamic_import" in rule_ids


def test_high_entropy_decode_returns_review(tmp_path: Path):
    skill = write_skill(tmp_path / "entropy-skill")
    payload = "QWxhZGRpbjpvcGVuIHNlc2FtZQ==" * 5
    (skill / "decode.py").write_text(
        f"import base64\nblob = '{payload}'\nexec(base64.b64decode(blob).decode())\n",
        encoding="utf-8",
    )
    report = run_audit(skill)
    assert report["verdict"] in {"REVIEW", "DANGEROUS"}
    assert any(item["rule_id"] == "high_entropy_decode" for item in report["findings"])


def test_dependency_typosquat_and_npm_lifecycle(tmp_path: Path):
    skill = write_skill(tmp_path / "deps-skill")
    (skill / "requirements.txt").write_text("reqeusts==1.0\n", encoding="utf-8")
    (skill / "package.json").write_text(
        json.dumps({"scripts": {"postinstall": "node install.js"}, "dependencies": {"expres": "1.0.0"}}),
        encoding="utf-8",
    )
    report = run_audit(skill)
    rule_ids = {item["rule_id"] for item in report["findings"]}
    assert "dependency_typosquat" in rule_ids
    assert "npm_lifecycle_script" in rule_ids
    assert report["verdict"] in {"REVIEW", "DANGEROUS"}


def test_expected_capabilities_and_ignore_suppress_low_medium_findings(tmp_path: Path):
    skill = write_skill(
        tmp_path / "allow-skill",
        """---
name: allow-skill
description: Uses network intentionally.
expected-capabilities:
  - network
---

# Allow
""",
    )
    (skill / "SKILL.md").write_text((skill / "SKILL.md").read_text(encoding="utf-8") + "\nhttps://example.com\n", encoding="utf-8")
    (skill / ".skillaudit-ignore").write_text("capability_mismatch * expected\n", encoding="utf-8")
    report = run_audit(skill)
    assert report["verdict"] == "SAFE"
    assert report["suppressed_findings"]
    assert any(item["rule_id"] == "unknown_network" for item in report["suppressed_findings"])


def test_exit_codes_are_verdict_specific(tmp_path: Path):
    module = load_module()
    assert module.main([str(ROOT / "examples" / "benign-skill"), "--output-dir", str(tmp_path / "safe")]) == 0
    assert module.main([str(ROOT / "examples" / "suspicious-skill"), "--output-dir", str(tmp_path / "review")]) == 1
    assert module.main([str(ROOT / "examples" / "dangerous-skill"), "--output-dir", str(tmp_path / "danger")]) == 2


def test_custom_rules_file_merges(tmp_path: Path):
    module = load_module()
    skill = write_skill(tmp_path / "custom-rule-skill")
    (skill / "notes.txt").write_text("custom-badness\n", encoding="utf-8")
    custom_rules = tmp_path / "rules.json"
    custom_rules.write_text(
        json.dumps(
            {
                "version": "custom",
                "rules": [
                    {
                        "id": "custom_badness",
                        "severity": "high",
                        "category": "shell",
                        "pattern": "custom-badness",
                        "recommendation": "Remove custom badness.",
                    }
                ],
            }
        ),
        encoding="utf-8",
    )
    exit_code = module.main([str(skill), "--rules", str(custom_rules), "--output-dir", str(tmp_path / "out")])
    assert exit_code == 1
    payload = json.loads((tmp_path / "out" / "skill_security_report.json").read_text(encoding="utf-8"))
    assert any(item["rule_id"] == "custom_badness" for item in payload["findings"])


def test_claude_hook_and_mcp_config_are_flagged(tmp_path: Path):
    skill = write_skill(tmp_path / "claude-skill")
    (skill / "settings.json").write_text(
        json.dumps(
            {
                "hooks": {"PreToolUse": [{"command": "bash hook.sh"}]},
                "mcpServers": {"x": {"command": "npx", "args": ["server"]}},
            }
        ),
        encoding="utf-8",
    )
    report = run_audit(skill)
    rule_ids = {item["rule_id"] for item in report["findings"]}
    assert "claude_hook_command" in rule_ids
    assert "mcp_command_config" in rule_ids


def test_ref_and_reproducibility_metadata_are_reported(tmp_path: Path):
    module = load_module()
    target = ROOT / "examples" / "benign-skill"
    exit_code = module.main([str(target), "--ref", "abc123", "--format", "json", "--output-dir", str(tmp_path)])
    assert exit_code == 0
    payload = json.loads((tmp_path / "skill_security_report.json").read_text(encoding="utf-8"))
    assert payload["tool_version"] == "1.1.0"
    assert payload["metadata"]["target_ref"] == "abc123"
    assert payload["metadata"]["target_sha256"]
    assert payload["metadata"]["rules_hash"]
