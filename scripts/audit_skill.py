#!/usr/bin/env python3
"""Static security auditor for SKILL.md-based Agent Skills."""

from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import re
import sys
import tempfile
import urllib.parse
import urllib.request
import zipfile


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


def load_rules(script_dir: Path) -> list[dict]:
    rules_path = script_dir / "rules.yaml"
    with rules_path.open("r", encoding="utf-8") as handle:
        payload = json.load(handle)
    return payload["rules"]


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


def download_github_source(raw_url: str) -> tuple[Path, tempfile.TemporaryDirectory]:
    owner, repo, ref, subpath = parse_github_url(raw_url)
    tmp = tempfile.TemporaryDirectory(prefix="skill-audit-")
    tmp_path = Path(tmp.name)
    zip_url = f"https://codeload.github.com/{owner}/{repo}/zip/{ref}"
    archive_path = tmp_path / "repo.zip"
    urllib.request.urlretrieve(zip_url, archive_path)
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
    return target, tmp


def resolve_target(target: str) -> tuple[Path, tempfile.TemporaryDirectory | None, str]:
    if target.startswith("https://github.com/"):
        path, tmp = download_github_source(target)
        return path, tmp, target
    path = Path(target).expanduser().resolve()
    if not path.exists():
        raise FileNotFoundError(f"target not found: {target}")
    return path, None, str(path)


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
    return [path for path in target.rglob("*") if path.is_file()]


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
        try:
            return data.decode("utf-8", errors="replace"), None
        except UnicodeError as exc:
            return None, f"could not decode text: {exc}"


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


def validate_skill_structure(target: Path, root: Path) -> list[dict]:
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

    frontmatter_match = re.match(r"^---\s*\n(.*?)\n---\s*", text, re.DOTALL)
    if not frontmatter_match:
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

    frontmatter = frontmatter_match.group(1)
    if not re.search(r"(?m)^name\s*:\s*.+", frontmatter):
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
    if not re.search(r"(?m)^description\s*:\s*.+", frontmatter):
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


def scan_files(target: Path, rules: list[dict]) -> tuple[list[dict], Path]:
    root = target.parent if target.is_file() else target
    findings = validate_skill_structure(target, root)
    for path in iter_files(target):
        file_name = relpath(path, root)
        if any(part.startswith(".") for part in Path(file_name).parts):
            if path.name not in {".gitignore"}:
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
    return dedupe_findings(findings), root


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


def build_report(target_label: str, findings: list[dict]) -> dict:
    score = score_findings(findings)
    verdict = verdict_for(findings, score)
    return {
        "target": target_label,
        "verdict": verdict,
        "risk_score": score,
        "summary": summarize(verdict, findings),
        "findings": findings,
        "recommendation": recommendation_for(verdict),
    }


def render_markdown(report: dict) -> str:
    lines = [
        "# Skill Security Report",
        "",
        f"**Target:** `{report['target']}`",
        f"**Verdict:** `{report['verdict']}`",
        f"**Risk score:** `{report['risk_score']}`",
        f"**Recommendation:** `{report['recommendation']}`",
        "",
        report["summary"],
        "",
        "## Findings",
        "",
    ]
    if not report["findings"]:
        lines.append("No findings.")
    else:
        lines.append("| Severity | Category | File | Line | Evidence | Recommendation |")
        lines.append("|---|---|---|---:|---|---|")
        for item in report["findings"]:
            evidence = str(item["evidence"]).replace("|", "\\|")
            recommendation = str(item["recommendation"]).replace("|", "\\|")
            lines.append(
                f"| {item['severity']} | {item['category']} | `{item['file']}` | "
                f"{item['line']} | {evidence} | {recommendation} |"
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
    return parser.parse_args(argv)


def main(argv: list[str]) -> int:
    args = parse_args(argv)
    tmp: tempfile.TemporaryDirectory | None = None
    try:
        target, tmp, target_label = resolve_target(args.target)
        rules = load_rules(Path(__file__).resolve().parent)
        findings, _root = scan_files(target, rules)
        report = build_report(target_label, findings)
        write_outputs(report, Path(args.output_dir).resolve())
        if args.format == "json":
            print(json.dumps(report, indent=2, ensure_ascii=False))
        else:
            print(render_markdown(report))
        return 0 if report["verdict"] in {"SAFE", "REVIEW", "DANGEROUS"} else 1
    except Exception as exc:  # noqa: BLE001 - CLI should return readable failures.
        print(f"error: {exc}", file=sys.stderr)
        return 2
    finally:
        if tmp is not None:
            tmp.cleanup()


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
