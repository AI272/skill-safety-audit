---
name: skill-safety-audit
description: "Audit third-party Agent Skills before installation. Use when the user wants to inspect a Codex, Claude Code, or SKILL.md-based skill, GitHub skill repository, install script, or local skill folder for malicious instructions, secret access, dangerous shell commands, prompt injection, persistence, network exfiltration, or install-time risk."
---

# Skill Safety Audit

Use this skill to audit Agent Skills before installation. It is conservative by default: a `REVIEW` verdict is acceptable when behavior may be legitimate but needs human inspection.

## Workflow

1. Identify the target: local skill folder, single `SKILL.md`, GitHub repo URL, or GitHub `/tree/<ref>/<path>` URL.
2. Do not run any code from the target. Do not execute install scripts, package scripts, hooks, or copied commands.
3. Run the static auditor:

```bash
python scripts/audit_skill.py <target> --format markdown
```

4. Read `SKILL_SECURITY_REPORT.md` and `skill_security_report.json`.
5. Report the verdict first: `SAFE`, `REVIEW`, or `DANGEROUS`, followed by the risk score, top findings, and install recommendation.

## Verdict Policy

- `SAFE`: no high or critical findings and low score.
- `REVIEW`: suspicious behavior exists, but the evidence is not enough to reject the skill automatically.
- `DANGEROUS`: critical behavior appears, such as secret access, dangerous shell execution, persistence, or code paths that can exfiltrate data.

Never tell the user a skill is safe if the report says `REVIEW` or `DANGEROUS`. If the user asks whether to install it, recommend installation only for `SAFE`; for `REVIEW`, recommend reading the cited files first; for `DANGEROUS`, recommend not installing.

## Notes

- GitHub URL support downloads source only. The auditor must not execute third-party code.
- The scanner is static and conservative. It can produce false positives.
- For a final security decision, combine this report with manual review of the cited files.
