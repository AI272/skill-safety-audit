# Skill Safety Audit

Audit third-party Agent Skills before installing them.

`skill-safety-audit` is a conservative static scanner for Codex, Claude Code, and other `SKILL.md`-based Agent Skills. It looks for dangerous install patterns, secret access, prompt injection, persistence, suspicious network behavior, and structural red flags.

It does not execute the target skill.

## What It Checks

- Dangerous shell: `curl | bash`, destructive deletes, encoded shell payloads
- Secret access: `~/.ssh`, `~/.aws`, `.env`, `.codex`, `.claude`, API tokens
- Persistence: cron, systemd, launchctl, shell profile mutation
- Prompt injection: hidden execution, bypassing approval, hiding behavior from users
- Install risk: binary downloads, Git-based package installs, required credentials
- Structure: missing or invalid `SKILL.md`, hidden files, binaries, large skipped files

## Usage

From the project root:

```bash
python scripts/audit_skill.py ./examples/benign-skill
python scripts/audit_skill.py ./examples/dangerous-skill --format json
python scripts/audit_skill.py https://github.com/user/repo
python scripts/audit_skill.py https://github.com/user/repo/tree/main/path/to/skill
```

The scanner writes:

```text
SKILL_SECURITY_REPORT.md
skill_security_report.json
```

## Verdicts

- `SAFE`: no high or critical findings and low score.
- `REVIEW`: suspicious behavior needs manual inspection.
- `DANGEROUS`: critical risk appears; do not install without removing the behavior.

This tool is intentionally conservative. False positives are expected when a skill legitimately needs network access, package installation, or credentials.

## Codex Skill

Install or copy this folder as a Codex skill, then restart Codex. Invoke it with:

```text
Use $skill-safety-audit to audit https://github.com/user/repo before installation.
```

Codex should run the static auditor and summarize the verdict, top findings, cited files, and install recommendation.

## Threat Model

This scanner is designed for installation-time review of untrusted `SKILL.md` packages. It tries to catch:

- malicious instructions embedded in skill prose
- install scripts that execute downloaded code
- scripts that read or upload secrets
- persistence mechanisms
- risky dependency installation paths

It does not prove runtime safety and does not sandbox execution.

## Development

Run tests:

```bash
python -m pytest tests
```

Manual checks:

```bash
python scripts/audit_skill.py examples/benign-skill --format markdown
python scripts/audit_skill.py examples/dangerous-skill --format json
```
