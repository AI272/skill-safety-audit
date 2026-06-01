# Skill Safety Audit

**Current version:** `v1.1.0`

Audit third-party Agent Skills before installing them.

`skill-safety-audit` is a conservative static scanner for Codex, Claude Code, and other `SKILL.md`-based Agent Skills. It looks for dangerous install patterns, secret access, prompt injection, persistence, suspicious network behavior, dependency risk, Claude hook/MCP command risk, and structural red flags.

It does not execute the target skill.

## What changed since v1.0

v1.1 adds deeper static analysis and GitHub-ready release metadata:

- AST-based Python risk detection for `os.system`, `subprocess`, `exec`, `eval`, dynamic imports, and network-capable imports.
- Entropy and obfuscation heuristics for encoded payloads combined with decode or execution sinks.
- Dependency and typosquat checks for `requirements.txt` and `package.json`.
- Allowlist and `expected-capabilities` support for documented, repeated findings.
- Reproducible report metadata: tool version, rules hash, target ref, target SHA256, and generated timestamp.
- CI-ready exit codes and reusable GitHub Action/pre-commit integration.
- Claude Code hooks and MCP server command scanning.

Compare: <https://github.com/AI272/skill-safety-audit/compare/v1.0.0...v1.1.0>

## What It Checks

- Dangerous shell: `curl | bash`, destructive deletes, encoded shell payloads
- Python AST risk: shell execution, dynamic execution, dynamic imports, network imports
- Secret access: `~/.ssh`, `~/.aws`, `.env`, `.codex`, `.claude`, API tokens
- Persistence: cron, systemd, launchctl, shell profile mutation
- Prompt injection: hidden execution, bypassing approval, hiding behavior from users
- Install risk: binary downloads, Git-based package installs, npm lifecycle scripts
- Dependency risk: common typosquatting names in Python and npm manifests
- Claude Code risk: hooks and MCP command fields in JSON config
- Structure: missing or invalid `SKILL.md`, hidden files, binaries, large skipped files

## Usage

From the project root:

```bash
python scripts/audit_skill.py ./examples/benign-skill
python scripts/audit_skill.py ./examples/dangerous-skill --format json
python scripts/audit_skill.py https://github.com/user/repo
python scripts/audit_skill.py https://github.com/user/repo/tree/main/path/to/skill
```

v1.1 options:

```bash
python scripts/audit_skill.py ./skill --rules ./custom-rules.json
python scripts/audit_skill.py https://github.com/user/repo --ref <commit-sha>
python scripts/audit_skill.py ./skill --since v1.0.0
python scripts/audit_skill.py ./skill --ignore-file .skillaudit-ignore
python scripts/audit_skill.py ./skill --online-deps
```

`--online-deps` is opt-in and reserved for online dependency intelligence. The default scan remains offline.

The scanner writes:

```text
SKILL_SECURITY_REPORT.md
skill_security_report.json
```

## Exit Codes

- `0`: `SAFE`
- `1`: `REVIEW`
- `2`: `DANGEROUS`
- `3`: runtime or input error

## Verdicts

- `SAFE`: no high or critical findings and low score.
- `REVIEW`: suspicious behavior needs manual inspection.
- `DANGEROUS`: critical risk appears; do not install without removing the behavior.

This tool is intentionally conservative. False positives are expected when a skill legitimately needs network access, package installation, or credentials.

## Expected Capabilities and Baselines

Skills can declare expected capabilities in `SKILL.md` frontmatter:

```yaml
expected-capabilities:
  - network
  - filesystem
```

Repeated findings can be suppressed with `.skillaudit-ignore`:

```text
unknown_network README.md documented link
capability_mismatch * expected capability already declared
```

Suppressed findings remain visible in the report.

## GitHub Action

Add this repository as an action in your workflow:

```yaml
name: Skill Safety Audit
on: [push, pull_request]
jobs:
  audit:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: AI272/skill-safety-audit@v1.1.0
        with:
          target: .
          format: markdown
```

## Codex Skill

Install or copy this folder as a Codex skill, then restart Codex. Invoke it with:

```text
Use $skill-safety-audit to audit https://github.com/user/repo before installation.
```

Codex should run the static auditor and summarize the verdict, top findings, cited files, reproducibility metadata, capability mismatch table, and install recommendation.

## Threat Model

This scanner is designed for installation-time review of untrusted `SKILL.md` packages. It tries to catch:

- malicious instructions embedded in skill prose
- install scripts that execute downloaded code
- scripts that read or upload secrets
- persistence mechanisms
- risky dependency installation paths
- Claude Code hooks or MCP commands that execute local processes

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
