# Changelog

## [1.1.0] - 2026-06-01

### Added

- AST-based Python risk detection for shell execution, dynamic execution, dynamic imports, and network-capable imports.
- Entropy and obfuscation heuristics for encoded strings combined with decode or execution sinks.
- Dependency and typosquat checks for `requirements.txt` and `package.json`.
- `.skillaudit-ignore` and `expected-capabilities` support for repeated, expected low/medium findings.
- Reproducible report metadata: tool version, rules hash, target ref, target SHA256, and generated timestamp.
- Capability declaration vs observed behavior table in Markdown reports.
- Claude Code hook and MCP server command scanning for JSON settings files.

### Changed

- CLI now supports repeated `--rules`, `--ref`, `--since`, `--ignore-file`, and opt-in `--online-deps`.
- JSON reports now include `tool_version`, `exit_code`, `metadata`, `declared_capabilities`, `observed_capabilities`, `capability_mismatches`, and `suppressed_findings`.
- Markdown reports now lead with reproducibility metadata and capability comparison before findings.

### Security

- Critical and high findings remain conservative and are not hidden by expected capabilities.
- GitHub URL downloads record the source archive URL, selected ref, and SHA256 of the downloaded archive.
- The scanner still never executes third-party skill code, install scripts, hooks, or package scripts.

### CI

- Added CI-ready exit code semantics: `SAFE=0`, `REVIEW=1`, `DANGEROUS=2`, runtime/input error `3`.
- Added `action.yml` for GitHub Actions.
- Added `.pre-commit-hooks.yaml` for pre-commit integration.

### Compatibility

- Existing v1.0 commands still work.
- The default scan remains offline and uses the Python standard library only.
- `--online-deps` is opt-in and reserved for online dependency intelligence.

## [1.0.0] - 2026-05-28

Initial GitHub-ready release with static regex rules, local/GitHub target support, Markdown and JSON reports, conservative verdicts, and Codex skill metadata.
