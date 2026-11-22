# Changelog

## 0.1.0 - 2026-11-23

Initial release.

- Deterministic CLI linter for agent instruction files.
- Rules: AFG001 secrets, AFG002 hidden Unicode controls, AFG003 stale local markdown references, AFG005 dangerous shell instructions, AFG006 prompt-injection markers.
- Output formats: text, JSON, SARIF, GitHub Actions annotations.
- Config file support via `.agentfile-guard.toml`.
- CI workflow, tests, and benchmark script.
