# Changelog

## 0.2.0 - 2026-11-23

Security audit and hardening release.

- **AFG001**: added context-aware AWS Secret Access Key detection (env/JSON/assignment forms), improved secret masking, and fixed boundary matching for base64-like secrets.
- **AFG002**: expanded hidden/bidi Unicode detection to include LRM/RLM/ALM and deprecated bidi formatting controls (U+206A-U+206F), in addition to existing Trojan Source controls.
- **AFG003**: ignore markdown links inside fenced code blocks to reduce false positives in documented examples.
- **AFG005**: added PowerShell encoded command detection (`-enc`/`-encodedcommand`).
- **AFG006**: broadened prompt-injection detection (prior/above/earlier/system/developer overrides, system prompt extraction phrasings, jailbreak/bypass markers, instruction replacement markers) with per-line deduplication to limit noise.
- **CLI**: added update check/auto-update flow before scan (`--no-update-check`, `AGENTFILE_GUARD_NO_UPDATE=1`, `AGENTFILE_GUARD_SKIP_UPDATE=1` for restart safety). Network call is only for PyPI version metadata and upgrade uses `pip install --upgrade agentfile-guard`.
- **Tests**: added regression and edge-case tests for reported smoke failures, AWS secret masking/placeholders, bidi controls, prompt-injection variants, fenced code blocks, and CLI behavior.

## 0.1.0 - 2026-11-23

Initial release.

- Deterministic CLI linter for agent instruction files.
- Rules: AFG001 secrets, AFG002 hidden Unicode controls, AFG003 stale local markdown references, AFG005 dangerous shell instructions, AFG006 prompt-injection markers.
- Output formats: text, JSON, SARIF, GitHub Actions annotations.
- Config file support via `.agentfile-guard.toml`.
- CI workflow, tests, and benchmark script.
