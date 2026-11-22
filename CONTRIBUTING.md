# Contributing

## Development setup

```bash
python -m pip install -e .[dev]
python -m pip install ruff
```

## Checks

```bash
python -m pytest -q
ruff check src tests
agentfile-guard --root . --format text
```

## Guidelines

- Keep rules deterministic and explainable.
- Prefer high-confidence checks over noisy heuristics.
- Add tests for every rule change.
- Do not add telemetry or network access to the linter.
- Do not claim support for platforms or formats that are not tested.
