from __future__ import annotations

from dataclasses import dataclass, field
from fnmatch import fnmatch
from pathlib import Path
from typing import Any

try:
    import tomllib
except ModuleNotFoundError:  # pragma: no cover - py310 fallback not expected in dev env
    tomllib = None  # type: ignore[assignment]


DEFAULT_INCLUDE_GLOBS = [
    "AGENTS.md",
    "CLAUDE.md",
    ".cursorrules",
    ".windsurfrules",
    ".clinerules",
    ".github/copilot-instructions.md",
    "**/AGENTS.md",
    "**/CLAUDE.md",
    "**/.cursorrules",
    "**/.windsurfrules",
    "**/.clinerules",
    "**/.github/copilot-instructions.md",
]

DEFAULT_EXCLUDE_DIRS = {
    ".git",
    ".hg",
    ".svn",
    ".venv",
    "venv",
    "node_modules",
    "__pycache__",
    ".pytest_cache",
    ".ruff_cache",
    ".mypy_cache",
    "dist",
    "build",
}


@dataclass
class Config:
    include: list[str] = field(default_factory=lambda: list(DEFAULT_INCLUDE_GLOBS))
    exclude: list[str] = field(default_factory=list)
    disable_rules: set[str] = field(default_factory=set)
    fail_on: str = "error"  # error|warning|info
    max_file_bytes: int = 1_000_000

    @classmethod
    def load(cls, root: Path, explicit_path: Path | None = None) -> Config:
        config_path = explicit_path
        if config_path is None:
            candidate = root / ".agentfile-guard.toml"
            if candidate.exists():
                config_path = candidate
        if config_path is None or not config_path.exists():
            return cls()
        if tomllib is None:
            raise RuntimeError("TOML config requires Python 3.11+ or tomllib")
        data = tomllib.loads(config_path.read_text(encoding="utf-8"))
        return cls.from_dict(data)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> Config:
        cfg = cls()
        if not isinstance(data, dict):
            return cfg
        include = data.get("include")
        if isinstance(include, list) and all(isinstance(x, str) for x in include):
            cfg.include = include
        exclude = data.get("exclude")
        if isinstance(exclude, list) and all(isinstance(x, str) for x in exclude):
            cfg.exclude = exclude
        disable = data.get("disable_rules")
        if isinstance(disable, list) and all(isinstance(x, str) for x in disable):
            cfg.disable_rules = set(disable)
        fail_on = data.get("fail_on")
        if isinstance(fail_on, str) and fail_on in {"error", "warning", "info"}:
            cfg.fail_on = fail_on
        max_file_bytes = data.get("max_file_bytes")
        if isinstance(max_file_bytes, int) and max_file_bytes > 0:
            cfg.max_file_bytes = max_file_bytes
        return cfg

    def is_rule_enabled(self, rule_id: str) -> bool:
        return rule_id not in self.disable_rules

    def is_path_excluded(self, rel_path: Path) -> bool:
        rel = rel_path.as_posix()
        parts = set(rel_path.parts)
        if parts & DEFAULT_EXCLUDE_DIRS:
            return True
        for pattern in self.exclude:
            normalized = pattern.replace("\\", "/")
            if fnmatch(rel, normalized) or fnmatch(rel_path.name, normalized):
                return True
            # Support directory patterns like "docs/**"
            if normalized.endswith("/**"):
                prefix = normalized[:-3].rstrip("/")
                if rel == prefix or rel.startswith(prefix + "/"):
                    return True
        return False
