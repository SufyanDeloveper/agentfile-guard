from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path


class Severity(str, Enum):
    ERROR = "error"
    WARNING = "warning"
    INFO = "info"


SEVERITY_RANK = {
    Severity.INFO: 10,
    Severity.WARNING: 20,
    Severity.ERROR: 30,
}


@dataclass(frozen=True)
class Rule:
    id: str
    name: str
    description: str
    severity: Severity
    help_url: str = ""


@dataclass
class Finding:
    rule: Rule
    path: Path
    line: int
    column: int
    message: str
    end_line: int | None = None
    end_column: int | None = None
    snippet: str = ""

    @property
    def severity(self) -> Severity:
        return self.rule.severity

    def to_dict(self, root: Path | None = None) -> dict:
        display_path = self.path
        if root is not None:
            try:
                display_path = self.path.resolve().relative_to(root.resolve())
            except Exception:
                display_path = self.path
        return {
            "rule_id": self.rule.id,
            "rule_name": self.rule.name,
            "severity": self.severity.value,
            "path": str(display_path).replace("\\", "/"),
            "line": self.line,
            "column": self.column,
            "end_line": self.end_line or self.line,
            "end_column": self.end_column or self.column,
            "message": self.message,
            "snippet": self.snippet,
        }


@dataclass
class ScanResult:
    root: Path
    files_scanned: list[Path] = field(default_factory=list)
    findings: list[Finding] = field(default_factory=list)

    @property
    def errors(self) -> int:
        return sum(1 for f in self.findings if f.severity == Severity.ERROR)

    @property
    def warnings(self) -> int:
        return sum(1 for f in self.findings if f.severity == Severity.WARNING)

    @property
    def infos(self) -> int:
        return sum(1 for f in self.findings if f.severity == Severity.INFO)

    @property
    def ok(self) -> bool:
        return self.errors == 0

    def to_dict(self) -> dict:
        return {
            "root": str(self.root),
            "files_scanned": [
                str(p.resolve().relative_to(self.root.resolve())).replace("\\", "/")
                if self._is_relative(p)
                else str(p).replace("\\", "/")
                for p in self.files_scanned
            ],
            "summary": {
                "files_scanned": len(self.files_scanned),
                "findings": len(self.findings),
                "errors": self.errors,
                "warnings": self.warnings,
                "infos": self.infos,
            },
            "findings": [f.to_dict(self.root) for f in self.findings],
        }

    def _is_relative(self, path: Path) -> bool:
        try:
            path.resolve().relative_to(self.root.resolve())
            return True
        except Exception:
            return False
