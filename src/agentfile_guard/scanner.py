from __future__ import annotations

from pathlib import Path

from .config import Config
from .models import Finding, ScanResult
from .rules import ALL_RULES


def discover_files(root: Path, paths: list[Path], config: Config) -> list[Path]:
    root = root.resolve()
    discovered: list[Path] = []
    if paths:
        for raw in paths:
            p = (raw if raw.is_absolute() else (root / raw)).resolve()
            if p.is_file():
                discovered.append(p)
            elif p.is_dir():
                discovered.extend(_scan_dir_for_agent_files(p, root, config))
            else:
                # Ignore missing paths here; CLI can warn.
                continue
    else:
        discovered.extend(_scan_dir_for_agent_files(root, root, config))

    # Deduplicate, keep deterministic order
    uniq: list[Path] = []
    seen: set[str] = set()
    for p in discovered:
        try:
            rel = p.resolve().relative_to(root)
        except Exception:
            rel = p
        if config.is_path_excluded(rel if isinstance(rel, Path) else Path(str(rel))):
            continue
        key = str(p.resolve()).lower()
        if key in seen:
            continue
        seen.add(key)
        uniq.append(p.resolve())
    uniq.sort(key=lambda x: str(x).lower())
    return uniq


def _scan_dir_for_agent_files(directory: Path, root: Path, config: Config) -> list[Path]:
    out: list[Path] = []
    for pattern in config.include:
        for p in directory.glob(pattern):
            if not p.is_file():
                continue
            try:
                rel = p.resolve().relative_to(root.resolve())
            except Exception:
                rel = p.name
            if config.is_path_excluded(Path(rel)):
                continue
            out.append(p.resolve())
    return out


def scan(root: Path, paths: list[Path], config: Config) -> ScanResult:
    root = root.resolve()
    files = discover_files(root, paths, config)
    result = ScanResult(root=root, files_scanned=files)
    for file_path in files:
        result.findings.extend(scan_file(file_path, root, config))
    # Deterministic ordering
    result.findings.sort(
        key=lambda f: (
            str(f.path).lower(),
            f.line,
            f.column,
            f.rule.id,
            f.message,
        )
    )
    return result


def scan_file(path: Path, root: Path, config: Config) -> list[Finding]:
    try:
        size = path.stat().st_size
    except OSError:
        return []
    if size > config.max_file_bytes:
        return []
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return []

    findings: list[Finding] = []
    for checker in ALL_RULES:
        # A checker may emit multiple rule IDs; filter per finding.
        try:
            produced = checker.check(path, text, root, config)
        except Exception as exc:  # pragma: no cover - defensive
            produced = [
                Finding(
                    rule=checker.rule,
                    path=path,
                    line=1,
                    column=1,
                    message=f"Internal rule error: {exc}",
                )
            ]
        for finding in produced:
            if config.is_rule_enabled(finding.rule.id):
                findings.append(finding)
    return findings
