from __future__ import annotations

import re
from pathlib import Path
from urllib.parse import unquote

from ..config import Config
from ..models import Finding, Rule, Severity

STALE_REF_RULE = Rule(
    id="AFG003",
    name="stale-file-reference",
    description="Detects local markdown file references that do not exist.",
    severity=Severity.WARNING,
)

# Markdown links/images: ![alt](path) or [text](path)
MD_LINK_RE = re.compile(r"!?\[[^\]]*\]\(([^)]+)\)")
SCHEME_RE = re.compile(r"^[a-zA-Z][a-zA-Z0-9+.-]*:")


class StaleRefsRule:
    rule = STALE_REF_RULE

    def check(self, path: Path, text: str, root: Path, config: Config) -> list[Finding]:
        findings: list[Finding] = []
        in_fence = False
        fence_marker = ""
        for lineno, line in enumerate(text.splitlines(), start=1):
            stripped = line.lstrip()
            if stripped.startswith("```") or stripped.startswith("~~~"):
                marker = stripped[:3]
                if not in_fence:
                    in_fence = True
                    fence_marker = marker
                elif marker == fence_marker:
                    in_fence = False
                    fence_marker = ""
                continue
            if in_fence:
                continue

            for match in MD_LINK_RE.finditer(line):
                raw_target = match.group(1).strip()
                target = _normalize_target(raw_target)
                if target is None:
                    continue
                if not _looks_like_local_path(target):
                    continue
                resolved = _resolve_target(path, root, target)
                if resolved is None:
                    continue
                exists_anywhere = any(p.exists() for p in resolved)
                if exists_anywhere:
                    continue
                findings.append(
                    Finding(
                        rule=self.rule,
                        path=path,
                        line=lineno,
                        column=match.start(1) + 1,
                        end_line=lineno,
                        end_column=match.end(1) + 1,
                        message=f"Referenced local path '{target}' does not exist.",
                        snippet=line.rstrip("\n\r")[:240],
                    )
                )
        return findings


def _normalize_target(raw: str) -> str | None:
    if not raw:
        return None
    # Handle optional title: (path "title")
    if raw.startswith("<") and ">" in raw:
        raw = raw[1 : raw.index(">")]
    else:
        # split on whitespace before optional title, but keep it simple
        parts = raw.split()
        if parts:
            raw = parts[0]
    raw = raw.strip()
    if not raw:
        return None
    # strip anchor
    raw = raw.split("#", 1)[0]
    raw = raw.split("?", 1)[0]
    raw = unquote(raw).strip()
    if not raw:
        return None
    return raw


def _looks_like_local_path(target: str) -> bool:
    if target.startswith("#"):
        return False
    if SCHEME_RE.match(target):
        # allow Windows drive letters like C:\...
        if re.match(r"^[a-zA-Z]:[\\/]", target):
            return True
        return False
    if target.startswith("//"):
        return False
    if any(ch in target for ch in ["{", "}", "$", "<", ">", "*", "|"]):
        return False
    # Ignore pure URLs without scheme edge cases
    if target.lower().startswith("www."):
        return False
    return True


def _resolve_target(path: Path, root: Path, target: str) -> list[Path] | None:
    # Normalize separators
    normalized = target.replace("\\", "/")
    try:
        target_path = Path(normalized)
    except Exception:
        return None
    candidates = []
    if target_path.is_absolute():
        candidates.append(target_path)
    else:
        candidates.append(path.parent / target_path)
        candidates.append(root / target_path)
    # Deduplicate while preserving order
    seen = set()
    uniq: list[Path] = []
    for c in candidates:
        key = str(c)
        if key in seen:
            continue
        seen.add(key)
        uniq.append(c)
    return uniq
