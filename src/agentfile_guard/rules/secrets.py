from __future__ import annotations

import re
from pathlib import Path

from ..config import Config
from ..models import Finding, Rule, Severity

SECRET_RULE = Rule(
    id="AFG001",
    name="embedded-secret",
    description="Detects high-confidence secrets embedded in agent instruction files.",
    severity=Severity.ERROR,
)


# High-confidence token patterns. Keep conservative to avoid noisy false positives.
SECRET_PATTERNS: list[tuple[re.Pattern[str], str]] = [
    (re.compile(r"\bAKIA[0-9A-Z]{16}\b"), "AWS access key ID"),
    (re.compile(r"\bASIA[0-9A-Z]{16}\b"), "AWS temporary access key ID"),
    (re.compile(r"\bghp_[A-Za-z0-9]{36}\b"), "GitHub personal access token"),
    (re.compile(r"\bgithub_pat_[A-Za-z0-9_]{20,}\b"), "GitHub fine-grained token"),
    (re.compile(r"\bsk-(?:proj-|live-|test-)?[A-Za-z0-9]{20,}\b"), "API secret key-like token"),
    (re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{10,}\b"), "Slack token"),
    (
        re.compile(r"-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY-----"),
        "Private key block",
    ),
    (re.compile(r"\bAIza[0-9A-Za-z\-_]{35}\b"), "Google API key"),
]

# Context-aware AWS Secret Access Key detection.
# Matches assignment/context forms like:
#   aws_secret_access_key = "..."
#   "SecretAccessKey": "..."
#   AWS_SECRET_ACCESS_KEY=...
AWS_SECRET_NAME_RE = re.compile(
    r"(?i)\b(?:aws[_\s-]?secret[_\s-]?access[_\s-]?key|secretaccesskey)\b"
)
AWS_SECRET_VALUE_RE = re.compile(r"(?=([A-Za-z0-9/+=]{40}))")

# Common placeholder markers that indicate examples, not real secrets.
PLACEHOLDER_MARKERS = (
    "example",
    "placeholder",
    "your_",
    "your-",
    "<",
    ">",
    "changeme",
    "replace_me",
    "replace-me",
    "dummy",
    "sample",
    "fake",
    "xxxxx",
    "...",
    "examplekey",
    "redacted",
)

# "test" is a placeholder marker only for certain token families to avoid
# suppressing real-looking keys that happen to appear on lines with "test".
TEST_PLACEHOLDER_FAMILIES = ("sk-", "pk-", "rk-")


class SecretsRule:
    rule = SECRET_RULE

    def check(self, path: Path, text: str, root: Path, config: Config) -> list[Finding]:
        findings: list[Finding] = []
        for lineno, line in enumerate(text.splitlines(), start=1):
            stripped = line.strip()
            if not stripped or stripped.startswith("<!--"):
                continue
            lower = line.lower()
            findings.extend(self._check_token_patterns(path, lineno, line, lower))
            findings.extend(self._check_aws_secret_access_key(path, lineno, line, lower))
        return findings

    def _check_token_patterns(
        self, path: Path, lineno: int, line: str, lower: str
    ) -> list[Finding]:
        findings: list[Finding] = []
        for pattern, label in SECRET_PATTERNS:
            for match in pattern.finditer(line):
                value = match.group(0)
                if self._looks_like_placeholder(value, lower):
                    continue
                snippet = _mask_secret(line.rstrip("\n\r"))
                findings.append(
                    Finding(
                        rule=self.rule,
                        path=path,
                        line=lineno,
                        column=match.start() + 1,
                        end_line=lineno,
                        end_column=match.end() + 1,
                        message=f"Possible {label} embedded in agent instruction file.",
                        snippet=snippet,
                    )
                )
        return findings

    def _check_aws_secret_access_key(
        self, path: Path, lineno: int, line: str, lower: str
    ) -> list[Finding]:
        if not AWS_SECRET_NAME_RE.search(line):
            return []
        findings: list[Finding] = []
        for match in AWS_SECRET_VALUE_RE.finditer(line):
            value = match.group(1)
            if self._looks_like_placeholder(value, lower):
                continue
            # Avoid flagging the value when it's part of a longer identifier/path.
            start, end = match.start(1), match.end(1)
            before = line[start - 1] if start > 0 else ""
            after = line[end] if end < len(line) else ""
            if (
                before.isalnum()
                or (before != "" and before in "+/")
                or after.isalnum()
                or (after != "" and after in "/+=")
            ):
                continue
            snippet = _mask_secret(line.rstrip("\n\r"), extra_values=[value])
            findings.append(
                Finding(
                    rule=self.rule,
                    path=path,
                    line=lineno,
                    column=match.start(1) + 1,
                    end_line=lineno,
                    end_column=match.end(1) + 1,
                    message="Possible AWS secret access key embedded in agent instruction file.",
                    snippet=snippet,
                )
            )
        return findings

    @staticmethod
    def _looks_like_placeholder(value: str, lower_line: str) -> bool:
        lower_value = value.lower()
        if any(marker in lower_value for marker in PLACEHOLDER_MARKERS):
            return True
        if (
            any(lower_value.startswith(fam) for fam in TEST_PLACEHOLDER_FAMILIES)
            and "test" in lower_value
        ):
            return True
        if any(marker in lower_line for marker in ("example", "placeholder", "dummy", "sample")):
            # Avoid flagging obvious documentation examples with fake-looking keys.
            if (
                "sk-" in lower_value
                or "akia" in lower_value
                or "ghp_" in lower_value
                or re.fullmatch(r"[A-Za-z0-9/+=]{40}", value)
            ):
                return True
        return False


def _mask_secret(line: str, extra_values: list[str] | None = None) -> str:
    # Mask likely secret payloads in snippets so findings don't leak secrets.
    masked = re.sub(r"(AKIA|ASIA)[0-9A-Z]{16}", r"\1****************", line)
    masked = re.sub(r"ghp_[A-Za-z0-9]{36}", "ghp_************************************", masked)
    masked = re.sub(r"github_pat_[A-Za-z0-9_]{20,}", "github_pat_[REDACTED]", masked)
    masked = re.sub(r"sk-(?:proj-|live-|test-)?[A-Za-z0-9]{20,}", "sk-[REDACTED]", masked)
    masked = re.sub(r"xox[baprs]-[A-Za-z0-9-]{10,}", "xox*-[REDACTED]", masked)
    masked = re.sub(r"AIza[0-9A-Za-z\-_]{35}", "AIza[REDACTED]", masked)
    for value in extra_values or []:
        if value and value in masked:
            masked = masked.replace(value, "[REDACTED_SECRET]")
    return masked[:240]
