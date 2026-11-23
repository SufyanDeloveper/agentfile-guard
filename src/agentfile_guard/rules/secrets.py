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
    (re.compile(r"\bgho_[A-Za-z0-9]{36}\b"), "GitHub OAuth token"),
    (re.compile(r"\bghu_[A-Za-z0-9]{36}\b"), "GitHub user token"),
    (re.compile(r"\bghs_[A-Za-z0-9]{36}\b"), "GitHub app session token"),
    (re.compile(r"\bghr_[A-Za-z0-9]{36}\b"), "GitHub refresh token"),
    (re.compile(r"\bglpat-[A-Za-z0-9\-_]{20,}\b"), "GitLab personal access token"),
    (re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{10,}\b"), "Slack token"),
    (re.compile(r"\bsk_live_[A-Za-z0-9]{16,}\b"), "Stripe live secret key"),
    (re.compile(r"\bsk_test_[A-Za-z0-9]{16,}\b"), "Stripe test secret key"),
    (re.compile(r"\brk_live_[A-Za-z0-9]{16,}\b"), "Stripe live restricted key"),
    (re.compile(r"\brk_test_[A-Za-z0-9]{16,}\b"), "Stripe test restricted key"),
    (re.compile(r"\bSG\.[A-Za-z0-9_-]{16,}\.[A-Za-z0-9_-]{16,}\b"), "SendGrid API key"),
    (re.compile(r"\bnpm_[A-Za-z0-9]{20,}\b"), "npm access token"),
    (re.compile(r"\bpypi-[A-Za-z0-9_-]{20,}\b"), "PyPI API token"),
    (re.compile(r"\bAIza[0-9A-Za-z\-_]{35}\b"), "Google API key"),
    (re.compile(r"\bsk-ant-[A-Za-z0-9\-_]{20,}\b"), "Anthropic API key"),
    (re.compile(r"\bsk-(?:proj-|live-|test-)?[A-Za-z0-9]{20,}\b"), "API secret key-like token"),
    (re.compile(r"(?i)\bBearer\s+[A-Za-z0-9\-._~+/]{20,}=*\b"), "hardcoded Bearer token"),
    (
        re.compile(r"-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY-----"),
        "Private key block",
    ),
]

# Context-aware AWS Secret Access Key detection.
AWS_SECRET_NAME_RE = re.compile(
    r"(?i)\b(?:aws[_\s-]?secret[_\s-]?access[_\s-]?key|secretaccesskey)\b"
)
AWS_SECRET_VALUE_RE = re.compile(r"(?=([A-Za-z0-9/+=]{40}))")

# Connection strings / URLs with embedded credentials.
CONNECTION_STRING_RE = re.compile(
    r"\b(?:postgres(?:ql)?|mysql|mongodb(?:\+srv)?|redis|amqp|mssql|https?|ftp)://"
    r"([^:/@\s]+):([^@\s]{3,})@[^ \t\r\n\"']+",
    re.IGNORECASE,
)

# Generic secret assignment: password/api_key/token/secret/credential = "value"
GENERIC_ASSIGNMENT_RE = re.compile(
    r"(?i)\b("
    r"api[_-]?key|apikey|access[_-]?token|auth[_-]?token|bearer[_-]?token|"
    r"secret(?:[_-]?key)?|password|passwd|pwd|private[_-]?token|client[_-]?secret|"
    r"db[_-]?password|database[_-]?password"
    r")\b\s*[:=]\s*['\"]?([^\s'\"`,;]{8,})['\"]?"
)

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
    "todo",
    "put-your",
    "insert-",
    "set-me",
)

TEST_PLACEHOLDER_FAMILIES = ("sk-", "pk-", "rk-")

SAFE_GENERIC_VALUES = {
    "none",
    "null",
    "false",
    "true",
    "undefined",
    "password",
    "secret",
    "token",
    "changeme",
    "admin",
    "root",
}


class SecretsRule:
    rule = SECRET_RULE

    def check(self, path: Path, text: str, root: Path, config: Config) -> list[Finding]:
        findings: list[Finding] = []
        seen: set[tuple[int, int, str]] = set()
        for lineno, line in enumerate(text.splitlines(), start=1):
            stripped = line.strip()
            if not stripped or stripped.startswith("<!--"):
                continue
            lower = line.lower()
            for f in self._check_token_patterns(path, lineno, line, lower):
                key = (f.line, f.column, f.rule.id)
                if key not in seen:
                    seen.add(key)
                    findings.append(f)
            for f in self._check_aws_secret_access_key(path, lineno, line, lower):
                key = (f.line, f.column, f.rule.id)
                if key not in seen:
                    seen.add(key)
                    findings.append(f)
            for f in self._check_connection_strings(path, lineno, line, lower):
                key = (f.line, f.column, f.rule.id)
                if key not in seen:
                    seen.add(key)
                    findings.append(f)
            for f in self._check_generic_assignments(path, lineno, line, lower):
                key = (f.line, f.column, f.rule.id)
                if key not in seen:
                    seen.add(key)
                    findings.append(f)
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
                snippet = _mask_secret(line.rstrip("\n\r"), extra_values=[value])
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

    def _check_connection_strings(
        self, path: Path, lineno: int, line: str, lower: str
    ) -> list[Finding]:
        findings: list[Finding] = []
        for match in CONNECTION_STRING_RE.finditer(line):
            user = match.group(1)
            password = match.group(2)
            if self._looks_like_placeholder(password, lower):
                continue
            if self._looks_like_placeholder(user, lower) and "<" in lower:
                continue
            # Ignore obvious env placeholders in URI
            if password.startswith("${") or password.startswith("$("):
                continue
            if len(password) < 4:
                continue
            snippet = _mask_secret(line.rstrip("\n\r"), extra_values=[password])
            findings.append(
                Finding(
                    rule=self.rule,
                    path=path,
                    line=lineno,
                    column=match.start(2) + 1,
                    end_line=lineno,
                    end_column=match.end(2) + 1,
                    message="Possible credential embedded in connection string.",
                    snippet=snippet,
                )
            )
        return findings

    def _check_generic_assignments(
        self, path: Path, lineno: int, line: str, lower: str
    ) -> list[Finding]:
        findings: list[Finding] = []
        for match in GENERIC_ASSIGNMENT_RE.finditer(line):
            name = match.group(1)
            value = match.group(2)
            if self._looks_like_placeholder(value, lower):
                continue
            if value.lower() in SAFE_GENERIC_VALUES:
                continue
            if value.startswith("${") or value.startswith("$(") or value.startswith("{{"):
                continue
            if value.upper() == value and "_" in value and len(value) < 40:
                # Likely env var name reference like MY_API_KEY
                continue
            if not _looks_secretish(value):
                continue
            snippet = _mask_secret(line.rstrip("\n\r"), extra_values=[value])
            findings.append(
                Finding(
                    rule=self.rule,
                    path=path,
                    line=lineno,
                    column=match.start(2) + 1,
                    end_line=lineno,
                    end_column=match.end(2) + 1,
                    message=f"Possible secret assigned to '{name}'.",
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
            if (
                "sk-" in lower_value
                or "sk_" in lower_value
                or "rk_" in lower_value
                or "akia" in lower_value
                or "ghp_" in lower_value
                or "gho_" in lower_value
                or "ghu_" in lower_value
                or "ghs_" in lower_value
                or "glpat-" in lower_value
                or "xox" in lower_value
                or "sg." in lower_value
                or "npm_" in lower_value
                or "pypi-" in lower_value
                or "aiza" in lower_value
                or re.fullmatch(r"[A-Za-z0-9/+=]{40}", value)
            ):
                return True
        return False


def _looks_secretish(value: str) -> bool:
    if len(value) < 12:
        return False
    # Paths, URLs, normal words are unlikely secrets.
    if "/" in value or "\\" in value:
        # allow base64-ish but not paths; paths usually have multiple slashes or extensions
        if value.count("/") > 1 or "." in value.split("/")[-1]:
            return False
    if value.startswith("http://") or value.startswith("https://"):
        return False
    if re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", value) and len(value) < 24:
        return False
    categories = 0
    if re.search(r"[a-z]", value):
        categories += 1
    if re.search(r"[A-Z]", value):
        categories += 1
    if re.search(r"[0-9]", value):
        categories += 1
    if re.search(r"[^A-Za-z0-9]", value):
        categories += 1
    if categories < 2:
        return False
    # Shannon-ish simple check: enough variety for a token-like string.
    if len(value) >= 20 and categories >= 2:
        return True
    if len(value) >= 12 and categories >= 3:
        return True
    return False


def _mask_secret(line: str, extra_values: list[str] | None = None) -> str:
    masked = re.sub(r"(AKIA|ASIA)[0-9A-Z]{16}", r"\1****************", line)
    masked = re.sub(
        r"gh[pousr]_[A-Za-z0-9]{36}", "gh*_************************************", masked
    )
    masked = re.sub(r"github_pat_[A-Za-z0-9_]{20,}", "github_pat_[REDACTED]", masked)
    masked = re.sub(r"glpat-[A-Za-z0-9\-_]{20,}", "glpat-[REDACTED]", masked)
    masked = re.sub(r"sk_(?:live|test)_[A-Za-z0-9]{16,}", "sk_*_[REDACTED]", masked)
    masked = re.sub(r"rk_(?:live|test)_[A-Za-z0-9]{16,}", "rk_*_[REDACTED]", masked)
    masked = re.sub(r"SG\.[A-Za-z0-9_-]{16,}\.[A-Za-z0-9_-]{16,}", "SG.[REDACTED]", masked)
    masked = re.sub(r"npm_[A-Za-z0-9]{20,}", "npm_[REDACTED]", masked)
    masked = re.sub(r"pypi-[A-Za-z0-9_-]{20,}", "pypi-[REDACTED]", masked)
    masked = re.sub(r"sk-ant-[A-Za-z0-9\-_]{20,}", "sk-ant-[REDACTED]", masked)
    masked = re.sub(r"sk-(?:proj-|live-|test-)?[A-Za-z0-9]{20,}", "sk-[REDACTED]", masked)
    masked = re.sub(r"xox[baprs]-[A-Za-z0-9-]{10,}", "xox*-[REDACTED]", masked)
    masked = re.sub(r"AIza[0-9A-Za-z\-_]{35}", "AIza[REDACTED]", masked)
    masked = re.sub(r"(?i)\bBearer\s+[A-Za-z0-9\-._~+/]{20,}=*", "Bearer [REDACTED]", masked)
    for value in extra_values or []:
        if value and len(value) >= 4 and value in masked:
            masked = masked.replace(value, "[REDACTED_SECRET]")
    return masked[:240]
