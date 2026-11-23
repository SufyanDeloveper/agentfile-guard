from __future__ import annotations

import re
from pathlib import Path

from ..config import Config
from ..models import Finding, Rule, Severity

DANGEROUS_SHELL_RULE = Rule(
    id="AFG005",
    name="dangerous-shell-instruction",
    description="Detects dangerous shell execution patterns in agent instruction files.",
    severity=Severity.ERROR,
)

PROMPT_INJECTION_RULE = Rule(
    id="AFG006",
    name="prompt-injection-marker",
    description="Detects common prompt-injection or instruction-override phrases.",
    severity=Severity.WARNING,
)


DANGEROUS_SHELL_PATTERNS: list[tuple[re.Pattern[str], str]] = [
    (re.compile(r"\bcurl\b[^\n|]{0,200}\|\s*(?:ba)?sh\b", re.IGNORECASE), "curl piped to shell"),
    (re.compile(r"\bwget\b[^\n|]{0,200}\|\s*(?:ba)?sh\b", re.IGNORECASE), "wget piped to shell"),
    (
        re.compile(
            r"\b(?:iwr|invoke-webrequest)\b[^\n|]{0,200}\|\s*(?:iex|invoke-expression)\b",
            re.IGNORECASE,
        ),
        "PowerShell download piped to Invoke-Expression",
    ),
    (re.compile(r"\bInvoke-Expression\b", re.IGNORECASE), "Invoke-Expression usage"),
    (re.compile(r"\b(?:iex)\s*\(", re.IGNORECASE), "PowerShell iex() usage"),
    (
        re.compile(
            r"\bpowershell(?:\.exe)?\b[^\n]{0,120}\s-(?:enc|encodedcommand)\b", re.IGNORECASE
        ),
        "PowerShell encoded command",
    ),
    (re.compile(r"\bchmod\s+777\b"), "chmod 777"),
    (re.compile(r"\brm\s+-rf\s+/(?:\s|$)"), "rm -rf /"),
]

PROMPT_INJECTION_PATTERNS: list[tuple[re.Pattern[str], str]] = [
    (
        re.compile(
            r"\b(?:ignore|disregard|forget|override)\s+"
            r"(?:all\s+|any\s+|the\s+|your\s+|my\s+)?"
            r"(?:previous|prior|above|earlier|preceding|system|developer|initial)\s+"
            r"(?:instructions?|rules?|directives?|prompts?|messages?|guidelines?)\b",
            re.IGNORECASE,
        ),
        "instruction override phrase",
    ),
    (
        re.compile(
            r"\b(?:reveal|show|print|expose|output|leak|display|repeat)\s+"
            r"(?:the\s+|your\s+|all\s+|any\s+|hidden\s+|secret\s+|internal\s+|original\s+)?"
            r"(?:system|developer|hidden|initial|internal|original)\s+"
            r"(?:prompt|instructions?|messages?|rules?)\b",
            re.IGNORECASE,
        ),
        "system prompt extraction phrase",
    ),
    (
        re.compile(
            r"\byou\s+are\s+now\s+"
            r"(?:DAN|developer\s+mode|unrestricted|jailbroken|in\s+developer\s+mode)\b",
            re.IGNORECASE,
        ),
        "role override / jailbreak marker",
    ),
    (
        re.compile(r"\b(?:do\s+anything\s+now|jailbreak(?:\s+mode)?)\b", re.IGNORECASE),
        "jailbreak marker",
    ),
    (
        re.compile(
            r"\b(?:bypass|disable|circumvent|ignore)\s+"
            r"(?:all\s+|any\s+|the\s+)?"
            r"(?:safety|security|guardrails?|filters?|restrictions?|policies?)\b",
            re.IGNORECASE,
        ),
        "safety bypass instruction",
    ),
    (
        re.compile(
            r"\bdo\s+not\s+follow\s+(?:any\s+)?(?:safety|security)\s+(?:rules|policies)\b",
            re.IGNORECASE,
        ),
        "safety override instruction",
    ),
    (
        re.compile(
            r"\b(?:new|updated|replacement)\s+(?:system\s+)?instructions?\s*:",
            re.IGNORECASE,
        ),
        "instruction replacement marker",
    ),
]


class DangerousPatternsRule:
    rule = DANGEROUS_SHELL_RULE

    def check(self, path: Path, text: str, root: Path, config: Config) -> list[Finding]:
        findings: list[Finding] = []
        for lineno, line in enumerate(text.splitlines(), start=1):
            findings.extend(
                self._scan_patterns(
                    path, lineno, line, DANGEROUS_SHELL_RULE, DANGEROUS_SHELL_PATTERNS
                )
            )
            findings.extend(
                self._scan_patterns(
                    path, lineno, line, PROMPT_INJECTION_RULE, PROMPT_INJECTION_PATTERNS
                )
            )
        return findings

    @staticmethod
    def _scan_patterns(
        path: Path, lineno: int, line: str, rule: Rule, patterns: list[tuple[re.Pattern[str], str]]
    ) -> list[Finding]:
        for pattern, label in patterns:
            m = pattern.search(line)
            if not m:
                continue
            return [
                Finding(
                    rule=rule,
                    path=path,
                    line=lineno,
                    column=m.start() + 1,
                    end_line=lineno,
                    end_column=m.end() + 1,
                    message=(
                        f"Detected {label}. Review this instruction for unsafe or "
                        "untrusted behavior."
                    ),
                    snippet=line.rstrip("\n\r")[:240],
                )
            ]
        return []
