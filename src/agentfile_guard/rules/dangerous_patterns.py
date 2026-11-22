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
    (re.compile(r"\bchmod\s+777\b"), "chmod 777"),
    (re.compile(r"\brm\s+-rf\s+/(?:\s|$)"), "rm -rf /"),
]

PROMPT_INJECTION_PATTERNS: list[tuple[re.Pattern[str], str]] = [
    (
        re.compile(r"\bignore\s+(?:all\s+)?previous\s+instructions\b", re.IGNORECASE),
        "ignore previous instructions",
    ),
    (
        re.compile(r"\bdisregard\s+(?:all\s+)?previous\s+instructions\b", re.IGNORECASE),
        "disregard previous instructions",
    ),
    (
        re.compile(r"\bforget\s+(?:all\s+)?previous\s+instructions\b", re.IGNORECASE),
        "forget previous instructions",
    ),
    (re.compile(r"\breveal\s+(?:the\s+)?system\s+prompt\b", re.IGNORECASE), "reveal system prompt"),
    (
        re.compile(r"\byou\s+are\s+now\s+(?:DAN|developer\s+mode)\b", re.IGNORECASE),
        "role override / jailbreak marker",
    ),
    (
        re.compile(
            r"\bdo\s+not\s+follow\s+(?:any\s+)?(?:safety|security)\s+(?:rules|policies)\b",
            re.IGNORECASE,
        ),
        "safety override instruction",
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
        out: list[Finding] = []
        for pattern, label in patterns:
            m = pattern.search(line)
            if not m:
                continue
            out.append(
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
            )
        return out
