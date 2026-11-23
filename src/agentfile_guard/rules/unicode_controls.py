from __future__ import annotations

from pathlib import Path

from ..config import Config
from ..models import Finding, Rule, Severity

UNICODE_RULE = Rule(
    id="AFG002",
    name="hidden-unicode-control",
    description=(
        "Detects hidden/bidi Unicode control characters often used for instruction obfuscation."
    ),
    severity=Severity.ERROR,
)


SUSPICIOUS_CODEPOINTS: dict[int, str] = {
    0x061C: "ARABIC LETTER MARK",
    0x200B: "ZERO WIDTH SPACE",
    0x200C: "ZERO WIDTH NON-JOINER",
    0x200D: "ZERO WIDTH JOINER",
    0x200E: "LEFT-TO-RIGHT MARK",
    0x200F: "RIGHT-TO-LEFT MARK",
    0x202A: "LEFT-TO-RIGHT EMBEDDING",
    0x202B: "RIGHT-TO-LEFT EMBEDDING",
    0x202C: "POP DIRECTIONAL FORMATTING",
    0x202D: "LEFT-TO-RIGHT OVERRIDE",
    0x202E: "RIGHT-TO-LEFT OVERRIDE",
    0x2060: "WORD JOINER",
    0x2066: "LEFT-TO-RIGHT ISOLATE",
    0x2067: "RIGHT-TO-LEFT ISOLATE",
    0x2068: "FIRST STRONG ISOLATE",
    0x2069: "POP DIRECTIONAL ISOLATE",
    0x206A: "INHIBIT SYMMETRIC SWAPPING",
    0x206B: "ACTIVATE SYMMETRIC SWAPPING",
    0x206C: "INHIBIT ARABIC FORM SHAPING",
    0x206D: "ACTIVATE ARABIC FORM SHAPING",
    0x206E: "NATIONAL DIGIT SHAPES",
    0x206F: "NOMINAL DIGIT SHAPES",
    0xFEFF: "ZERO WIDTH NO-BREAK SPACE/BOM",
}


def _is_tag_char(cp: int) -> bool:
    return 0xE0000 <= cp <= 0xE007F


class UnicodeControlsRule:
    rule = UNICODE_RULE

    def check(self, path: Path, text: str, root: Path, config: Config) -> list[Finding]:
        findings: list[Finding] = []
        for lineno, line in enumerate(text.splitlines(), start=1):
            for idx, ch in enumerate(line, start=1):
                cp = ord(ch)
                if cp == 0xFEFF and lineno == 1 and idx == 1:
                    # UTF-8 BOM at file start is benign.
                    continue
                name = SUSPICIOUS_CODEPOINTS.get(cp)
                if name is None and _is_tag_char(cp):
                    name = "TAG CHARACTER"
                if name is None:
                    continue
                findings.append(
                    Finding(
                        rule=self.rule,
                        path=path,
                        line=lineno,
                        column=idx,
                        end_line=lineno,
                        end_column=idx + 1,
                        message=(
                            f"Hidden Unicode control character U+{cp:04X} ({name}) found. "
                            "This can be used to obfuscate agent instructions."
                        ),
                        snippet=_visible_snippet(line),
                    )
                )
        return findings


def _visible_snippet(line: str) -> str:
    out = []
    for ch in line:
        cp = ord(ch)
        if cp in SUSPICIOUS_CODEPOINTS or _is_tag_char(cp):
            out.append(f"<U+{cp:04X}>")
        else:
            out.append(ch)
    return "".join(out)[:240]
