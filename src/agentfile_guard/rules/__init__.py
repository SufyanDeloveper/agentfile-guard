from __future__ import annotations

from ..models import Rule
from .dangerous_patterns import DANGEROUS_SHELL_RULE, PROMPT_INJECTION_RULE, DangerousPatternsRule
from .secrets import SecretsRule
from .stale_refs import StaleRefsRule
from .unicode_controls import UnicodeControlsRule

ALL_RULES = [
    SecretsRule(),
    UnicodeControlsRule(),
    StaleRefsRule(),
    DangerousPatternsRule(),
]

# Metadata for all rule IDs emitted by checkers (including multi-rule checkers).
ALL_RULE_METADATA: list[Rule] = [
    SecretsRule().rule,
    UnicodeControlsRule().rule,
    StaleRefsRule().rule,
    DANGEROUS_SHELL_RULE,
    PROMPT_INJECTION_RULE,
]

RULES_BY_ID = {rule.id: rule for rule in ALL_RULE_METADATA}

__all__ = [
    "ALL_RULES",
    "ALL_RULE_METADATA",
    "RULES_BY_ID",
    "SecretsRule",
    "UnicodeControlsRule",
    "StaleRefsRule",
    "DangerousPatternsRule",
]
