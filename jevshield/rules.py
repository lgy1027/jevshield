"""Deterministic local rules that can deny before remote evaluation."""

import re
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Mapping

from .models import GuardContext
from .redaction import redact_for_audit


class RuleOutcome(str, Enum):
    """The possible outcomes of a local rule evaluation."""

    NO_MATCH = "no_match"
    DENY = "deny"
    ERROR = "error"


@dataclass(frozen=True)
class RuleResult:
    """A local rule result with an audit-safe explanation."""

    outcome: RuleOutcome
    reason: str = ""
    evidence: Mapping[str, Any] = field(default_factory=dict)


# Tool-name stems and command patterns previously used only after evaluator
# fallback.  They are deliberately deny-only: no local rule grants execution.
DANGEROUS_STEMS = frozenset({
    "rm", "delete", "remove", "drop", "truncate", "wipe", "destroy",
    "purge", "kill", "terminate", "format", "erase", "shutdown", "revoke",
})
DANGEROUS_PATTERNS = (
    r"rm\s+-rf", r"drop\s+table", r"drop\s+database", r"format\s+[a-z]:",
    r"truncate\s+table", r"kill\s+-9", r"chmod\s+777", r">\s*/dev/sd",
    r"delete\s+from\s+[a-z_0-9]+", r"aws\s+s3\s+rb\s+--force",
)
SENSITIVE_UPLOAD_PATTERNS = (
    r"(?:curl|wget)\b[^\n]*\s(?:-F\s*['\"]?[^\s=]*=@|--upload-file\s+)(?:/etc/(?:shadow|passwd)|[^\s]*\.ssh/|[^\s]*(?:id_rsa|\.pem))",
    r"\b(?:scp|rsync)\b[^\n]*(?:/etc/(?:shadow|passwd)|[^\s]*\.ssh/|[^\s]*(?:id_rsa|\.pem))",
    r"\baws\s+s3\s+cp\b[^\n]*(?:/etc/(?:shadow|passwd)|[^\s]*\.ssh/|[^\s]*(?:id_rsa|\.pem))",
)


def fast_deny_reason(tool_name: str, text: str) -> str:
    """Return a stable deny reason for a known destructive signal, if any."""

    stems = {stem for stem in re.split(r"[_\W]+", tool_name.lower()) if stem}
    matched_stems = stems & DANGEROUS_STEMS
    if matched_stems:
        return "dangerous tool-name stem: " + ", ".join(sorted(matched_stems))
    if any(re.search(pattern, text, re.IGNORECASE) for pattern in DANGEROUS_PATTERNS):
        return "known destructive command pattern"
    if any(re.search(pattern, text, re.IGNORECASE) for pattern in SENSITIVE_UPLOAD_PATTERNS):
        return "sensitive file upload pattern"
    return ""


class LocalRuleEngine:
    """Evaluate deterministic Fast-Deny rules without I/O."""

    def evaluate(self, context: GuardContext) -> RuleResult:
        evidence = redact_for_audit({
            "tool_name": context.tool_name,
            "arguments": context.args,
        })
        text = "{} {} {}".format(
            context.tool_name, context.tool_description, context.args
        )
        reason = fast_deny_reason(context.tool_name, text)
        if reason:
            return RuleResult(RuleOutcome.DENY, reason, evidence)
        return RuleResult(RuleOutcome.NO_MATCH, evidence=evidence)
