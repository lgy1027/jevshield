"""Redacted audit event contracts for policy enforcement."""

from dataclasses import dataclass
from typing import Callable, Protocol

from .models import GuardDecision


@dataclass(frozen=True)
class AuditEvent(GuardDecision):
    """A redacted decision annotated with its terminal enforcement outcome."""

    outcome: str = ""

    @classmethod
    def from_decision(cls, decision: GuardDecision, outcome: str) -> "AuditEvent":
        return cls(
            action=decision.action,
            context=decision.context,
            evaluation=decision.evaluation,
            policy_name=decision.policy_name,
            network_called=decision.network_called,
            redacted_arguments=decision.redacted_arguments,
            outcome=outcome,
        )


class AuditSink(Protocol):
    """Consumer for terminal guard enforcement events."""

    def emit(self, event: AuditEvent) -> None:
        """Record one terminal enforcement event."""


class NullAuditSink:
    """Audit sink used when the caller has not configured persistence."""

    def emit(self, event: AuditEvent) -> None:
        del event


class CallbackAuditSink:
    """Adapt a callback into an audit sink."""

    def __init__(self, callback: Callable[[AuditEvent], None]):
        self._callback = callback

    def emit(self, event: AuditEvent) -> None:
        self._callback(event)
