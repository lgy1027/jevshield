"""Local, framework-independent safeguards for multi-agent handoffs."""

from dataclasses import dataclass
from enum import Enum
from typing import Optional


class HandoffAction(str, Enum):
    """The host's next step after a requested agent-to-agent handoff."""

    CONTINUE = "continue"
    HUMAN_ESCALATION = "human_escalation"


@dataclass(frozen=True)
class HandoffPolicy:
    """Deterministic limits for one multi-agent delegation run."""

    max_handoffs: int = 10
    max_repeated_handoffs: int = 2

    def __post_init__(self) -> None:
        for value in (self.max_handoffs, self.max_repeated_handoffs):
            if not isinstance(value, int) or isinstance(value, bool) or value < 1:
                raise ValueError("Handoff limits must be positive integers.")


@dataclass(frozen=True)
class HandoffDecision:
    """A local recommendation; the host performs any actual escalation."""

    action: HandoffAction
    reason: str
    handoff_count: int


class HandoffTracker:
    """Track one delegation run and stop handoff budgets and cycles locally."""

    def __init__(self, policy: Optional[HandoffPolicy] = None) -> None:
        self.policy = policy or HandoffPolicy()
        self.reset()

    def reset(self) -> None:
        """Clear state before reusing this tracker for another top-level task."""

        self._handoff_count = 0
        self._last_handoff: Optional[tuple[str, str]] = None
        self._repeated_handoffs = 0
        self._visited_roles: set[str] = set()
        self._terminal: Optional[HandoffDecision] = None

    def observe(self, source_role: str, target_role: str) -> HandoffDecision:
        """Record a requested handoff using opaque role identifiers."""

        if self._terminal is not None:
            return self._terminal
        self._validate_role(source_role)
        self._validate_role(target_role)
        if source_role == target_role:
            raise ValueError("source_role and target_role must differ.")

        handoff = (source_role, target_role)
        self._handoff_count += 1
        self._record_repetition(handoff)

        if self._handoff_count >= self.policy.max_handoffs:
            return self._escalate("max_handoffs")
        if self._repeated_handoffs >= self.policy.max_repeated_handoffs:
            return self._escalate("repeated_handoff")
        if target_role in self._visited_roles:
            return self._escalate("handoff_cycle")

        self._visited_roles.add(source_role)
        self._visited_roles.add(target_role)
        return HandoffDecision(HandoffAction.CONTINUE, "", self._handoff_count)

    @staticmethod
    def _validate_role(role: str) -> None:
        if not isinstance(role, str) or not role:
            raise ValueError("Role identifiers must be non-empty strings.")

    def _record_repetition(self, handoff: tuple[str, str]) -> None:
        if handoff == self._last_handoff:
            self._repeated_handoffs += 1
        else:
            self._last_handoff = handoff
            self._repeated_handoffs = 1

    def _escalate(self, reason: str) -> HandoffDecision:
        self._terminal = HandoffDecision(
            HandoffAction.HUMAN_ESCALATION, reason, self._handoff_count
        )
        return self._terminal
