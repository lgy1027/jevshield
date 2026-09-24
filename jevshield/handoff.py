"""Local, framework-independent safeguards for multi-agent handoffs."""

from dataclasses import dataclass
from enum import Enum
from typing import Optional
import warnings


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
    """Track active delegation and stop only true delegation loops locally."""

    def __init__(self, policy: Optional[HandoffPolicy] = None) -> None:
        self.policy = policy or HandoffPolicy()
        self.reset()

    def reset(self) -> None:
        """Clear state before reusing this tracker for another top-level task."""

        self._handoff_count = 0
        self._last_handoff: Optional[tuple[str, str]] = None
        self._repeated_handoffs = 0
        self._active_roles: list[str] = []
        self._terminal: Optional[HandoffDecision] = None

    def delegate(self, parent_role: str, child_role: str) -> HandoffDecision:
        """Delegate from the active role to a child and push that child on the stack."""

        if self._terminal is not None:
            return self._terminal
        self._validate_role(parent_role)
        self._validate_role(child_role)
        if parent_role == child_role:
            raise ValueError("parent_role and child_role must differ.")
        if self._active_roles:
            if parent_role != self._active_roles[-1]:
                raise ValueError("parent_role must be the active role.")
        else:
            self._active_roles.append(parent_role)

        handoff = (parent_role, child_role)
        self._handoff_count += 1
        self._record_repetition(handoff)

        if self._handoff_count >= self.policy.max_handoffs:
            return self._escalate("max_handoffs")
        if self._repeated_handoffs >= self.policy.max_repeated_handoffs:
            return self._escalate("repeated_delegation")
        if child_role in self._active_roles:
            return self._escalate("active_delegation_cycle")

        self._active_roles.append(child_role)
        return HandoffDecision(HandoffAction.CONTINUE, "", self._handoff_count)

    def observe(self, source_role: str, target_role: str) -> HandoffDecision:
        """Deprecated compatibility alias for one-way delegation."""

        warnings.warn(
            "observe() is deprecated; use delegate() or return_to_parent().",
            DeprecationWarning,
            stacklevel=2,
        )
        return self.delegate(source_role, target_role)

    def return_to_parent(self, child_role: str, parent_role: str) -> HandoffDecision:
        """Return from the active child to its parent without consuming budget."""

        if self._terminal is not None:
            return self._terminal
        self._validate_role(child_role)
        self._validate_role(parent_role)
        if (
            len(self._active_roles) < 2
            or self._active_roles[-1] != child_role
            or self._active_roles[-2] != parent_role
        ):
            raise ValueError("Return must match the active child and its parent.")

        self._active_roles.pop()
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
