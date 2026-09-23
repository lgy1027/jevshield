"""Framework-independent contracts for semantic loop review."""

from dataclasses import dataclass
from enum import Enum
import math
from typing import Optional, Tuple

from .runtime import DecisionStatus


class LoopReviewAction(str, Enum):
    """A semantic recommendation returned at an explicit loop checkpoint."""

    CONTINUE = "continue"
    ASK_FOR_HELP = "ask_for_help"
    STOP_STALLED = "stop_stalled"


@dataclass(frozen=True)
class LoopReviewInput:
    """Immutable application-owned state supplied at a review checkpoint."""

    trusted_objective: str
    checkpoint: str
    iteration: int
    spent_budget: Optional[float] = None
    step_summaries: Tuple[str, ...] = ()
    evidence_summary: Optional[str] = None

    def __post_init__(self) -> None:
        if type(self.trusted_objective) is not str or not self.trusted_objective:
            raise ValueError("trusted_objective must be a non-empty string.")
        if type(self.checkpoint) is not str or not self.checkpoint:
            raise ValueError("checkpoint must be a non-empty string.")
        if (
            not isinstance(self.iteration, int)
            or isinstance(self.iteration, bool)
            or self.iteration < 1
        ):
            raise ValueError("iteration must be a positive integer.")
        if self.spent_budget is not None and (
            isinstance(self.spent_budget, bool)
            or not isinstance(self.spent_budget, (int, float))
            or not math.isfinite(float(self.spent_budget))
            or self.spent_budget < 0.0
        ):
            raise ValueError("spent_budget must be a finite non-negative number.")
        if type(self.step_summaries) is not tuple or any(
            type(summary) is not str or not summary
            for summary in self.step_summaries
        ):
            raise ValueError("step_summaries must be a tuple of non-empty strings.")
        if self.evidence_summary is not None and (
            type(self.evidence_summary) is not str or not self.evidence_summary
        ):
            raise ValueError("evidence_summary must be a non-empty string when set.")


@dataclass(frozen=True)
class LoopReviewDecision:
    """Immutable semantic review result; the host remains in control."""

    action: Optional[LoopReviewAction]
    status: DecisionStatus
    confidence: float
    latency_ms: float
    source: str
    reason: str = ""

    def __post_init__(self) -> None:
        if not isinstance(self.status, DecisionStatus):
            raise ValueError("status must be a DecisionStatus.")
        if self.status is DecisionStatus.RESOLVED:
            if not isinstance(self.action, LoopReviewAction):
                raise ValueError("Resolved reviews require a LoopReviewAction.")
        elif self.action is not None:
            raise ValueError("Uncertain and unavailable reviews cannot carry an action.")
        for number, label in (
            (self.confidence, "confidence"),
            (self.latency_ms, "latency_ms"),
        ):
            if (
                isinstance(number, bool)
                or not isinstance(number, (int, float))
                or not math.isfinite(float(number))
                or number < 0.0
            ):
                raise ValueError(
                    "{} must be a finite non-negative number.".format(label)
                )
        if type(self.source) is not str or not self.source:
            raise ValueError("source must be a non-empty string.")
        if type(self.reason) is not str:
            raise ValueError("reason must be a string.")
