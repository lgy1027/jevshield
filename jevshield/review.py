"""Framework-independent contracts for semantic loop review."""

from dataclasses import dataclass
from enum import Enum
import math
from typing import Dict, Optional, Tuple

from .redaction import build_decision_state
from .runtime import ChoiceAnswer, ChoiceQuestion, DecisionClient
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


class LoopReviewer:
    """Recommend a semantic action at an application-selected checkpoint."""

    def __init__(
        self,
        client: DecisionClient,
        min_confidence: float = 0.0,
    ) -> None:
        if (
            isinstance(min_confidence, bool)
            or not isinstance(min_confidence, (int, float))
            or not math.isfinite(float(min_confidence))
            or not 0.0 <= min_confidence <= 1.0
        ):
            raise ValueError("min_confidence must be a finite number from 0 to 1.")

        self._client = client
        self._min_confidence = float(min_confidence)
        self._actions_by_value: Dict[str, LoopReviewAction] = {
            action.value: action for action in LoopReviewAction
        }
        self._question = ChoiceQuestion(
            name="loop_review",
            instructions=(
                "Recommend whether the application should continue, ask for help, "
                "or stop because progress has stalled."
            ),
            criteria={
                LoopReviewAction.CONTINUE.value: (
                    "Continue because useful progress remains likely."
                ),
                LoopReviewAction.ASK_FOR_HELP.value: (
                    "Ask for human or application help before continuing."
                ),
                LoopReviewAction.STOP_STALLED.value: (
                    "Stop because the work is stalled without sufficient progress."
                ),
            },
        )

    def review(self, value: LoopReviewInput) -> LoopReviewDecision:
        answer = self._client.choose(self._state(value), self._question)
        return self._decision_from_answer(answer)

    async def areview(self, value: LoopReviewInput) -> LoopReviewDecision:
        answer = await self._client.achoose(self._state(value), self._question)
        return self._decision_from_answer(answer)

    @staticmethod
    def _state(value: LoopReviewInput) -> str:
        return build_decision_state(
            {
                "trusted_objective": value.trusted_objective,
                "checkpoint": value.checkpoint,
                "iteration": value.iteration,
                "spent_budget": value.spent_budget,
                "step_summaries": value.step_summaries,
                "evidence_summary": value.evidence_summary,
            }
        )

    def _decision_from_answer(self, answer: ChoiceAnswer) -> LoopReviewDecision:
        if answer.status is not DecisionStatus.RESOLVED:
            return LoopReviewDecision(
                None,
                answer.status,
                answer.confidence,
                answer.latency_ms,
                answer.source,
                answer.reason,
            )
        if answer.confidence < self._min_confidence:
            return LoopReviewDecision(
                None,
                DecisionStatus.UNCERTAIN,
                answer.confidence,
                answer.latency_ms,
                answer.source,
                "Confidence is below min_confidence.",
            )
        action = self._actions_by_value.get(answer.value)
        if action is None:
            return LoopReviewDecision(
                None,
                DecisionStatus.UNCERTAIN,
                answer.confidence,
                answer.latency_ms,
                answer.source,
                "Returned value is not a valid loop review action.",
            )
        return LoopReviewDecision(
            action,
            DecisionStatus.RESOLVED,
            answer.confidence,
            answer.latency_ms,
            answer.source,
            answer.reason,
        )
