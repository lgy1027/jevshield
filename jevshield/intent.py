"""Framework-independent consistency checks for trusted and observed intent."""

from dataclasses import dataclass
from enum import Enum
from typing import Callable, Generic, Optional

from .classify import IntentClassifier, IntentResult, TIntent
from .models import Action, GuardContext
from .redaction import build_observed_intent_state
from .runtime import DecisionStatus


class IntentStatus(str, Enum):
    SKIPPED = "skipped"
    PASS = "pass"
    MISMATCH = "mismatch"
    UNCERTAIN = "uncertain"
    UNAVAILABLE = "unavailable"


@dataclass(frozen=True)
class IntentAssessment(Generic[TIntent]):
    """A restrictive intent signal for Guard to combine with other checks."""

    status: IntentStatus
    expected: Optional[TIntent]
    observed: Optional[TIntent]
    action: Optional[Action]
    reason: str


@dataclass(frozen=True)
class IntentPolicy(Generic[TIntent]):
    """Compare a trusted objective with the observed tool invocation."""

    classifier: IntentClassifier[TIntent]
    on_mismatch: Action = Action.DENY
    on_uncertain: Action = Action.DENY
    on_unavailable: Action = Action.DENY
    relation: Optional[Callable[[TIntent, TIntent], bool]] = None

    def __post_init__(self) -> None:
        for name in ("on_mismatch", "on_uncertain", "on_unavailable"):
            action = getattr(self, name)
            if action is not Action.ASK and action is not Action.DENY:
                raise ValueError("{} must be Action.ASK or Action.DENY.".format(name))
        if self.relation is not None and not callable(self.relation):
            raise TypeError("relation must be callable or None.")

    def assess(self, context: GuardContext) -> IntentAssessment[TIntent]:
        if context.intent is None:
            return IntentAssessment(
                IntentStatus.SKIPPED, None, None, None, "No trusted intent supplied."
            )
        expected = self.classifier.classify(context.intent)
        observed = self.classifier._classify_framed(
            build_observed_intent_state(context), observed=True
        )
        return self._assess_results(expected, observed)

    async def aassess(self, context: GuardContext) -> IntentAssessment[TIntent]:
        if context.intent is None:
            return IntentAssessment(
                IntentStatus.SKIPPED, None, None, None, "No trusted intent supplied."
            )
        expected = await self.classifier.aclassify(context.intent)
        observed = await self.classifier._aclassify_framed(
            build_observed_intent_state(context), observed=True
        )
        return self._assess_results(expected, observed)

    def _assess_results(
        self, expected: IntentResult[TIntent], observed: IntentResult[TIntent]
    ) -> IntentAssessment[TIntent]:
        expected_value = expected.value
        observed_value = observed.value
        if (
            expected.status is DecisionStatus.UNAVAILABLE
            or observed.status is DecisionStatus.UNAVAILABLE
        ):
            return IntentAssessment(
                IntentStatus.UNAVAILABLE,
                expected_value,
                observed_value,
                self.on_unavailable,
                "Intent classification unavailable.",
            )
        if (
            expected.status is not DecisionStatus.RESOLVED
            or observed.status is not DecisionStatus.RESOLVED
            or expected_value is None
            or observed_value is None
        ):
            return IntentAssessment(
                IntentStatus.UNCERTAIN,
                expected_value,
                observed_value,
                self.on_uncertain,
                "Intent classification uncertain.",
            )
        compatible = (
            self.relation(expected_value, observed_value)
            if self.relation is not None
            else expected_value is observed_value
        )
        if compatible:
            return IntentAssessment(
                IntentStatus.PASS,
                expected_value,
                observed_value,
                None,
                "Intent matched.",
            )
        return IntentAssessment(
            IntentStatus.MISMATCH,
            expected_value,
            observed_value,
            self.on_mismatch,
            "Observed intent differs from trusted intent.",
        )
