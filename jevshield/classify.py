"""Typed intent classification built on framework-independent decisions."""

from dataclasses import dataclass
from enum import Enum
import math
from typing import Any, Dict, Generic, Mapping, Optional, Type, TypeVar

from .redaction import build_decision_state
from .runtime import ChoiceAnswer, ChoiceQuestion, DecisionClient, DecisionStatus


TIntent = TypeVar("TIntent", bound=Enum)


@dataclass(frozen=True)
class IntentResult(Generic[TIntent]):
    value: Optional[TIntent]
    status: DecisionStatus
    confidence: float
    latency_ms: float
    source: str
    reason: str = ""


class IntentClassifier(Generic[TIntent]):
    """Classify arbitrary input into one member of an intent enum."""

    def __init__(
        self,
        enum_type: Type[TIntent],
        descriptions: Mapping[TIntent, str],
        client: DecisionClient,
        min_confidence: float = 0.0,
    ) -> None:
        if not isinstance(enum_type, type) or not issubclass(enum_type, Enum):
            raise TypeError("enum_type must be an Enum class.")

        members = list(enum_type)
        if not members:
            raise ValueError("enum_type must define at least one member.")
        if len(enum_type.__members__) != len(members):
            raise ValueError("Intent enum values must be unique.")

        members_by_value: Dict[str, TIntent] = {}
        for member in members:
            value = member.value
            if not isinstance(value, str) or not value.strip():
                raise ValueError("Intent enum values must be non-empty strings.")
            if value in members_by_value:
                raise ValueError("Intent enum values must be unique.")
            members_by_value[value] = member

        if not isinstance(descriptions, Mapping) or set(descriptions) != set(members):
            raise ValueError("Descriptions must contain exactly one entry per intent.")
        descriptions_copy: Dict[TIntent, str] = {}
        for member in members:
            description = descriptions[member]
            if not isinstance(description, str) or not description.strip():
                raise ValueError("Intent descriptions must be non-empty strings.")
            descriptions_copy[member] = description

        if (
            isinstance(min_confidence, bool)
            or not isinstance(min_confidence, (int, float))
            or not math.isfinite(float(min_confidence))
            or not 0.0 <= min_confidence <= 1.0
        ):
            raise ValueError("min_confidence must be a finite number from 0 to 1.")

        self._client = client
        self._min_confidence = float(min_confidence)
        self._members_by_value = members_by_value
        self._question = ChoiceQuestion(
            name="intent",
            instructions="Classify the request into the most appropriate intent.",
            criteria={member.value: descriptions_copy[member] for member in members},
        )

    def classify(self, state: Any) -> IntentResult[TIntent]:
        answer = self._client.choose(build_decision_state(state), self._question)
        return self._result_from_answer(answer)

    async def aclassify(self, state: Any) -> IntentResult[TIntent]:
        answer = await self._client.achoose(build_decision_state(state), self._question)
        return self._result_from_answer(answer)

    def _result_from_answer(self, answer: ChoiceAnswer) -> IntentResult[TIntent]:
        if answer.status is not DecisionStatus.RESOLVED:
            return IntentResult(
                None,
                answer.status,
                answer.confidence,
                answer.latency_ms,
                answer.source,
                answer.reason,
            )
        if answer.confidence < self._min_confidence:
            return IntentResult(
                None,
                DecisionStatus.UNCERTAIN,
                answer.confidence,
                answer.latency_ms,
                answer.source,
                "Confidence is below min_confidence.",
            )
        value = self._members_by_value.get(answer.value)
        if value is None:
            return IntentResult(
                None,
                DecisionStatus.UNCERTAIN,
                answer.confidence,
                answer.latency_ms,
                answer.source,
                "Returned value is not a valid intent.",
            )
        return IntentResult(
            value,
            answer.status,
            answer.confidence,
            answer.latency_ms,
            answer.source,
            answer.reason,
        )
