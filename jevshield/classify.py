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

        if not isinstance(descriptions, Mapping):
            raise ValueError("Descriptions must contain exactly one entry per intent.")
        description_keys = list(descriptions)
        if (
            len(description_keys) != len(members)
            or any(type(key) is not enum_type for key in description_keys)
            or any(
                not any(key is member for member in members)
                for key in description_keys
            )
        ):
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
        return self._classify_framed(build_decision_state(state))

    async def aclassify(self, state: Any) -> IntentResult[TIntent]:
        return await self._aclassify_framed(build_decision_state(state))

    def _classify_framed(self, state: str) -> IntentResult[TIntent]:
        """Classify a state already framed by the SDK's redaction helper."""
        answer = self._client.choose(state, self._question)
        return self._result_from_answer(answer)

    async def _aclassify_framed(self, state: str) -> IntentResult[TIntent]:
        """Async counterpart for an already framed, redacted state."""
        answer = await self._client.achoose(state, self._question)
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
