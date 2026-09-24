"""Framework-independent contracts for decision-control clients."""

from dataclasses import dataclass
from enum import Enum
import math
from types import MappingProxyType
from typing import Mapping, Optional, Protocol


class DecisionStatus(str, Enum):
    RESOLVED = "resolved"
    UNCERTAIN = "uncertain"
    UNAVAILABLE = "unavailable"


@dataclass(frozen=True)
class ChoiceQuestion:
    name: str
    instructions: str
    criteria: Mapping[str, str]

    def __post_init__(self) -> None:
        if not isinstance(self.name, str) or not self.name.strip():
            raise ValueError("Choice question name must be a non-empty string.")
        if not isinstance(self.instructions, str) or not self.instructions.strip():
            raise ValueError("Choice instructions must be a non-empty string.")
        if not isinstance(self.criteria, Mapping) or not self.criteria:
            raise ValueError("Choice criteria must be a non-empty mapping.")
        criteria_copy = dict(self.criteria)
        if any(
            not isinstance(key, str)
            or not key.strip()
            or not isinstance(value, str)
            or not value.strip()
            for key, value in criteria_copy.items()
        ):
            raise ValueError(
                "Choice criteria keys and descriptions must be non-empty strings."
            )
        object.__setattr__(self, "criteria", MappingProxyType(criteria_copy))


@dataclass(frozen=True)
class ChoiceAnswer:
    value: Optional[str]
    confidence: float
    status: DecisionStatus
    latency_ms: float
    source: str
    reason: str = ""

    def __post_init__(self) -> None:
        if not isinstance(self.status, DecisionStatus):
            raise ValueError("Choice status must be a DecisionStatus.")
        if self.status is DecisionStatus.RESOLVED and (
            not isinstance(self.value, str) or not self.value
        ):
            raise ValueError("Resolved choices require a non-empty value.")
        if self.status is not DecisionStatus.RESOLVED and self.value is not None:
            raise ValueError("Uncertain and unavailable choices cannot carry a value.")
        for number, label, minimum in (
            (self.confidence, "confidence", 0.0),
            (self.latency_ms, "latency_ms", 0.0),
        ):
            if (
                isinstance(number, bool)
                or not isinstance(number, (int, float))
                or not math.isfinite(float(number))
                or float(number) < minimum
            ):
                raise ValueError(
                    "Choice {} must be a finite non-negative number.".format(label)
                )
        if self.confidence > 1.0:
            raise ValueError("Choice confidence must be at most 1.0.")
        if not isinstance(self.source, str) or not self.source:
            raise ValueError("Choice source must be a non-empty string.")


class DecisionClient(Protocol):
    def choose(self, state: str, question: ChoiceQuestion) -> ChoiceAnswer:
        ...

    async def achoose(self, state: str, question: ChoiceQuestion) -> ChoiceAnswer:
        ...
