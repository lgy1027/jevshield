"""Typed route selection built on framework-independent decisions."""

from dataclasses import dataclass
import math
from types import MappingProxyType
from typing import Any, Dict, Generic, Mapping, Optional, TypeVar

from .redaction import build_decision_state
from .runtime import ChoiceAnswer, ChoiceQuestion, DecisionClient, DecisionStatus


TTarget = TypeVar("TTarget")


@dataclass(frozen=True)
class Route(Generic[TTarget]):
    description: str
    target: TTarget


@dataclass(frozen=True)
class RouteSelection(Generic[TTarget]):
    route_key: Optional[str]
    target: Optional[TTarget]
    status: DecisionStatus
    confidence: float
    latency_ms: float
    source: str
    reason: str = ""


class Router(Generic[TTarget]):
    """Select a registered target without invoking it."""

    def __init__(
        self,
        routes: Mapping[str, Route[TTarget]],
        client: DecisionClient,
        min_confidence: float = 0.0,
        fallback_key: Optional[str] = None,
    ) -> None:
        if not isinstance(routes, Mapping) or not routes:
            raise ValueError("Routes must be a non-empty mapping.")

        routes_copy: Dict[str, Route[TTarget]] = {}
        for key, route in routes.items():
            if not isinstance(key, str) or not key.strip():
                raise ValueError("Route keys must be non-empty strings.")
            if not isinstance(route, Route):
                raise ValueError("Route values must be Route instances.")
            if not isinstance(route.description, str) or not route.description.strip():
                raise ValueError("Route descriptions must be non-empty strings.")
            routes_copy[key] = route

        if (
            isinstance(min_confidence, bool)
            or not isinstance(min_confidence, (int, float))
            or not math.isfinite(float(min_confidence))
            or not 0.0 <= min_confidence <= 1.0
        ):
            raise ValueError("min_confidence must be a finite number from 0 to 1.")
        if fallback_key is not None and fallback_key not in routes_copy:
            raise ValueError("fallback_key must identify a registered route.")

        self._routes = MappingProxyType(routes_copy)
        self._client = client
        self._min_confidence = float(min_confidence)
        self._fallback_key = fallback_key
        self._question = ChoiceQuestion(
            name="route",
            instructions="Route the request to the most appropriate target.",
            criteria=MappingProxyType(
                {key: route.description for key, route in routes_copy.items()}
            ),
        )

    def select(self, state: Any) -> RouteSelection[TTarget]:
        answer = self._client.choose(build_decision_state(state), self._question)
        return self._selection_from_answer(answer)

    async def aselect(self, state: Any) -> RouteSelection[TTarget]:
        answer = await self._client.achoose(build_decision_state(state), self._question)
        return self._selection_from_answer(answer)

    def _selection_from_answer(self, answer: ChoiceAnswer) -> RouteSelection[TTarget]:
        if answer.status is not DecisionStatus.RESOLVED:
            return self._fallback_or_empty(
                answer.status,
                answer.confidence,
                answer.latency_ms,
                answer.source,
                answer.reason,
            )
        if answer.value not in self._routes:
            return self._fallback_or_empty(
                DecisionStatus.UNCERTAIN,
                answer.confidence,
                answer.latency_ms,
                answer.source,
                "Selected route is not registered.",
            )
        if answer.confidence < self._min_confidence:
            return self._fallback_or_empty(
                DecisionStatus.UNCERTAIN,
                answer.confidence,
                answer.latency_ms,
                answer.source,
                "Confidence is below min_confidence.",
            )
        route = self._routes[answer.value]
        return RouteSelection(
            answer.value,
            route.target,
            DecisionStatus.RESOLVED,
            answer.confidence,
            answer.latency_ms,
            answer.source,
            answer.reason,
        )

    def _fallback_or_empty(
        self,
        status: DecisionStatus,
        confidence: float,
        latency_ms: float,
        source: str,
        reason: str,
    ) -> RouteSelection[TTarget]:
        if self._fallback_key is not None:
            route = self._routes[self._fallback_key]
            return RouteSelection(
                self._fallback_key,
                route.target,
                status,
                confidence,
                latency_ms,
                "configured_fallback",
                reason,
            )
        return RouteSelection(None, None, status, confidence, latency_ms, source, reason)
