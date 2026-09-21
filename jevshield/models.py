"""Public data models for JevShield guard decisions."""

from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Mapping, Optional, Tuple


class Action(str, Enum):
    """The deterministic outcome of a guard evaluation."""

    ALLOW = "allow"
    ASK = "ask"
    DENY = "deny"


class FailureMode(str, Enum):
    """How a policy handles an evaluator or local-rule failure."""

    DENY = "deny"
    HEURISTIC = "heuristic"


@dataclass(frozen=True)
class GuardContext:
    """The invocation metadata evaluated by a guard."""

    tool_name: str
    tool_description: str
    args: Mapping[str, Any]
    environment: Optional[str] = None
    actor_id: Optional[str] = None
    resource_scope: Tuple[str, ...] = ()
    intent: Optional[str] = None


@dataclass(frozen=True)
class Evaluation:
    """Structured risk signals returned by an evaluator or local rule."""

    risk_level: str = "unknown"
    irreversibility: float = 0.0
    blast_radius: float = 0.0
    confidence: float = 0.0
    source: str = "unknown"
    latency_ms: float = 0.0


@dataclass(frozen=True)
class GuardDecision:
    """A policy decision with the data needed for enforcement and audit."""

    action: Action
    context: GuardContext
    evaluation: Evaluation
    policy_name: str
    network_called: bool = False
    redacted_arguments: Mapping[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class Policy:
    """Configuration for deterministic guard policy evaluation."""

    name: str = "development"
    risk_threshold: str = "critical_danger"
    min_confidence: float = 0.0
    on_local_rule_error: FailureMode = FailureMode.HEURISTIC
    on_evaluator_error: FailureMode = FailureMode.HEURISTIC
    on_timeout: FailureMode = FailureMode.HEURISTIC
    ask_timeout: float = 30.0


def DevelopmentPolicy() -> Policy:
    """Return the permissive development policy with heuristic fallback."""

    return Policy(name="development")


def StagingPolicy() -> Policy:
    """Return the staging policy."""

    return Policy(name="staging")


def ProductionPolicy() -> Policy:
    """Return the fail-closed production policy."""

    return Policy(
        name="production",
        on_local_rule_error=FailureMode.DENY,
        on_evaluator_error=FailureMode.DENY,
        on_timeout=FailureMode.DENY,
    )
