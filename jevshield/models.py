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
class GuardContextMetadata:
    """Trusted host metadata that may be added to a guard invocation.

    Invocation identity remains owned by ``GuardContext``.  This separate type
    deliberately has no tool or argument fields, so a context provider cannot
    substitute a different tool call while supplying the host's objective.
    """

    intent: Optional[str] = None
    environment: Optional[str] = None
    actor_id: Optional[str] = None
    resource_scope: Tuple[str, ...] = ()

    def __post_init__(self) -> None:
        for field_name in ("intent", "environment", "actor_id"):
            value = getattr(self, field_name)
            if value is not None and type(value) is not str:
                raise TypeError("{} must be a string or None.".format(field_name))
        if type(self.resource_scope) is not tuple:
            raise TypeError("resource_scope must be a tuple of strings.")
        if any(type(value) is not str for value in self.resource_scope):
            raise TypeError("resource_scope must be a tuple of strings.")


def merge_context_metadata(
    context: GuardContext, metadata: GuardContextMetadata
) -> GuardContext:
    """Add trusted metadata without changing an observed invocation.

    Metadata is authoritative for the optional context fields.  In particular,
    a missing trusted intent clears any value that might have arrived with
    untrusted invocation data, allowing the intent gate to skip safely.
    """

    if not isinstance(context, GuardContext):
        raise TypeError("context must be a GuardContext.")
    if not isinstance(metadata, GuardContextMetadata):
        raise TypeError("metadata must be a GuardContextMetadata.")
    return GuardContext(
        tool_name=context.tool_name,
        tool_description=context.tool_description,
        args=context.args,
        environment=metadata.environment,
        actor_id=metadata.actor_id,
        resource_scope=metadata.resource_scope,
        intent=metadata.intent,
    )


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
