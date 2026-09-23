import functools
import inspect
from typing import Any, Callable, Mapping, Optional, Union
from .audit import AuditSink
from .client import JevClient
from .core import AsyncConfirmer, Confirmer, _redacted_context, aenforce, decide, enforce
from .exceptions import EvaluatorError, SecurityViolationError
from .intent import IntentAssessment, IntentPolicy, IntentStatus
from .models import (
    Evaluation, FailureMode, GuardContext, GuardContextMetadata, GuardDecision,
    Policy, merge_context_metadata,
)
from .redaction import redact_for_audit
from .rules import LocalRuleEngine, RuleOutcome, RuleResult

_global_client: Optional[JevClient] = None


def _provider_snapshot(value: Any, active_ids: set) -> Any:
    """Copy plain invocation data without invoking user-defined copy hooks."""

    value_type = type(value)
    if value_type in (type(None), bool, int, float, complex, str, bytes):
        return value
    if value_type not in (dict, list, tuple, set, frozenset, bytearray):
        raise TypeError("Context provider arguments must contain only plain data.")
    identity = id(value)
    if identity in active_ids:
        raise TypeError("Context provider arguments cannot contain cycles.")
    active_ids.add(identity)
    try:
        if value_type is dict:
            return {
                _provider_snapshot(key, active_ids): _provider_snapshot(item, active_ids)
                for key, item in value.items()
            }
        if value_type is list:
            return [_provider_snapshot(item, active_ids) for item in value]
        if value_type is tuple:
            return tuple(_provider_snapshot(item, active_ids) for item in value)
        if value_type is set:
            return {_provider_snapshot(item, active_ids) for item in value}
        if value_type is frozenset:
            return frozenset(_provider_snapshot(item, active_ids) for item in value)
        return bytearray(value)
    finally:
        active_ids.remove(identity)


def get_client() -> JevClient:
    global _global_client
    if _global_client is None:
        _global_client = JevClient()
    return _global_client


def guard(
    *,
    policy: Policy,
    client: Optional[JevClient] = None,
    confirmer: Optional[Union[Confirmer, AsyncConfirmer]] = None,
    audit_sink: Optional[AuditSink] = None,
    context_provider: Optional[Callable[[tuple, Mapping[str, Any]], GuardContextMetadata]] = None,
    intent_policy: Optional[IntentPolicy] = None,
):
    """
    为任何 Python 函数或 Agent 工具注入毫秒级 Jev 门禁。

    :param policy: Required policy used for deterministic evaluation and enforcement.
    :param client: 可选注入定制客户端
    """
    effective_confirmer = confirmer

    def decorator(func: Callable):
        tool_name = func.__name__
        docstring = inspect.getdoc(func) or ""
        rule_engine = LocalRuleEngine()

        def context_for(args: tuple, kwargs: Mapping[str, Any]) -> GuardContext:
            return GuardContext(tool_name, docstring, {"args": args, "kwargs": kwargs})

        def trusted_context_for(
            context: GuardContext, args: tuple, kwargs: Mapping[str, Any]
        ) -> GuardContext:
            if context_provider is None:
                return context
            provider_args, provider_kwargs = _provider_snapshot(
                (args, kwargs), set()
            )
            return merge_context_metadata(
                context, context_provider(provider_args, provider_kwargs)
            )

        def intent_decision(
            context: GuardContext, assessment: IntentAssessment
        ) -> GuardDecision:
            sources = {
                IntentStatus.MISMATCH: "intent_mismatch",
                IntentStatus.UNCERTAIN: "intent_uncertain",
                IntentStatus.UNAVAILABLE: "intent_unavailable",
            }
            safe_context = _redacted_context(context)
            return GuardDecision(
                action=assessment.action,
                context=safe_context,
                evaluation=Evaluation(source=sources[assessment.status]),
                policy_name=redact_for_audit(policy.name),
                network_called=False,
                redacted_arguments=safe_context.args,
            )

        def enforce_local_deny(context: GuardContext, result: RuleResult) -> None:
            evaluation = Evaluation(
                risk_level="critical_danger",
                irreversibility=0.99,
                blast_radius=4.0,
                confidence=1.0,
                source=(
                    "local_rule_error"
                    if result.outcome == RuleOutcome.ERROR
                    else "local_rule"
                ),
            )
            decision = decide(context, evaluation, policy)
            try:
                enforce(decision, audit_sink=audit_sink)
            except SecurityViolationError as error:
                error.rule_result = result
                raise

        def evaluate_rules(context: GuardContext) -> None:
            try:
                result = rule_engine.evaluate(context)
            except Exception as error:
                result = RuleResult(
                    RuleOutcome.ERROR,
                    "local rule engine error: " + type(error).__name__,
                )
            if result.outcome == RuleOutcome.DENY:
                enforce_local_deny(context, result)
            if result.outcome == RuleOutcome.ERROR and policy.on_local_rule_error == FailureMode.DENY:
                enforce_local_deny(context, result)

        def policy_decision(context: GuardContext, evaluation) -> None:
            decision = decide(context, evaluation, policy)
            enforce(
                decision,
                confirmer=effective_confirmer,
                audit_sink=audit_sink,
                ask_timeout=policy.ask_timeout,
            )

        async def async_policy_decision(context: GuardContext, evaluation) -> None:
            decision = decide(context, evaluation, policy)
            await aenforce(
                decision,
                confirmer=effective_confirmer,
                audit_sink=audit_sink,
                ask_timeout=policy.ask_timeout,
            )

        if inspect.iscoroutinefunction(func):
            @functools.wraps(func)
            async def async_wrapper(*args, **kwargs):
                context = context_for(args, kwargs)
                evaluate_rules(context)
                context = trusted_context_for(context, args, kwargs)
                if intent_policy is not None:
                    assessment = await intent_policy.aassess(context)
                    if assessment.action is not None:
                        await aenforce(
                            intent_decision(context, assessment),
                            confirmer=effective_confirmer,
                            audit_sink=audit_sink,
                            ask_timeout=policy.ask_timeout,
                        )
                active_client = client or get_client()

                try:
                    evaluation = await active_client.aevaluate_context(context, policy)
                except EvaluatorError as error:
                    evaluation = error
                await async_policy_decision(context, evaluation)
                return await func(*args, **kwargs)
            return async_wrapper

        @functools.wraps(func)
        def wrapper(*args, **kwargs):
            context = context_for(args, kwargs)
            evaluate_rules(context)
            context = trusted_context_for(context, args, kwargs)
            if intent_policy is not None:
                assessment = intent_policy.assess(context)
                if assessment.action is not None:
                    enforce(
                        intent_decision(context, assessment),
                        confirmer=effective_confirmer,
                        audit_sink=audit_sink,
                        ask_timeout=policy.ask_timeout,
                    )
            active_client = client or get_client()

            try:
                evaluation = active_client.evaluate_context(context, policy)
            except EvaluatorError as error:
                evaluation = error
            policy_decision(context, evaluation)
            return func(*args, **kwargs)

        return wrapper
    return decorator
