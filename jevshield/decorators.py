import functools
import inspect
from typing import Any, Callable, Mapping, Optional, Union
from .audit import AuditSink
from .client import JevClient
from .core import AsyncConfirmer, Confirmer, aenforce, decide, enforce, enforce_policy
from .exceptions import EvaluatorError, SecurityViolationError
from .models import Evaluation, FailureMode, GuardContext, Policy
from .rules import LocalRuleEngine, RuleOutcome, RuleResult

_global_client: Optional[JevClient] = None

def get_client() -> JevClient:
    global _global_client
    if _global_client is None:
        _global_client = JevClient()
    return _global_client

def guard(
    risk_threshold: str = "critical_danger",
    interactive: bool = True,
    client: Optional[JevClient] = None,
    min_confidence: float = 0.0,
    policy: Optional[Policy] = None,
    confirmer: Optional[Union[Confirmer, AsyncConfirmer]] = None,
    audit_sink: Optional[AuditSink] = None,
):
    """
    为任何 Python 函数或 Agent 工具注入毫秒级 Jev 门禁。

    :param risk_threshold: 触发门禁的风险阈值 ('medium_risk' | 'critical_danger')
    :param interactive: 触发阻断时是否在终端等待人工确认
    :param client: 可选注入定制客户端
    :param min_confidence: 模型校准置信度下限；低于该值（或缺失）时即使未命中阻断
        条件也升级为人工确认，0 表示关闭（默认）
    """
    def decorator(func: Callable):
        tool_name = func.__name__
        docstring = inspect.getdoc(func) or ""
        rule_engine = LocalRuleEngine()

        def context_for(args: tuple, kwargs: Mapping[str, Any]) -> GuardContext:
            return GuardContext(tool_name, docstring, {"args": args, "kwargs": kwargs})

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
            if policy is None:
                return
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
                confirmer=confirmer,
                audit_sink=audit_sink,
                ask_timeout=policy.ask_timeout,
            )

        async def async_policy_decision(context: GuardContext, evaluation) -> None:
            decision = decide(context, evaluation, policy)
            await aenforce(
                decision,
                confirmer=confirmer,
                audit_sink=audit_sink,
                ask_timeout=policy.ask_timeout,
            )

        if inspect.iscoroutinefunction(func):
            @functools.wraps(func)
            async def async_wrapper(*args, **kwargs):
                args_repr = f"args={args}, kwargs={kwargs}"
                context = context_for(args, kwargs)
                evaluate_rules(context)
                active_client = client or get_client()

                # 毫秒级 Jev 并行评估
                if policy is None:
                    decision = await active_client.aevaluate(tool_name, docstring, args_repr)
                else:
                    try:
                        evaluation = await active_client.aevaluate_context(context, policy)
                    except EvaluatorError as error:
                        evaluation = error
                    await async_policy_decision(context, evaluation)
                    return await func(*args, **kwargs)

                # 策略裁决
                enforce_policy(
                    tool_name=tool_name,
                    args=args,
                    kwargs=kwargs,
                    decision=decision,
                    threshold=risk_threshold,
                    interactive=interactive,
                    min_confidence=min_confidence
                )

                # 安全放行
                return await func(*args, **kwargs)
            return async_wrapper

        @functools.wraps(func)
        def wrapper(*args, **kwargs):
            args_repr = f"args={args}, kwargs={kwargs}"
            context = context_for(args, kwargs)
            evaluate_rules(context)
            active_client = client or get_client()

            # 毫秒级 Jev 并行评估
            if policy is None:
                decision = active_client.evaluate(tool_name, docstring, args_repr)
            else:
                try:
                    evaluation = active_client.evaluate_context(context, policy)
                except EvaluatorError as error:
                    evaluation = error
                policy_decision(context, evaluation)
                return func(*args, **kwargs)

            # 策略裁决
            enforce_policy(
                tool_name=tool_name,
                args=args,
                kwargs=kwargs,
                decision=decision,
                threshold=risk_threshold,
                interactive=interactive,
                min_confidence=min_confidence
            )

            # 安全放行
            return func(*args, **kwargs)

        return wrapper
    return decorator
