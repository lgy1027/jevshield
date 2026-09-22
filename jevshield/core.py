import asyncio
import inspect
import queue
import sys
import threading
import time
from typing import Any, Dict, Optional, Protocol, Tuple, Union

from .audit import AuditEvent, AuditSink, NullAuditSink
from .exceptions import (
    EvaluatorError,
    EvaluatorTimeout,
    MalformedEvaluationError,
    SecurityViolationError,
)
from .models import Action, Evaluation, GuardContext, GuardDecision, Policy
from .redaction import redact_for_audit

RISK_TIERS = {
    "safe": 1,
    "medium_risk": 2,
    "critical_danger": 3
}

# Score 原语返回 0..n-1 的档位加权位置（5 档 -> 0..4）
BLAST_MAX = 4.0
# 「影响面达到次高档位及以上」的阻断线
BLAST_BLOCK_THRESHOLD = 3.0
MAX_ASK_TIMEOUT = 30.0


class Confirmer(Protocol):
    """Bounded synchronous confirmation contract."""

    def confirm(self, decision: GuardDecision, timeout: float) -> bool:
        """Return ``True`` only when the redacted decision is approved."""


class AsyncConfirmer(Protocol):
    """Bounded asynchronous confirmation contract."""

    async def confirm(self, decision: GuardDecision, timeout: float) -> bool:
        """Return ``True`` only when the redacted decision is approved."""


class CLIConfirmer:
    """Interactive terminal confirmer for the policy-based guard path."""

    def confirm(self, decision: GuardDecision, timeout: float) -> bool:
        evaluation = decision.evaluation
        print(
            "[JevShield] Confirmation required for "
            f"'{decision.context.tool_name}' "
            f"(risk={evaluation.risk_level}, "
            f"irreversibility={evaluation.irreversibility:.1%})."
        )
        bounded_timeout = _bounded_ask_timeout(timeout)
        if bounded_timeout <= 0.0:
            return False
        deadline = time.monotonic() + bounded_timeout
        result_queue = queue.Queue(maxsize=1)

        def read_choice() -> None:
            try:
                choice = input(
                    "Authorize this execution? "
                    "(Enter 'y' to approve, any other key to abort): "
                )
                approved = choice.strip().lower() == "y"
            except BaseException:
                approved = False
            result_queue.put((approved, time.monotonic()))

        threading.Thread(target=read_choice, daemon=True).start()
        remaining = deadline - time.monotonic()
        if remaining <= 0.0:
            return False
        try:
            approved, completed_at = result_queue.get(timeout=remaining)
        except queue.Empty:
            return False
        return approved is True and completed_at < deadline


def _safe_float(value: Any, default: float = 0.0) -> float:
    try:
        return float(value)
    except (TypeError, ValueError):
        return default


def _redacted_context(context: GuardContext) -> GuardContext:
    """Return the audit-safe context retained on a decision."""

    return GuardContext(
        tool_name=redact_for_audit(context.tool_name),
        tool_description=redact_for_audit(context.tool_description),
        args=redact_for_audit(context.args),
        environment=redact_for_audit(context.environment),
        actor_id=redact_for_audit(context.actor_id),
        resource_scope=redact_for_audit(context.resource_scope),
        intent=redact_for_audit(context.intent),
    )


def _redacted_decision(decision: GuardDecision) -> GuardDecision:
    """Return a decision safe to pass to confirmers, audits, and exceptions."""

    evaluation = decision.evaluation
    safe_decision = GuardDecision(
        action=decision.action,
        context=_redacted_context(decision.context),
        evaluation=Evaluation(
            risk_level=redact_for_audit(evaluation.risk_level),
            # Evaluation values may originate in untrusted gateway output.  Do
            # not retain scalar subclasses: their __str__/__repr__ can carry
            # secrets into audit, confirmer, or exception boundaries.
            irreversibility=_safe_float(evaluation.irreversibility),
            blast_radius=_safe_float(evaluation.blast_radius),
            confidence=_safe_float(evaluation.confidence),
            source=redact_for_audit(evaluation.source),
            latency_ms=_safe_float(evaluation.latency_ms),
        ),
        policy_name=redact_for_audit(decision.policy_name),
        network_called=decision.network_called,
        redacted_arguments=redact_for_audit(decision.context.args),
    )
    return safe_decision


def _bounded_ask_timeout(timeout: float) -> float:
    try:
        value = float(timeout)
    except (TypeError, ValueError):
        return 0.0
    return min(MAX_ASK_TIMEOUT, max(0.0, value))


def _stdin_is_interactive() -> bool:
    """Return whether stdin can safely support an interactive confirmation."""

    stdin = sys.stdin
    if stdin is None:
        return False
    try:
        return bool(stdin.isatty())
    except Exception:
        return False


def _audit(
    audit_sink: Optional[AuditSink], outcome: str, decision: GuardDecision
) -> None:
    sink = audit_sink if audit_sink is not None else NullAuditSink()
    failed = False
    try:
        sink.emit(AuditEvent.from_decision(decision, outcome))
    except Exception:
        failed = True
    if failed:
        raise _security_violation(decision, "Audit sink failed closed.") from None


def _security_violation(
    decision: GuardDecision, reason: str
) -> SecurityViolationError:
    evaluation = decision.evaluation
    return SecurityViolationError(
        tool_name=decision.context.tool_name,
        risk_level=evaluation.risk_level,
        reason=reason,
        p_destructive=evaluation.irreversibility,
        decision=decision,
    )


def _denial(
    decision: GuardDecision, reason: str, audit_sink: Optional[AuditSink], outcome: str
) -> SecurityViolationError:
    _audit(audit_sink, outcome, decision)
    return _security_violation(decision, reason)


def _run_confirmer(
    confirmer: Confirmer,
    decision: GuardDecision,
    timeout: float,
    *,
    deadline: Optional[float] = None,
) -> Tuple[str, bool]:
    """Run a synchronous confirmer without allowing it to block enforcement."""

    if timeout <= 0.0:
        return "timeout", False
    result_queue = queue.Queue(maxsize=1)
    deadline = time.monotonic() + timeout if deadline is None else deadline

    def invoke() -> None:
        try:
            result = confirmer.confirm(decision, timeout)
        except Exception:
            result_queue.put(("error", False, time.monotonic()))
        else:
            result_queue.put(("result", result is True, time.monotonic()))

    threading.Thread(target=invoke, daemon=True).start()
    remaining = deadline - time.monotonic()
    if remaining <= 0.0:
        return "timeout", False
    try:
        state, approved, completed_at = result_queue.get(timeout=remaining)
    except queue.Empty:
        return "timeout", False
    if completed_at >= deadline:
        return "timeout", False
    return state, approved


def _consume_task_result(task: "asyncio.Task[Any]") -> None:
    """Retrieve a detached confirmer result without allowing it to affect policy."""

    try:
        task.exception()
    except BaseException:
        pass


async def _run_async_confirmer(
    confirmer: AsyncConfirmer, decision: GuardDecision, timeout: float
) -> Tuple[str, bool]:
    """Race confirmation against an irrevocable deadline."""

    if timeout <= 0.0:
        return "timeout", False
    loop = asyncio.get_running_loop()
    deadline = loop.time() + timeout
    confirmation_task = asyncio.create_task(confirmer.confirm(decision, timeout))
    deadline_task = asyncio.create_task(asyncio.sleep(timeout))
    done, _ = await asyncio.wait(
        {confirmation_task, deadline_task},
        return_when=asyncio.FIRST_COMPLETED,
    )
    if deadline_task in done or loop.time() >= deadline:
        deadline_task.cancel()
        if confirmation_task.done():
            _consume_task_result(confirmation_task)
        else:
            confirmation_task.cancel()
            confirmation_task.add_done_callback(_consume_task_result)
        return "timeout", False

    deadline_task.cancel()
    try:
        result = confirmation_task.result()
    except BaseException:
        return "error", False
    return "result", result is True


def _failure_evaluation(error: EvaluatorError) -> Evaluation:
    if isinstance(error, EvaluatorTimeout):
        source = "evaluator_timeout"
    elif isinstance(error, MalformedEvaluationError):
        source = "malformed_evaluation"
    else:
        source = "evaluator_error"
    return Evaluation(
        risk_level="critical_danger",
        irreversibility=1.0,
        blast_radius=BLAST_MAX,
        confidence=1.0,
        source=source,
    )


def decide(
    context: GuardContext,
    evaluation: Union[Evaluation, EvaluatorError],
    policy: Policy,
) -> GuardDecision:
    """Map structured signals to an action without performing I/O."""

    network_called = True
    if isinstance(evaluation, EvaluatorError):
        network_called = evaluation.network_called
        evaluation = _failure_evaluation(evaluation)
        action = Action.DENY
    else:
        network_called = evaluation.source not in {
            "heuristic",
            "local_rule",
            "local_rule_error",
        }
        risk_tier = RISK_TIERS.get(evaluation.risk_level)
        threshold_tier = RISK_TIERS.get(policy.risk_threshold, 3)
        irreversible = _safe_float(evaluation.irreversibility)
        blast_radius = _safe_float(evaluation.blast_radius, BLAST_MAX)
        blocked = (
            risk_tier is None
            or (risk_tier >= threshold_tier and irreversible > 0.75)
            or (blast_radius >= BLAST_BLOCK_THRESHOLD and irreversible > 0.5)
        )
        low_confidence = (
            policy.min_confidence > 0.0
            and _safe_float(evaluation.confidence, -1.0) < policy.min_confidence
        )
        if blocked:
            action = Action.DENY
        elif low_confidence:
            action = Action.ASK
        else:
            action = Action.ALLOW

    safe_context = _redacted_context(context)
    return GuardDecision(
        action=action,
        context=safe_context,
        evaluation=evaluation,
        policy_name=policy.name,
        network_called=network_called,
        redacted_arguments=redact_for_audit(context.args),
    )


def _deny_reason(decision: GuardDecision) -> str:
    reasons = {
        "local_rule": "Blocked by local rule.",
        "local_rule_error": "Blocked after local rule failure.",
        "evaluator_timeout": "Blocked after evaluator timeout.",
        "malformed_evaluation": "Blocked after malformed evaluator response.",
        "evaluator_error": "Blocked after evaluator failure.",
    }
    return reasons.get(
        decision.evaluation.source, "Blocked automatically by policy."
    )


def enforce(
    decision: GuardDecision,
    confirmer: Optional[Confirmer] = None,
    audit_sink: Optional[AuditSink] = None,
    ask_timeout: float = MAX_ASK_TIMEOUT,
) -> None:
    """Enforce a decision with bounded confirmation and one terminal audit event."""

    safe_decision = _redacted_decision(decision)
    if safe_decision.action == Action.ALLOW:
        _audit(audit_sink, "allow", safe_decision)
        return
    if safe_decision.action == Action.DENY:
        raise _denial(
            safe_decision,
            _deny_reason(safe_decision),
            audit_sink,
            "deny",
        )

    active_confirmer = confirmer
    if active_confirmer is None and _stdin_is_interactive():
        active_confirmer = CLIConfirmer()
    if active_confirmer is None:
        raise _denial(
            safe_decision,
            "Confirmation required but no interactive terminal or confirmer is available.",
            audit_sink,
            "ask-rejection",
        )

    timeout = _bounded_ask_timeout(ask_timeout)
    state, approved = _run_confirmer(active_confirmer, safe_decision, timeout)
    if approved:
        _audit(audit_sink, "ask-approval", safe_decision)
        return
    if state == "timeout":
        reason = "Confirmation timed out."
    elif state == "error":
        reason = "Confirmation failed closed."
    else:
        reason = "Confirmation was not approved."
    raise _denial(safe_decision, reason, audit_sink, "ask-rejection")

async def aenforce(
    decision: GuardDecision,
    confirmer: Optional[Union[Confirmer, AsyncConfirmer]] = None,
    audit_sink: Optional[AuditSink] = None,
    ask_timeout: float = MAX_ASK_TIMEOUT,
) -> None:
    """Asynchronously enforce a decision with a bounded confirmer."""

    safe_decision = _redacted_decision(decision)
    if safe_decision.action == Action.ALLOW:
        _audit(audit_sink, "allow", safe_decision)
        return
    if safe_decision.action == Action.DENY:
        raise _denial(
            safe_decision,
            _deny_reason(safe_decision),
            audit_sink,
            "deny",
        )

    active_confirmer = confirmer
    if active_confirmer is None and _stdin_is_interactive():
        active_confirmer = CLIConfirmer()
    if active_confirmer is None:
        raise _denial(
            safe_decision,
            "Confirmation required but no interactive terminal or confirmer is available.",
            audit_sink,
            "ask-rejection",
        )

    timeout = _bounded_ask_timeout(ask_timeout)
    state = "result"
    approved = False
    try:
        if inspect.iscoroutinefunction(active_confirmer.confirm):
            state, approved = await _run_async_confirmer(
                active_confirmer,
                safe_decision,
                timeout,
            )
        else:
            # The budget starts before queueing work in the executor.  Otherwise
            # a saturated executor can make an expired confirmation appear fresh.
            deadline = time.monotonic() + timeout
            remaining = max(0.0, deadline - time.monotonic())
            if remaining <= 0.0:
                state = "timeout"
            else:
                state, approved = await asyncio.wait_for(
                    asyncio.to_thread(
                        _run_confirmer,
                        active_confirmer,
                        safe_decision,
                        timeout,
                        deadline=deadline,
                    ),
                    timeout=remaining,
                )
    except asyncio.TimeoutError:
        state = "timeout"
    except Exception:
        state = "error"

    if approved:
        _audit(audit_sink, "ask-approval", safe_decision)
        return
    if state == "timeout":
        reason = "Confirmation timed out."
    elif state == "error":
        reason = "Confirmation failed closed."
    else:
        reason = "Confirmation was not approved."
    raise _denial(safe_decision, reason, audit_sink, "ask-rejection")
