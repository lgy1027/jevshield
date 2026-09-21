import sys
from typing import Any, Dict, Optional, Tuple, Union

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


def _safe_float(value: Any, default: float = 0.0) -> float:
    try:
        return float(value)
    except (TypeError, ValueError):
        return default


def _redacted_context(context: GuardContext) -> GuardContext:
    """Return the audit-safe context retained on a decision."""

    return GuardContext(
        tool_name=context.tool_name,
        tool_description=redact_for_audit(context.tool_description),
        args=redact_for_audit(context.args),
        environment=redact_for_audit(context.environment),
        actor_id=redact_for_audit(context.actor_id),
        resource_scope=redact_for_audit(context.resource_scope),
        intent=redact_for_audit(context.intent),
    )


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


def enforce(decision: GuardDecision, confirmer=None) -> None:
    """Enforce a completed decision; confirmation is implemented in Task 5."""

    del confirmer
    if decision.action != Action.DENY:
        return

    reasons = {
        "local_rule": "Blocked by local rule.",
        "local_rule_error": "Blocked after local rule failure.",
        "evaluator_timeout": "Blocked after evaluator timeout.",
        "malformed_evaluation": "Blocked after malformed evaluator response.",
        "evaluator_error": "Blocked after evaluator failure.",
    }
    evaluation = decision.evaluation
    raise SecurityViolationError(
        tool_name=decision.context.tool_name,
        risk_level=evaluation.risk_level,
        reason=reasons.get(evaluation.source, "Blocked automatically by policy."),
        p_destructive=evaluation.irreversibility,
        decision=decision,
    )


def enforce_policy(
    tool_name: str,
    args: Tuple[Any, ...],
    kwargs: Dict[str, Any],
    decision: Dict[str, Any],
    threshold: str = "critical_danger",
    interactive: bool = True,
    min_confidence: float = 0.0
) -> None:
    risk_info = decision.get("risk_level", {})
    # 官方字段为 choice；兼容早期网关的 selected/value；缺失视为畸形响应，按 critical_danger 处理（fail-closed）
    risk_choice = risk_info.get("choice") or risk_info.get("selected") or risk_info.get("value") or "critical_danger"
    conf_raw = risk_info.get("confidence")
    risk_conf = _safe_float(conf_raw, 1.0)
    # confidence 缺失视为「未知置信度」，启用 min_confidence 时同样升级为人工确认（fail-closed）
    has_conf = conf_raw is not None

    destruct_info = decision.get("is_destructive", {})
    # 官方 Noul 仅返回单个 noul 概率（0-1），无独立布尔与置信度；兼容旧的 value/p_true
    if "noul" in destruct_info:
        p_destructive = _safe_float(destruct_info.get("noul"))
    elif "p_true" in destruct_info:
        p_destructive = _safe_float(destruct_info.get("p_true"))
    else:
        p_destructive = 1.0 if destruct_info.get("value") else 0.0
    is_destructive = p_destructive > 0.5

    blast_info = decision.get("blast_radius", {})
    # score 缺失视为网关畸形响应，按最高影响面处理（fail-closed）
    blast_score = _safe_float(blast_info.get("score", BLAST_MAX), BLAST_MAX)

    meta = decision.get("_meta", {})

    # 官方保证选项封闭；未知值视为网关畸形响应，按 critical_danger 处理（fail-closed）
    if risk_choice not in RISK_TIERS:
        risk_choice = "critical_danger"
    current_tier = RISK_TIERS.get(risk_choice, 3)
    threshold_tier = RISK_TIERS.get(threshold, 3)

    # 2D cross-validation: Tier threshold + Irreversibility probability
    is_blocked = (
        (current_tier >= threshold_tier and p_destructive > 0.75)
        or (blast_score >= BLAST_BLOCK_THRESHOLD and is_destructive)
    )

    # 低置信度升级：模型校准置信度低于阈值（或缺失）时，不信任「安全」裁决，强制走人工确认
    low_conf = min_confidence > 0.0 and (not has_conf or risk_conf < min_confidence)

    if not is_blocked and not low_conf:
        return

    if is_blocked:
        fallback_hint = f" [Engine: {meta['reason']}]" if "fallback" in meta else " [Engine: Jev System-1]"
        print("\n" + "!" * 64)
        print(f"🚨 [JevShield Policy Violation]{fallback_hint}")
        print(f"• Tool Target    : {tool_name}")
        print(f"• Assessed Risk  : {risk_choice.upper()} (Confidence: {risk_conf:.1%})")
        print(f"• Destructive    : {'YES' if is_destructive else 'NO'} (P_irreversible: {p_destructive:.1%})")
        print(f"• Blast Radius   : {blast_score:.1f} / {BLAST_MAX:.0f}")
        print(f"• Invoc Arguments: args={args}, kwargs={kwargs}")
        print("!" * 64)
    else:
        print(f"⚠️ [JevShield] Low model confidence ({risk_conf:.1%} < {min_confidence:.1%}); "
              f"escalating '{tool_name}' to operator confirmation.")

    # Headless / Docker CI Check
    can_interact = interactive and sys.stdin.isatty()

    if can_interact:
        try:
            choice = input("👉 Authorize this execution? (Enter 'y' to approve, any other key to abort): ").strip().lower()
            if choice == "y":
                print("[JevShield] Authorized manually by operator.\n")
                return
            raise SecurityViolationError(
                tool_name=tool_name,
                risk_level=risk_choice,
                reason="Explicitly rejected by operator via interactive terminal.",
                p_destructive=p_destructive
            )
        except (EOFError, KeyboardInterrupt):
            raise SecurityViolationError(
                tool_name=tool_name,
                risk_level=risk_choice,
                reason="Terminal session interrupted during confirmation.",
                p_destructive=p_destructive
            )
    elif is_blocked:
        raise SecurityViolationError(
            tool_name=tool_name,
            risk_level=risk_choice,
            reason=f"Blocked automatically by policy (P_destruct: {p_destructive:.1%}, Blast: {blast_score:.1f}/{BLAST_MAX:.0f}, Interactive: {can_interact}).",
            p_destructive=p_destructive
        )
    else:
        raise SecurityViolationError(
            tool_name=tool_name,
            risk_level=risk_choice,
            reason=f"Low model confidence ({risk_conf:.1%} < {min_confidence:.1%}) and no interactive terminal to confirm; fail-closed.",
            p_destructive=p_destructive
        )
