import sys
from typing import Dict, Any, Tuple, Optional
from .exceptions import SecurityViolationError

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
        print(f"🚨 [Jev-Guard Policy Violation]{fallback_hint}")
        print(f"• Tool Target    : {tool_name}")
        print(f"• Assessed Risk  : {risk_choice.upper()} (Confidence: {risk_conf:.1%})")
        print(f"• Destructive    : {'YES' if is_destructive else 'NO'} (P_irreversible: {p_destructive:.1%})")
        print(f"• Blast Radius   : {blast_score:.1f} / {BLAST_MAX:.0f}")
        print(f"• Invoc Arguments: args={args}, kwargs={kwargs}")
        print("!" * 64)
    else:
        print(f"⚠️ [Jev-Guard] Low model confidence ({risk_conf:.1%} < {min_confidence:.1%}); "
              f"escalating '{tool_name}' to operator confirmation.")

    # Headless / Docker CI Check
    can_interact = interactive and sys.stdin.isatty()

    if can_interact:
        try:
            choice = input("👉 Authorize this execution? (Enter 'y' to approve, any other key to abort): ").strip().lower()
            if choice == "y":
                print("[Jev-Guard] Authorized manually by operator.\n")
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
