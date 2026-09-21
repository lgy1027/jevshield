import os
import time
import atexit
import asyncio
from typing import Dict, Any, Optional
import httpx

from .models import GuardContext, Policy
from .rules import DANGEROUS_STEMS as _DANGEROUS_STEMS, fast_deny_reason
from .redaction import build_evaluation_state

try:
    from importlib.metadata import version as _pkg_version
    _USER_AGENT = f"jevshield/{_pkg_version('jevshield')}"
except Exception:
    _USER_AGENT = "jevshield/0.1.1"

# 429/529 的退避窗口：牺牲至多 0.25s，仍在 2s timeout 预算内
_RETRY_STATUSES = (429, 529)
_RETRY_BACKOFF = 0.25
# retry-after 头允许的最大等待，防止网关给出超大值击穿延迟预算
_RETRY_BACKOFF_MAX = 2.0


def _retry_after_seconds(resp: httpx.Response) -> float:
    """解析 429/529 响应的 retry-after 头（数值型秒数）。

    与官方 SDK 行为对齐：遵循网关给出的等待时间；缺失、非法或过大时
    回退到固定退避窗口。
    """
    raw = resp.headers.get("retry-after")
    if raw:
        try:
            return min(max(float(raw), 0.0), _RETRY_BACKOFF_MAX)
        except (TypeError, ValueError):
            pass
    return _RETRY_BACKOFF

# ---------------------------------------------------------------------------
# 后端注册表：TypeSafe 官方直连与 OpenRouter System One 端点
# 参见 docs.typesafe.ai/api、openrouter.ai/docs/guides/community/typesafe-sdk
# 与 openrouter.ai/typesafe/jev-1.13
# ---------------------------------------------------------------------------
BACKENDS = {
    "typesafe": {
        "base_url": "https://api.typesafe.ai/v1/systemone",
        "default_model": "jev-latest",
        "env_keys": ("JEV_API_KEY", "TYPESAFE_API_KEY"),
    },
    # OpenRouter 官方 System One 端点（openrouter.ai/docs/guides/community/typesafe-sdk）
    # 与官方协议同构，响应额外携带 id/provider/usage.cost；另有 alpha 端点 /api/alpha/decisions
    "openrouter": {
        "base_url": "https://openrouter.ai/api/v1/systemone",
        "default_model": "typesafe/jev-1.13",
        "env_keys": ("OPENROUTER_API_KEY", "JEV_API_KEY"),
    },
}
DEFAULT_BACKEND = "typesafe"


class JevClient:
    # Compatibility alias; authoritative Fast-Deny rules live in rules.py.
    DANGEROUS_STEMS = _DANGEROUS_STEMS

    def __init__(
        self,
        api_key: Optional[str] = None,
        base_url: Optional[str] = None,
        model: Optional[str] = None,
        backend: Optional[str] = None,
        timeout: float = 2.0
    ):
        # 后端解析：显式参数 > JEV_BACKEND 环境变量 > 自动探测
        if backend is None:
            backend = os.getenv("JEV_BACKEND")
        if backend is None:
            has_typesafe_key = bool(os.getenv("JEV_API_KEY") or os.getenv("TYPESAFE_API_KEY"))
            has_openrouter_key = bool(os.getenv("OPENROUTER_API_KEY"))
            backend = DEFAULT_BACKEND if (has_typesafe_key or not has_openrouter_key) else "openrouter"
        if backend not in BACKENDS:
            raise ValueError(f"Unknown backend {backend!r}. Supported: {list(BACKENDS)}")
        self.backend = backend
        profile = BACKENDS[backend]

        if api_key is None:
            for env_name in profile["env_keys"]:
                api_key = os.getenv(env_name)
                if api_key:
                    break
        self.api_key = api_key

        self.base_url = (base_url or os.getenv("JEV_BASE_URL") or profile["base_url"]).rstrip("/")
        if model is None:
            model = os.getenv("JEV_MODEL") or profile["default_model"]
        self.model = model
        self.timeout = timeout
        self.is_mock_mode = not bool(self.api_key)

        # Persistent Connection Pool to preserve sub-100ms budget
        self._http_client = httpx.Client(
            timeout=self.timeout,
            limits=httpx.Limits(max_keepalive_connections=20, max_connections=50)
        )
        self._async_http_client: Optional[httpx.AsyncClient] = None
        atexit.register(self.close)

    def close(self):
        """Cleanup persistent transport connections."""
        if hasattr(self, "_http_client") and not self._http_client.is_closed:
            self._http_client.close()

    async def aclose(self):
        """Cleanup async persistent transport connections."""
        if self._async_http_client and not self._async_http_client.is_closed:
            await self._async_http_client.aclose()

    def _get_async_client(self) -> httpx.AsyncClient:
        if self._async_http_client is None or self._async_http_client.is_closed:
            self._async_http_client = httpx.AsyncClient(
                timeout=self.timeout,
                limits=httpx.Limits(max_keepalive_connections=20, max_connections=50)
            )
        return self._async_http_client

    def _prune_state(self, tool_name: str, docstring: str, args_repr: str, max_chars: int = 800) -> str:
        """Build canonical state for callers of the legacy private helper."""
        return build_evaluation_state(
            GuardContext(tool_name, docstring, {"args_repr": args_repr[:max_chars]})
        )

    def _build_payload(self, state: str) -> Dict[str, Any]:
        """严格按照 TypeSafe 官方 Schema 构造三原语（docs.typesafe.ai/api）。"""
        return {
            "model": self.model,
            "state": state,
            "questions": {
                # 原语 1: Choice —— criteria 为「选项 -> 描述」映射
                "risk_level": {
                    "type": "choice",
                    "instructions": "Assess the operational risk tier of executing this tool call.",
                    "criteria": {
                        "safe": "Read-only or fully reversible routine operation.",
                        "medium_risk": "Modifies state but is recoverable; no data loss or credential exposure.",
                        "critical_danger": "Irreversibly deletes data, terminates key processes, or leaks credentials."
                    }
                },
                # 原语 2: Noul —— instructions 承载待验证陈述，返回单个 noul 概率
                "is_destructive": {
                    "type": "noul",
                    "instructions": "This action permanently deletes resources, formats data, terminates key processes, or exposes credentials.",
                    "criteria": {
                        "true": "The action causes permanent data loss, system termination, or credential exposure.",
                        "false": "The action is fully reversible or read-only."
                    }
                },
                # 原语 3: Score —— criteria 为有序档位描述数组（2~10 档），返回 0..n-1 加权位置
                "blast_radius": {
                    "type": "score",
                    "instructions": "Rate the blast radius/severity of potential failure.",
                    "criteria": [
                        "Trivial or read-only, no side effects.",
                        "Minor local impact, easily reversed.",
                        "Moderate impact, recoverable from backups or restart.",
                        "Major data loss or prolonged service disruption.",
                        "Catastrophic irreversible damage across systems."
                    ]
                }
            }
        }

    def _extract_answers(self, data: Any) -> Dict[str, Any]:
        """提取 answers 映射；兼容早期网关包装的 results/questions。"""
        if not isinstance(data, dict):
            return {}
        return data.get("answers") or data.get("results") or data.get("questions") or {}

    def _headers(self) -> Dict[str, str]:
        return {
            "Authorization": f"Bearer {self.api_key}",
            "Content-Type": "application/json",
            "User-Agent": _USER_AGENT
        }

    def evaluate(self, tool_name: str, docstring: str, args_repr: str) -> Dict[str, Any]:
        """Compatibility wrapper for the legacy string-based evaluation API."""
        return self.evaluate_context(
            GuardContext(tool_name, docstring, {"args_repr": args_repr}), None
        )

    def evaluate_context(
        self, context: GuardContext, policy: Optional[Policy]
    ) -> Dict[str, Any]:
        """Evaluate a structured context using redacted canonical state."""
        del policy
        state = build_evaluation_state(context)
        if self.is_mock_mode:
            return self._heuristic_fallback(
                context.tool_name, str(context.args), "Local Mock Mode (No API Key)"
            )

        payload = self._build_payload(state)
        try:
            resp = self._http_client.post(self.base_url, headers=self._headers(), json=payload)
            # 限流/过载按官方建议退避重试一次（遵循 retry-after 头），避免直接静默降级到启发式
            if resp.status_code in _RETRY_STATUSES:
                time.sleep(_retry_after_seconds(resp))
                resp = self._http_client.post(self.base_url, headers=self._headers(), json=payload)
            if resp.status_code == 200:
                answers = self._extract_answers(resp.json())
                if answers:
                    return answers
                return self._heuristic_fallback(
                    context.tool_name, str(context.args), "Empty Answers Fallback"
                )
        except Exception as e:
            return self._heuristic_fallback(
                context.tool_name, str(context.args),
                f"Gateway Fallback ({type(e).__name__})"
            )

        return self._heuristic_fallback(
            context.tool_name, str(context.args), "Gateway Non-200 Fallback"
        )

    async def aevaluate(self, tool_name: str, docstring: str, args_repr: str) -> Dict[str, Any]:
        """Compatibility wrapper for the legacy async string-based evaluation API."""
        return await self.aevaluate_context(
            GuardContext(tool_name, docstring, {"args_repr": args_repr}), None
        )

    async def aevaluate_context(
        self, context: GuardContext, policy: Optional[Policy]
    ) -> Dict[str, Any]:
        """Asynchronously evaluate a structured context using canonical state."""
        del policy
        state = build_evaluation_state(context)
        if self.is_mock_mode:
            return self._heuristic_fallback(
                context.tool_name, str(context.args), "Local Mock Mode (No API Key)"
            )

        payload = self._build_payload(state)
        client = self._get_async_client()
        try:
            resp = await client.post(self.base_url, headers=self._headers(), json=payload)
            if resp.status_code in _RETRY_STATUSES:
                await asyncio.sleep(_retry_after_seconds(resp))
                resp = await client.post(self.base_url, headers=self._headers(), json=payload)
            if resp.status_code == 200:
                answers = self._extract_answers(resp.json())
                if answers:
                    return answers
                return self._heuristic_fallback(
                    context.tool_name, str(context.args), "Empty Answers Fallback"
                )
        except Exception as e:
            return self._heuristic_fallback(
                context.tool_name, str(context.args),
                f"Gateway Async Fallback ({type(e).__name__})"
            )

        return self._heuristic_fallback(
            context.tool_name, str(context.args), "Gateway Non-200 Fallback"
        )

    def _heuristic_fallback(self, tool_name: str, args_repr: str, reason: str) -> Dict[str, Any]:
        """本地启发式兜底：零依赖离线可用；返回与官方一致的 answers 结构。"""
        combined = f"{tool_name} {args_repr}".lower()
        is_danger = bool(fast_deny_reason(tool_name, combined))

        return {
            "risk_level": {
                "type": "choice",
                "choice": "critical_danger" if is_danger else "safe",
                "selected": "critical_danger" if is_danger else "safe",  # 向后兼容旧解析
                "confidence": 0.99 if is_danger else 0.85,
                "probabilities": {"safe": 0.01 if is_danger else 0.85, "critical_danger": 0.99 if is_danger else 0.05, "medium_risk": 0.10}
            },
            "is_destructive": {
                "type": "noul",
                "noul": 0.99 if is_danger else 0.01,
                "p_true": 0.99 if is_danger else 0.01  # 向后兼容旧解析
            },
            "blast_radius": {
                "type": "score",
                "score": 4.0 if is_danger else 0.0,
                "confidence": 0.90
            },
            "_meta": {"fallback": True, "reason": reason}
        }
