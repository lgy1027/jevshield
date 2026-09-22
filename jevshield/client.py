import os
import re
import time
import atexit
import asyncio
import math
from typing import Dict, Any, Optional
import httpx

from .exceptions import EvaluatorError, EvaluatorTimeout, MalformedEvaluationError
from .models import Evaluation, FailureMode, GuardContext, Policy
from .redaction import build_evaluation_state
from .runtime import ChoiceAnswer, ChoiceQuestion, DecisionStatus

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
DEFAULT_TIMEOUT_SECONDS = 2.0


def _resolve_timeout(timeout: Optional[float]) -> float:
    """Resolve the explicit or environment-configured request timeout."""

    raw_timeout: Any = timeout
    if raw_timeout is None:
        raw_timeout = os.getenv("JEV_TIMEOUT_SECONDS", DEFAULT_TIMEOUT_SECONDS)
    try:
        resolved = float(raw_timeout)
    except (TypeError, ValueError) as error:
        raise ValueError("Jev timeout must be a positive number of seconds.") from error
    if not math.isfinite(resolved) or resolved <= 0.0:
        raise ValueError("Jev timeout must be a positive finite number of seconds.")
    return resolved


class JevClient:
    # 工具名中的高危词干（按 _ 与非单词字符切分），覆盖 delete_x / drop_x / wipe_x 等命名习惯
    DANGEROUS_STEMS = {
        "rm", "delete", "remove", "drop", "truncate", "wipe", "destroy",
        "purge", "kill", "terminate", "format", "erase", "shutdown", "revoke",
    }

    def __init__(
        self,
        api_key: Optional[str] = None,
        base_url: Optional[str] = None,
        model: Optional[str] = None,
        backend: Optional[str] = None,
        timeout: Optional[float] = None,
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
        self.timeout = _resolve_timeout(timeout)
        self.is_mock_mode = not bool(self.api_key)

        # Persistent connection pooling avoids repeated TCP/TLS setup.
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

    def _build_choice_payload(
        self, state: str, question: ChoiceQuestion
    ) -> Dict[str, Any]:
        return {
            "model": self.model,
            "state": state,
            "questions": {
                question.name: {
                    "type": "choice",
                    "instructions": question.instructions,
                    "criteria": dict(question.criteria),
                }
            },
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

    def _post_payload(self, payload: Dict[str, Any]):
        resp = self._http_client.post(
            self.base_url, headers=self._headers(), json=payload
        )
        if resp.status_code in _RETRY_STATUSES:
            time.sleep(_retry_after_seconds(resp))
            resp = self._http_client.post(
                self.base_url, headers=self._headers(), json=payload
            )
        return resp

    async def _apost_payload(self, payload: Dict[str, Any]):
        client = self._get_async_client()
        resp = await client.post(
            self.base_url, headers=self._headers(), json=payload
        )
        if resp.status_code in _RETRY_STATUSES:
            await asyncio.sleep(_retry_after_seconds(resp))
            resp = await client.post(
                self.base_url, headers=self._headers(), json=payload
            )
        return resp

    def evaluate(self, tool_name: str, docstring: str, args_repr: str) -> Dict[str, Any]:
        """Return the legacy raw answer mapping without strict normalization."""
        context = GuardContext(tool_name, docstring, {"args_repr": args_repr})
        if self.is_mock_mode:
            return self._legacy_fallback(
                tool_name, args_repr, "Local Mock Mode (No API Key)"
            )

        payload = self._build_payload(build_evaluation_state(context))
        try:
            resp = self._post_payload(payload)
            if resp.status_code == 200:
                answers = self._extract_answers(resp.json())
                if answers:
                    return answers
                return self._legacy_fallback(
                    tool_name, args_repr, "Empty Answers Fallback"
                )
        except Exception as error:
            return self._legacy_fallback(
                tool_name,
                args_repr,
                f"Gateway Fallback ({type(error).__name__})",
            )
        return self._legacy_fallback(
            tool_name, args_repr, "Gateway Non-200 Fallback"
        )

    def choose(self, state: str, question: ChoiceQuestion) -> ChoiceAnswer:
        if not isinstance(state, str) or not state:
            raise ValueError("Choice state must be a non-empty string.")
        if self.is_mock_mode:
            return ChoiceAnswer(
                None, 0.0, DecisionStatus.UNAVAILABLE, 0.0, "unconfigured",
                "No API key is configured.",
            )
        started = time.perf_counter()
        try:
            response = self._post_payload(self._build_choice_payload(state, question))
        except (httpx.TimeoutException, TimeoutError):
            return ChoiceAnswer(
                None, 0.0, DecisionStatus.UNAVAILABLE,
                (time.perf_counter() - started) * 1000.0, "timeout",
                "Evaluator timed out.",
            )
        except Exception as error:
            return ChoiceAnswer(
                None, 0.0, DecisionStatus.UNAVAILABLE,
                (time.perf_counter() - started) * 1000.0, "transport_error",
                type(error).__name__,
            )
        if response.status_code != 200:
            return ChoiceAnswer(
                None, 0.0, DecisionStatus.UNAVAILABLE,
                (time.perf_counter() - started) * 1000.0, "http_error",
                "HTTP {}".format(response.status_code),
            )
        try:
            return self._parse_choice_answer(
                self._extract_answers(response.json()), question,
                (time.perf_counter() - started) * 1000.0,
            )
        except Exception as error:
            return ChoiceAnswer(
                None, 0.0, DecisionStatus.UNAVAILABLE,
                (time.perf_counter() - started) * 1000.0, "invalid_response",
                type(error).__name__,
            )

    def evaluate_context(
        self, context: GuardContext, policy: Policy
    ) -> Evaluation:
        """Evaluate a structured context or raise a typed evaluator failure."""
        state = build_evaluation_state(context)
        if self.is_mock_mode:
            return self._resolve_failure(
                context,
                policy,
                EvaluatorError(
                    "Evaluator unavailable because no API key is configured.",
                    network_called=False,
                ),
            )

        payload = self._build_payload(state)
        started = time.perf_counter()
        try:
            resp = self._post_payload(payload)
        except (httpx.TimeoutException, TimeoutError) as error:
            return self._resolve_failure(
                context, policy, EvaluatorTimeout(type(error).__name__)
            )
        except Exception as error:
            return self._resolve_failure(
                context, policy, EvaluatorError(type(error).__name__)
            )

        if resp.status_code != 200:
            return self._resolve_failure(
                context,
                policy,
                EvaluatorError(f"Evaluator returned HTTP {resp.status_code}."),
            )

        try:
            answers = self._extract_answers(resp.json())
            evaluation = self._parse_evaluation(
                answers, latency_ms=(time.perf_counter() - started) * 1000.0
            )
        except MalformedEvaluationError as error:
            return self._resolve_failure(context, policy, error)
        except Exception as error:
            return self._resolve_failure(
                context,
                policy,
                MalformedEvaluationError(type(error).__name__),
            )
        return evaluation

    async def aevaluate(self, tool_name: str, docstring: str, args_repr: str) -> Dict[str, Any]:
        """Return the legacy raw answer mapping without strict normalization."""
        context = GuardContext(tool_name, docstring, {"args_repr": args_repr})
        if self.is_mock_mode:
            return self._legacy_fallback(
                tool_name, args_repr, "Local Mock Mode (No API Key)"
            )

        payload = self._build_payload(build_evaluation_state(context))
        try:
            resp = await self._apost_payload(payload)
            if resp.status_code == 200:
                answers = self._extract_answers(resp.json())
                if answers:
                    return answers
                return self._legacy_fallback(
                    tool_name, args_repr, "Empty Answers Fallback"
                )
        except Exception as error:
            return self._legacy_fallback(
                tool_name,
                args_repr,
                f"Gateway Async Fallback ({type(error).__name__})",
            )
        return self._legacy_fallback(
            tool_name, args_repr, "Gateway Non-200 Fallback"
        )

    async def achoose(self, state: str, question: ChoiceQuestion) -> ChoiceAnswer:
        if not isinstance(state, str) or not state:
            raise ValueError("Choice state must be a non-empty string.")
        if self.is_mock_mode:
            return ChoiceAnswer(
                None, 0.0, DecisionStatus.UNAVAILABLE, 0.0, "unconfigured",
                "No API key is configured.",
            )
        started = time.perf_counter()
        try:
            response = await self._apost_payload(
                self._build_choice_payload(state, question)
            )
        except (httpx.TimeoutException, TimeoutError):
            return ChoiceAnswer(
                None, 0.0, DecisionStatus.UNAVAILABLE,
                (time.perf_counter() - started) * 1000.0, "timeout",
                "Evaluator timed out.",
            )
        except Exception as error:
            return ChoiceAnswer(
                None, 0.0, DecisionStatus.UNAVAILABLE,
                (time.perf_counter() - started) * 1000.0, "transport_error",
                type(error).__name__,
            )
        if response.status_code != 200:
            return ChoiceAnswer(
                None, 0.0, DecisionStatus.UNAVAILABLE,
                (time.perf_counter() - started) * 1000.0, "http_error",
                "HTTP {}".format(response.status_code),
            )
        try:
            return self._parse_choice_answer(
                self._extract_answers(response.json()), question,
                (time.perf_counter() - started) * 1000.0,
            )
        except Exception as error:
            return ChoiceAnswer(
                None, 0.0, DecisionStatus.UNAVAILABLE,
                (time.perf_counter() - started) * 1000.0, "invalid_response",
                type(error).__name__,
            )

    async def aevaluate_context(
        self, context: GuardContext, policy: Policy
    ) -> Evaluation:
        """Asynchronously evaluate a context or raise a typed failure."""
        state = build_evaluation_state(context)
        if self.is_mock_mode:
            return self._resolve_failure(
                context,
                policy,
                EvaluatorError(
                    "Evaluator unavailable because no API key is configured.",
                    network_called=False,
                ),
            )

        payload = self._build_payload(state)
        started = time.perf_counter()
        try:
            resp = await self._apost_payload(payload)
        except (httpx.TimeoutException, TimeoutError) as error:
            return self._resolve_failure(
                context, policy, EvaluatorTimeout(type(error).__name__)
            )
        except Exception as error:
            return self._resolve_failure(
                context, policy, EvaluatorError(type(error).__name__)
            )

        if resp.status_code != 200:
            return self._resolve_failure(
                context,
                policy,
                EvaluatorError(f"Evaluator returned HTTP {resp.status_code}."),
            )

        try:
            answers = self._extract_answers(resp.json())
            evaluation = self._parse_evaluation(
                answers, latency_ms=(time.perf_counter() - started) * 1000.0
            )
        except MalformedEvaluationError as error:
            return self._resolve_failure(context, policy, error)
        except Exception as error:
            return self._resolve_failure(
                context,
                policy,
                MalformedEvaluationError(type(error).__name__),
            )
        return evaluation

    def _resolve_failure(
        self,
        context: GuardContext,
        policy: Policy,
        error: EvaluatorError,
    ) -> Evaluation:
        failure_mode = (
            policy.on_timeout
            if isinstance(error, EvaluatorTimeout)
            else policy.on_evaluator_error
        )
        if failure_mode == FailureMode.HEURISTIC:
            return self._heuristic_fallback(
                context.tool_name, str(context.args), type(error).__name__
            )
        raise error

    def _parse_evaluation(
        self, answers: Dict[str, Any], latency_ms: float
    ) -> Evaluation:
        if not isinstance(answers, dict) or not answers:
            raise MalformedEvaluationError("Evaluator returned empty answers.")

        risk_info = answers.get("risk_level")
        destructive_info = answers.get("is_destructive")
        blast_info = answers.get("blast_radius")
        if not all(isinstance(value, dict) for value in (
            risk_info, destructive_info, blast_info
        )):
            raise MalformedEvaluationError("Evaluator answer fields are missing.")

        risk_level = (
            risk_info.get("choice")
            or risk_info.get("selected")
            or risk_info.get("value")
        )
        if risk_level not in {"safe", "medium_risk", "critical_danger"}:
            raise MalformedEvaluationError("Evaluator returned an invalid risk level.")

        confidence = self._bounded_number(
            risk_info.get("confidence"), "risk confidence", 0.0, 1.0
        )
        if "noul" in destructive_info:
            irreversibility_raw = destructive_info.get("noul")
        elif "p_true" in destructive_info:
            irreversibility_raw = destructive_info.get("p_true")
        else:
            irreversibility_raw = destructive_info.get("value")
        irreversibility = self._bounded_number(
            irreversibility_raw, "irreversibility", 0.0, 1.0
        )
        blast_radius = self._bounded_number(
            blast_info.get("score"), "blast radius", 0.0, 4.0
        )
        return Evaluation(
            risk_level=risk_level,
            irreversibility=irreversibility,
            blast_radius=blast_radius,
            confidence=confidence,
            source="jev",
            latency_ms=max(latency_ms, 0.0),
        )

    def _parse_choice_answer(
        self, answers: Dict[str, Any], question: ChoiceQuestion, latency_ms: float
    ) -> ChoiceAnswer:
        unavailable = lambda reason: ChoiceAnswer(
            None, 0.0, DecisionStatus.UNAVAILABLE, max(latency_ms, 0.0),
            "invalid_response", reason,
        )
        if not isinstance(answers, dict):
            return unavailable("Evaluator returned invalid answers.")
        answer = answers.get(question.name)
        if not isinstance(answer, dict):
            return unavailable("Evaluator answer is missing.")
        try:
            confidence = self._bounded_number(
                answer.get("confidence"), "choice confidence", 0.0, 1.0
            )
        except MalformedEvaluationError:
            return unavailable("Evaluator returned an invalid choice confidence.")
        selected = (
            answer.get("choice")
            or answer.get("selected")
            or answer.get("value")
        )
        if not isinstance(selected, str):
            return unavailable("Evaluator returned an invalid choice.")
        if selected not in question.criteria:
            return ChoiceAnswer(
                None, confidence, DecisionStatus.UNCERTAIN,
                max(latency_ms, 0.0), "jev", "Evaluator selected an unknown choice.",
            )
        return ChoiceAnswer(
            selected, confidence, DecisionStatus.RESOLVED,
            max(latency_ms, 0.0), "jev",
        )

    @staticmethod
    def _bounded_number(
        value: Any, field_name: str, minimum: float, maximum: float
    ) -> float:
        if isinstance(value, bool):
            raise MalformedEvaluationError(
                f"Evaluator returned an invalid {field_name}."
            )
        try:
            number = float(value)
        except (TypeError, ValueError):
            raise MalformedEvaluationError(
                f"Evaluator returned an invalid {field_name}."
            )
        if not math.isfinite(number) or not minimum <= number <= maximum:
            raise MalformedEvaluationError(
                f"Evaluator returned an invalid {field_name}."
            )
        return number

    @staticmethod
    def _evaluation_to_answers(
        evaluation: Evaluation, fallback_reason: str = "Heuristic Fallback"
    ) -> Dict[str, Any]:
        answers = {
            "risk_level": {
                "type": "choice",
                "choice": evaluation.risk_level,
                "selected": evaluation.risk_level,
                "confidence": evaluation.confidence,
            },
            "is_destructive": {
                "type": "noul",
                "noul": evaluation.irreversibility,
                "p_true": evaluation.irreversibility,
            },
            "blast_radius": {
                "type": "score",
                "score": evaluation.blast_radius,
            },
        }
        if evaluation.source == "heuristic":
            answers["_meta"] = {"fallback": True, "reason": fallback_reason}
        return answers

    def _legacy_fallback(
        self, tool_name: str, args_repr: str, reason: str
    ) -> Dict[str, Any]:
        return self._evaluation_to_answers(
            self._heuristic_fallback(tool_name, args_repr, reason),
            fallback_reason=reason,
        )

    def _heuristic_fallback(
        self, tool_name: str, args_repr: str, reason: str
    ) -> Evaluation:
        """Return the explicit local heuristic fallback evaluation."""
        del reason
        combined = f"{tool_name} {args_repr}".lower()
        patterns = [
            r"rm\s+-rf", r"drop\s+table", r"drop\s+database", r"format\s+[a-z]:",
            r"truncate\s+table", r"kill\s+-9", r"chmod\s+777", r">\s*/dev/sd",
            r"delete\s+from\s+[a-z_0-9]+", r"aws\s+s3\s+rb\s+--force"
        ]
        stems = {s for s in re.split(r"[_\W]+", tool_name.lower()) if s}
        is_danger = bool(stems & self.DANGEROUS_STEMS) or any(
            re.search(pat, combined) for pat in patterns
        )

        return Evaluation(
            risk_level="critical_danger" if is_danger else "safe",
            irreversibility=0.99 if is_danger else 0.01,
            blast_radius=4.0 if is_danger else 0.0,
            confidence=0.99 if is_danger else 0.85,
            source="heuristic",
        )
