"""jevshield 核心逻辑测试（stdlib unittest，零第三方依赖）。"""
import os
import unittest
from unittest import mock

from jevshield.client import JevClient, DEFAULT_BACKEND
from jevshield.core import enforce_policy, BLAST_MAX
from jevshield.exceptions import SecurityViolationError
from jevshield import Action, GuardContext, ProductionPolicy


def make_decision(risk="safe", conf=0.9, noul=0.01, blast=0.0):
    """构造与官方 answers 结构一致的决策字典。"""
    return {
        "risk_level": {"type": "choice", "choice": risk, "confidence": conf},
        "is_destructive": {"type": "noul", "noul": noul},
        "blast_radius": {"type": "score", "score": blast},
    }


def make_client(**kwargs):
    """构造一个强制 mock 模式、避免真实网络与环境变量干扰的客户端。"""
    return JevClient(api_key=None, backend="typesafe", **kwargs)


class TestPublicGuardModels(unittest.TestCase):
    def test_production_policy_defaults_to_deny_on_failures(self):
        policy = ProductionPolicy()
        self.assertEqual(policy.on_evaluator_error.value, "deny")
        self.assertEqual(policy.on_timeout.value, "deny")
        self.assertEqual(policy.ask_timeout, 30.0)

    def test_guard_context_keeps_optional_scope_metadata(self):
        context = GuardContext(
            "delete_db",
            "Deletes a database",
            {"name": "prod"},
            environment="production",
            resource_scope=("db:prod",),
        )
        self.assertEqual(context.environment, "production")
        self.assertEqual(context.resource_scope, ("db:prod",))


class TestEnforcePolicy(unittest.TestCase):
    def setUp(self):
        # enforce_policy 的 headless 判定依赖 isatty；测试中统一置为 False
        self.tty_patcher = mock.patch("sys.stdin.isatty", return_value=False)
        self.tty_patcher.start()
        self.addCleanup(self.tty_patcher.stop)

    def test_safe_decision_passes(self):
        enforce_policy("run", (), {}, make_decision(), interactive=False)

    def test_blocked_by_tier_and_probability(self):
        with self.assertRaises(SecurityViolationError):
            enforce_policy(
                "run", (), {},
                make_decision(risk="critical_danger", noul=0.99),
                interactive=False
            )

    def test_high_tier_low_probability_not_blocked(self):
        # P=0.5 不超过 0.75 线，单 tier 高不足以阻断
        enforce_policy(
            "run", (), {},
            make_decision(risk="critical_danger", noul=0.5),
            interactive=False
        )

    def test_blocked_by_blast_and_destructive(self):
        with self.assertRaises(SecurityViolationError):
            enforce_policy(
                "run", (), {},
                make_decision(risk="medium_risk", noul=0.9, blast=3.0),
                threshold="critical_danger",
                interactive=False
            )

    def test_blast_alone_without_destructive_passes(self):
        # blast 高但非 destructive（P=0.4）不触发第二条路径
        enforce_policy(
            "run", (), {},
            make_decision(risk="medium_risk", noul=0.4, blast=4.0),
            threshold="critical_danger",
            interactive=False
        )

    def test_unknown_risk_choice_fails_closed(self):
        decision = make_decision(risk="bogus_tier", noul=0.99)
        with self.assertRaises(SecurityViolationError):
            enforce_policy("run", (), {}, decision, interactive=False)

    def test_missing_risk_choice_fails_closed(self):
        decision = make_decision(noul=0.99)
        del decision["risk_level"]
        with self.assertRaises(SecurityViolationError):
            enforce_policy("run", (), {}, decision, interactive=False)

    def test_missing_blast_fails_closed(self):
        # blast 缺失按 BLAST_MAX 处理，destructive 时触发阻断
        decision = make_decision(risk="medium_risk", noul=0.9)
        del decision["blast_radius"]
        with self.assertRaises(SecurityViolationError):
            enforce_policy(
                "run", (), {}, decision,
                threshold="critical_danger", interactive=False
            )

    def test_min_confidence_blocks_low_conf_in_headless(self):
        with self.assertRaises(SecurityViolationError) as ctx:
            enforce_policy(
                "run", (), {},
                make_decision(conf=0.3),
                interactive=False, min_confidence=0.6
            )
        self.assertIn("confidence", ctx.exception.reason.lower())

    def test_min_confidence_missing_conf_fails_closed(self):
        decision = make_decision()
        del decision["risk_level"]["confidence"]
        with self.assertRaises(SecurityViolationError):
            enforce_policy(
                "run", (), {}, decision,
                interactive=False, min_confidence=0.6
            )

    def test_min_confidence_disabled_by_default(self):
        # 默认 min_confidence=0 时低置信度不影响放行
        enforce_policy(
            "run", (), {},
            make_decision(conf=0.1),
            interactive=False
        )

    def test_min_confidence_high_conf_passes(self):
        enforce_policy(
            "run", (), {},
            make_decision(conf=0.95),
            interactive=False, min_confidence=0.6
        )


class TestHeuristicFallback(unittest.TestCase):
    def test_dangerous_pattern_critical(self):
        client = make_client()
        out = client._heuristic_fallback("run_cmd", "rm -rf /etc/kubernetes", "test")
        self.assertEqual(out["risk_level"]["choice"], "critical_danger")
        self.assertEqual(out["is_destructive"]["noul"], 0.99)
        self.assertEqual(out["blast_radius"]["score"], BLAST_MAX)
        self.assertTrue(out["_meta"]["fallback"])

    def test_dangerous_stem_critical(self):
        client = make_client()
        out = client._heuristic_fallback("delete_records", "id=42", "test")
        self.assertEqual(out["risk_level"]["choice"], "critical_danger")

    def test_safe_call_safe(self):
        client = make_client()
        out = client._heuristic_fallback("list_files", "path=/var/log", "test")
        self.assertEqual(out["risk_level"]["choice"], "safe")
        self.assertEqual(out["is_destructive"]["noul"], 0.01)
        self.assertEqual(out["blast_radius"]["score"], 0.0)


class TestPayloadAndState(unittest.TestCase):
    def test_build_payload_three_primitives(self):
        client = make_client()
        payload = client._build_payload("some state")
        self.assertEqual(payload["model"], client.model)
        self.assertEqual(payload["state"], "some state")
        questions = payload["questions"]
        self.assertEqual(questions["risk_level"]["type"], "choice")
        self.assertEqual(questions["is_destructive"]["type"], "noul")
        self.assertEqual(questions["blast_radius"]["type"], "score")
        self.assertEqual(len(questions["blast_radius"]["criteria"]), 5)

    def test_prune_state_injection_framing(self):
        client = make_client()
        state = client._prune_state("my_tool", "Does things.\nMore details.", "arg1")
        self.assertIn("security gate", state)
        self.assertIn("not instructions", state)
        self.assertIn("Tool: my_tool", state)
        self.assertIn("Doc: Does things.", state)
        self.assertNotIn("More details", state)  # docstring 只取首行

    def test_prune_state_truncates_args(self):
        client = make_client()
        state = client._prune_state("t", "doc", "x" * 2000)
        self.assertLessEqual(len(state.split("Args: ")[1]), 800)


class FakeResponse:
    def __init__(self, status_code, json_data=None, headers=None):
        self.status_code = status_code
        self._json_data = json_data or {}
        # 用真实 httpx.Headers 以验证大小写不敏感解析
        import httpx
        self.headers = httpx.Headers(headers or {})

    def json(self):
        return self._json_data


class TestRetryAndFallback(unittest.TestCase):
    def _client_with_post(self, responses):
        client = make_client()
        client.is_mock_mode = False
        client.api_key = "test-key"
        client._http_client = mock.Mock()
        client._http_client.post.side_effect = responses
        return client

    def test_429_then_success_retries(self):
        client = self._client_with_post([
            FakeResponse(429),
            FakeResponse(200, {"answers": {"risk_level": {"choice": "safe"}}}),
        ])
        with mock.patch("jevshield.client.time.sleep") as sleep_mock:
            out = client.evaluate("t", "doc", "args")
        self.assertEqual(sleep_mock.call_count, 1)
        self.assertEqual(out["risk_level"]["choice"], "safe")
        self.assertEqual(client._http_client.post.call_count, 2)

    def test_retry_after_header_is_honored(self):
        client = self._client_with_post([
            FakeResponse(429, headers={"Retry-After": "1.5"}),
            FakeResponse(200, {"answers": {"risk_level": {"choice": "safe"}}}),
        ])
        with mock.patch("jevshield.client.time.sleep") as sleep_mock:
            client.evaluate("t", "doc", "args")
        sleep_mock.assert_called_once_with(1.5)

    def test_retry_after_header_is_clamped(self):
        # 超大 retry-after 封顶在 2s，保护延迟预算
        client = self._client_with_post([
            FakeResponse(429, headers={"retry-after": "30"}),
            FakeResponse(200, {"answers": {"risk_level": {"choice": "safe"}}}),
        ])
        with mock.patch("jevshield.client.time.sleep") as sleep_mock:
            client.evaluate("t", "doc", "args")
        sleep_mock.assert_called_once_with(2.0)

    def test_retry_after_invalid_falls_back(self):
        client = self._client_with_post([
            FakeResponse(429, headers={"retry-after": "not-a-number"}),
            FakeResponse(200, {"answers": {"risk_level": {"choice": "safe"}}}),
        ])
        with mock.patch("jevshield.client.time.sleep") as sleep_mock:
            client.evaluate("t", "doc", "args")
        from jevshield.client import _RETRY_BACKOFF
        sleep_mock.assert_called_once_with(_RETRY_BACKOFF)

    def test_529_persist_falls_back(self):
        client = self._client_with_post([FakeResponse(529), FakeResponse(529)])
        with mock.patch("jevshield.client.time.sleep"):
            out = client.evaluate("run_cmd", "doc", "rm -rf /")
        self.assertTrue(out["_meta"]["fallback"])
        self.assertEqual(client._http_client.post.call_count, 2)

    def test_non_200_no_retry(self):
        client = self._client_with_post([FakeResponse(500)])
        out = client.evaluate("t", "doc", "args")
        self.assertTrue(out["_meta"]["fallback"])
        self.assertEqual(client._http_client.post.call_count, 1)

    def test_empty_answers_falls_back(self):
        client = self._client_with_post([FakeResponse(200, {"answers": {}})])
        out = client.evaluate("t", "doc", "args")
        self.assertTrue(out["_meta"]["fallback"])


class TestBackendResolution(unittest.TestCase):
    def test_explicit_backend_wins(self):
        with mock.patch.dict(os.environ, {"JEV_BACKEND": "openrouter"}, clear=True):
            client = JevClient(api_key="k", backend="typesafe")
        self.assertEqual(client.backend, "typesafe")

    def test_env_backend(self):
        with mock.patch.dict(os.environ, {"JEV_BACKEND": "openrouter"}, clear=True):
            client = JevClient(api_key="k")
        self.assertEqual(client.backend, "openrouter")

    def test_autodetect_openrouter_only(self):
        with mock.patch.dict(os.environ, {"OPENROUTER_API_KEY": "sk-or-v1-x"}, clear=True):
            client = JevClient()
        self.assertEqual(client.backend, "openrouter")

    def test_autodetect_default_typesafe(self):
        with mock.patch.dict(os.environ, {}, clear=True):
            client = JevClient()
        self.assertEqual(client.backend, DEFAULT_BACKEND)


class TestLangChainIntegration(unittest.TestCase):
    """验证 guard_langchain_tool 修补后门禁能拿到真实工具名与描述。"""
    @classmethod
    def setUpClass(cls):
        try:
            from langchain_core.tools import tool as tool_decorator
        except ImportError:
            raise unittest.SkipTest("langchain-core not installed")
        # 注意不能存为类属性：函数是 descriptor，经实例访问会被绑定 self
        cls._tool_decorator = staticmethod(tool_decorator)

    def setUp(self):
        self.tty_patcher = mock.patch("sys.stdin.isatty", return_value=False)
        self.tty_patcher.start()
        self.addCleanup(self.tty_patcher.stop)

    def _make_tool(self):
        @self._tool_decorator()
        def delete_s3_bucket(bucket_name: str, force: bool = False):
            """Permanently deletes an Amazon S3 storage bucket and all its contents."""
            return f"Bucket {bucket_name} dropped."

        return delete_s3_bucket

    def test_wrapper_preserves_tool_identity(self):
        from jevshield import guard_langchain_tool
        tool = self._make_tool()
        guarded = guard_langchain_tool(tool, interactive=False)
        self.assertEqual(guarded._run.__name__, "delete_s3_bucket")
        self.assertIn("S3", guarded._run.__doc__)

    def test_destructive_langchain_tool_blocked(self):
        from jevshield import guard_langchain_tool, SecurityViolationError
        guarded = guard_langchain_tool(self._make_tool(), interactive=False)
        with self.assertRaises(SecurityViolationError):
            guarded.invoke({"bucket_name": "prod-customer-backups", "force": True})

    def test_safe_langchain_tool_passes(self):
        from jevshield import guard_langchain_tool

        @self._tool_decorator()
        def list_files(path: str):
            """Lists files within a specified local filesystem directory."""
            return f"Files at {path}: ['app.py']"

        guarded = guard_langchain_tool(list_files, interactive=False)
        result = guarded.invoke({"path": "/var/log"})
        self.assertIn("/var/log", result)


if __name__ == "__main__":
    unittest.main()
