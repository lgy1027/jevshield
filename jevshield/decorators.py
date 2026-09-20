import functools
import inspect
from typing import Callable, Optional
from .client import JevClient
from .core import enforce_policy

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
    min_confidence: float = 0.0
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

        if inspect.iscoroutinefunction(func):
            @functools.wraps(func)
            async def async_wrapper(*args, **kwargs):
                active_client = client or get_client()
                args_repr = f"args={args}, kwargs={kwargs}"

                # 毫秒级 Jev 并行评估
                decision = await active_client.aevaluate(tool_name, docstring, args_repr)

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
            active_client = client or get_client()
            args_repr = f"args={args}, kwargs={kwargs}"

            # 毫秒级 Jev 并行评估
            decision = active_client.evaluate(tool_name, docstring, args_repr)

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
