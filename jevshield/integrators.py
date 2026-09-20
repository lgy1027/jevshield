import functools
from typing import Any
from .decorators import guard


def guard_langchain_tool(
    tool: Any,
    risk_threshold: str = "critical_danger",
    interactive: bool = True,
    min_confidence: float = 0.0
):
    """
    Patches both sync (_run) and async (_arun) invocations of a LangChain BaseTool.

    必须先以 functools.wraps 暴露原始函数的完整签名（含 config / run_manager 等
    keyword-only 参数），否则 LangChain 运行时会按包装后的 (*args, **kwargs) 签名
    注入回调参数，导致底层 _run 缺失必需的 config 参数。
    """
    original_run = tool._run
    original_arun = getattr(tool, "_arun", None)

    def run_impl(*args, **kwargs):
        return original_run(*args, **kwargs)

    # 暴露原始签名，再套门控；guard 的 functools.wraps 会继续传递 __wrapped__ 链，
    # LangChain 的 inspect.signature 解析因此能看到原始参数列表
    run_impl = functools.wraps(original_run)(run_impl)
    # functools.wraps 会把 __name__/__doc__ 也替换成 _run 的通用元数据，
    # 导致门禁拿到 Tool=_run + 通用 docstring，丢失真实工具名与描述；这里覆盖回来
    run_impl.__name__ = getattr(tool, "name", tool.__class__.__name__)
    run_impl.__doc__ = getattr(tool, "description", None)
    tool._run = guard(
        risk_threshold=risk_threshold,
        interactive=interactive,
        min_confidence=min_confidence
    )(run_impl)

    if original_arun is not None:
        async def arun_impl(*args, **kwargs):
            return await original_arun(*args, **kwargs)

        arun_impl = functools.wraps(original_arun)(arun_impl)
        arun_impl.__name__ = getattr(tool, "name", tool.__class__.__name__)
        arun_impl.__doc__ = getattr(tool, "description", None)
        tool._arun = guard(
            risk_threshold=risk_threshold,
            interactive=interactive,
            min_confidence=min_confidence
        )(arun_impl)

    return tool
