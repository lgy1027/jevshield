class JevGuardError(Exception):
    """Base exception for all JevShield runtime exceptions."""
    pass


class EvaluatorError(JevGuardError):
    """Raised when the remote evaluator cannot produce a result."""

    def __init__(self, message: str, *, network_called: bool = True):
        self.network_called = network_called
        super().__init__(message)


class EvaluatorTimeout(EvaluatorError):
    """Raised when the remote evaluator exceeds its timeout."""


class MalformedEvaluationError(EvaluatorError):
    """Raised when evaluator output does not satisfy the response contract."""


class SecurityViolationError(JevGuardError):
    """Raised when an action violates security policy and is denied execution."""
    def __init__(
        self,
        tool_name: str,
        risk_level: str,
        reason: str,
        p_destructive: float = 0.0,
        decision=None,
    ):
        self.tool_name = tool_name
        self.risk_level = risk_level
        self.reason = reason
        self.p_destructive = p_destructive
        self.decision = decision
        super().__init__(f"[{tool_name}] Blocked ({risk_level}): {reason}")
