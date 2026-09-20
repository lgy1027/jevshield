class JevGuardError(Exception):
    """Base exception for all JevShield runtime exceptions."""
    pass


class SecurityViolationError(JevGuardError):
    """Raised when an action violates security policy and is denied execution."""
    def __init__(self, tool_name: str, risk_level: str, reason: str, p_destructive: float = 0.0):
        self.tool_name = tool_name
        self.risk_level = risk_level
        self.reason = reason
        self.p_destructive = p_destructive
        super().__init__(f"[{tool_name}] Blocked ({risk_level}): {reason}")
