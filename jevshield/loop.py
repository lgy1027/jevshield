"""Local, framework-independent termination rules for agent loops."""

from dataclasses import dataclass
from enum import Enum
import math
from typing import Optional


class LoopAction(str, Enum):
    """The next action recommended after one completed agent iteration."""

    CONTINUE = "continue"
    ASK_FOR_HELP = "ask_for_help"
    STOP_SUCCESS = "stop_success"
    STOP_STALLED = "stop_stalled"


@dataclass(frozen=True)
class LoopPolicy:
    """Local limits for one agent loop; no model evaluation is performed."""

    max_iterations: int = 20
    max_repeated_tool_calls: int = 3
    max_stagnant_iterations: int = 3
    max_budget: Optional[float] = None
    stall_action: LoopAction = LoopAction.STOP_STALLED

    def __post_init__(self) -> None:
        for value in (
            self.max_iterations,
            self.max_repeated_tool_calls,
            self.max_stagnant_iterations,
        ):
            if not isinstance(value, int) or isinstance(value, bool) or value < 1:
                raise ValueError("Loop limits must be positive integers.")
        if self.max_budget is not None:
            if (
                isinstance(self.max_budget, bool)
                or not isinstance(self.max_budget, (int, float))
                or not math.isfinite(float(self.max_budget))
                or self.max_budget <= 0.0
            ):
                raise ValueError("max_budget must be a positive finite number.")
        if (
            not isinstance(self.stall_action, LoopAction)
            or self.stall_action not in {
                LoopAction.STOP_STALLED,
                LoopAction.ASK_FOR_HELP,
            }
        ):
            raise ValueError("stall_action must stop a stalled loop or ask for help.")


@dataclass(frozen=True)
class LoopStep:
    """A completed iteration represented only by safe, opaque identifiers."""

    tool_call_key: Optional[str] = None
    observation_key: Optional[str] = None
    spent_budget: Optional[float] = None
    goal_completed: bool = False

    def __post_init__(self) -> None:
        for key in (self.tool_call_key, self.observation_key):
            if key is not None and (not isinstance(key, str) or not key):
                raise ValueError("Loop keys must be non-empty opaque strings.")
        if not isinstance(self.goal_completed, bool):
            raise ValueError("goal_completed must be a boolean.")
        if self.spent_budget is not None:
            if (
                isinstance(self.spent_budget, bool)
                or not isinstance(self.spent_budget, (int, float))
                or not math.isfinite(float(self.spent_budget))
                or self.spent_budget < 0.0
            ):
                raise ValueError("spent_budget must be a non-negative finite number.")


@dataclass(frozen=True)
class LoopDecision:
    """A deterministic recommendation; the host remains responsible for action."""

    action: LoopAction
    reason: str
    iteration: int


class LoopTerminator:
    """Track one agent loop and stop deterministic retry patterns locally."""

    def __init__(self, policy: Optional[LoopPolicy] = None) -> None:
        self.policy = policy or LoopPolicy()
        self.reset()

    def reset(self) -> None:
        """Clear state before reusing this terminator for another agent run."""

        self._iterations = 0
        self._last_tool_call_key: Optional[str] = None
        self._repeated_tool_calls = 0
        self._last_observation_key: Optional[str] = None
        self._stagnant_iterations = 0
        self._spent_budget = 0.0
        self._terminal: Optional[LoopDecision] = None

    def observe(self, step: LoopStep) -> LoopDecision:
        """Record a completed step and return the next loop recommendation."""

        if self._terminal is not None:
            return self._terminal

        self._validate_budget(step.spent_budget)
        self._iterations += 1
        self._record_budget(step.spent_budget)
        if step.goal_completed:
            return self._stop(LoopAction.STOP_SUCCESS, "goal_completed")

        self._record_tool_call(step.tool_call_key)
        self._record_observation(step.observation_key)

        if (
            self.policy.max_budget is not None
            and self._spent_budget >= self.policy.max_budget
        ):
            return self._stop(LoopAction.STOP_STALLED, "budget_exhausted")
        if self._iterations >= self.policy.max_iterations:
            return self._stop(LoopAction.STOP_STALLED, "max_iterations")
        if self._repeated_tool_calls >= self.policy.max_repeated_tool_calls:
            return self._stop(LoopAction.STOP_STALLED, "repeated_tool_call")
        if self._stagnant_iterations >= self.policy.max_stagnant_iterations:
            return self._stop(self.policy.stall_action, "stagnant_observation")
        return LoopDecision(LoopAction.CONTINUE, "", self._iterations)

    def _record_budget(self, spent_budget: Optional[float]) -> None:
        if spent_budget is None:
            return
        self._spent_budget = float(spent_budget)

    def _validate_budget(self, spent_budget: Optional[float]) -> None:
        if spent_budget is not None and float(spent_budget) < self._spent_budget:
            raise ValueError("spent_budget must not decrease within one loop.")

    def _record_tool_call(self, key: Optional[str]) -> None:
        if key is None:
            self._last_tool_call_key = None
            self._repeated_tool_calls = 0
            return
        if key == self._last_tool_call_key:
            self._repeated_tool_calls += 1
        else:
            self._last_tool_call_key = key
            self._repeated_tool_calls = 1

    def _record_observation(self, key: Optional[str]) -> None:
        if key is None:
            self._last_observation_key = None
            self._stagnant_iterations = 0
            return
        if key == self._last_observation_key:
            self._stagnant_iterations += 1
        else:
            self._last_observation_key = key
            self._stagnant_iterations = 1

    def _stop(self, action: LoopAction, reason: str) -> LoopDecision:
        self._terminal = LoopDecision(action, reason, self._iterations)
        return self._terminal
