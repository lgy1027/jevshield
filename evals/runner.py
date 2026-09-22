"""Credential and safe-report primitives for local Jev evaluations."""

from dataclasses import dataclass
from datetime import datetime, timezone
from enum import Enum
import json
import os
from pathlib import Path
from typing import Any, Iterable, Mapping, Optional, Tuple, Union

from jevshield import DecisionStatus, IntentClassifier, Route, Router

from .loader import EvalCase


_SUPPORTED_SUITES = frozenset(("classify", "route", "all"))


class MissingCredentialError(RuntimeError):
    """Raised when a local evaluation has no Jev credential available."""


@dataclass(frozen=True)
class EvalCaseResult:
    """The non-sensitive outcome of one evaluation case."""

    id: str
    expected: str
    predicted: Optional[str]
    status: str
    confidence: Optional[float]
    latency_ms: Optional[float]
    passed: bool

    def to_dict(self):
        """Return the explicit safe schema used in persisted reports."""
        return {
            "id": self.id,
            "expected": self.expected,
            "predicted": self.predicted,
            "status": self.status,
            "confidence": self.confidence,
            "latency_ms": self.latency_ms,
            "passed": self.passed,
        }


@dataclass(frozen=True)
class EvalReport:
    """Immutable aggregate metrics and safe per-case outcomes."""

    suite: str
    model: str
    total: int
    passed: int
    incorrect: int
    uncertain: int
    unavailable: int
    cases: Tuple[EvalCaseResult, ...]

    def to_dict(self):
        """Return a report payload that cannot contain source case data."""
        return {
            "suite": self.suite,
            "model": self.model,
            "total": self.total,
            "passed": self.passed,
            "incorrect": self.incorrect,
            "uncertain": self.uncertain,
            "unavailable": self.unavailable,
            "cases": [case.to_dict() for case in self.cases],
        }


def load_api_key(project_root: Union[str, Path]) -> str:
    """Load ``JEV_API_KEY`` from the environment, then project ``.env``.

    Values are intentionally neither logged nor included in exception messages.
    """
    environment_key = os.environ.get("JEV_API_KEY")
    if environment_key:
        return environment_key

    dotenv_path = Path(project_root) / ".env"
    if dotenv_path.is_file():
        dotenv_key = _load_dotenv_key(dotenv_path)
        if dotenv_key:
            return dotenv_key

    raise MissingCredentialError(
        "JEV_API_KEY is required. Set it in the environment or project-root .env file."
    )


def _load_dotenv_key(path: Path) -> Optional[str]:
    for raw_line in path.read_text(encoding="utf-8").splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        if line.startswith("export "):
            line = line[len("export "):].lstrip()
        if "=" not in line:
            continue
        name, raw_value = line.split("=", 1)
        if name.strip() != "JEV_API_KEY":
            continue
        return _parse_dotenv_value(raw_value)
    return None


def _parse_dotenv_value(raw_value: str) -> str:
    value = raw_value.strip()
    if not value:
        return ""
    if value[0] in ("'", '"'):
        quote = value[0]
        closing_index = value.find(quote, 1)
        if closing_index != -1:
            return value[1:closing_index]
    return value.split("#", 1)[0].rstrip()


def aggregate_report(
    suite: str, model: str, case_results: Iterable[EvalCaseResult]
) -> EvalReport:
    """Aggregate immutable results without retaining inputs or raw responses."""
    cases = tuple(case_results)
    return EvalReport(
        suite=suite,
        model=model,
        total=len(cases),
        passed=sum(case.passed for case in cases),
        incorrect=sum(case.status == "resolved" and not case.passed for case in cases),
        uncertain=sum(case.status == "uncertain" for case in cases),
        unavailable=sum(case.status == "unavailable" for case in cases),
        cases=cases,
    )


def write_report(report: EvalReport, report_dir: Union[str, Path]) -> Path:
    """Write one timestamped, redacted JSON report and return its path."""
    if report.suite not in _SUPPORTED_SUITES:
        raise ValueError("Unsupported suite: {}".format(report.suite))
    destination = Path(report_dir)
    destination.mkdir(parents=True, exist_ok=True)
    timestamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S%fZ")
    report_path = destination / "{}-{}.json".format(report.suite, timestamp)
    report_path.write_text(
        json.dumps(report.to_dict(), ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )
    return report_path


def run_classify_suite(
    cases: Iterable[EvalCase],
    client: Any,
    *,
    model: str,
    min_confidence: float = 0.0,
) -> EvalReport:
    """Evaluate cases through the public :class:`IntentClassifier` API."""
    results = []
    for case in cases:
        intent_type, descriptions = _intent_type_for(case.candidates)
        result = IntentClassifier(
            intent_type, descriptions, client, min_confidence=min_confidence
        ).classify(case.input)
        predicted = result.value.value if result.value is not None else None
        results.append(
            EvalCaseResult(
                id=case.id,
                expected=case.expected,
                predicted=predicted,
                status=result.status.value,
                confidence=result.confidence,
                latency_ms=result.latency_ms,
                passed=(
                    result.status is DecisionStatus.RESOLVED
                    and predicted == case.expected
                ),
            )
        )
    return aggregate_report("classify", model, results)


def run_route_suite(
    cases: Iterable[EvalCase],
    client: Any,
    *,
    model: str,
    min_confidence: float = 0.0,
) -> EvalReport:
    """Evaluate cases through the public :class:`Router` API."""
    results = []
    for case in cases:
        routes = {
            key: Route(description=description, target=key)
            for key, description in case.candidates.items()
        }
        result = Router(routes, client, min_confidence=min_confidence).select(case.input)
        results.append(
            EvalCaseResult(
                id=case.id,
                expected=case.expected,
                predicted=result.route_key,
                status=result.status.value,
                confidence=result.confidence,
                latency_ms=result.latency_ms,
                passed=(
                    result.status is DecisionStatus.RESOLVED
                    and result.route_key == case.expected
                ),
            )
        )
    return aggregate_report("route", model, results)


def _intent_type_for(candidates: Mapping[str, str]):
    """Create an enum and descriptions accepted by ``IntentClassifier``."""
    intent_type = Enum(
        "EvaluationIntent",
        {
            "candidate_{}".format(index): candidate
            for index, candidate in enumerate(candidates)
        },
    )
    descriptions = {
        member: candidates[member.value]
        for member in intent_type
    }
    return intent_type, descriptions
