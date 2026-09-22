"""Manual, privacy-safe command line entry point for Jev evaluation suites."""

import argparse
import math
from pathlib import Path
import sys
from typing import Iterable, Optional

from jevshield import JevClient

from .loader import load_cases
from .runner import (
    EvalCaseResult,
    MissingCredentialError,
    aggregate_report,
    load_api_key,
    run_classify_suite,
    run_high_risk_route_suite,
    run_route_suite,
    run_security_holdout_route_suite,
    write_report,
)


_PROJECT_ROOT = Path(__file__).resolve().parents[1]
_DEFAULT_REPORT_DIR = _PROJECT_ROOT / "evals" / "reports"


def _confidence(value: str) -> float:
    try:
        confidence = float(value)
    except ValueError as error:
        raise argparse.ArgumentTypeError("must be a number between 0 and 1") from error
    if not math.isfinite(confidence) or not 0.0 <= confidence <= 1.0:
        raise argparse.ArgumentTypeError("must be a finite number between 0 and 1")
    return confidence


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Run checked-in Jev decision evaluations and write a redacted report."
    )
    parser.add_argument(
        "--suite",
        choices=("classify", "route", "route_high_risk", "route_security_holdout", "all"),
        required=True,
    )
    parser.add_argument("--report-dir", type=Path, default=_DEFAULT_REPORT_DIR)
    parser.add_argument("--min-confidence", type=_confidence, default=0.0)
    return parser


def _run_suite(name: str, client: JevClient, min_confidence: float):
    cases = load_cases(_PROJECT_ROOT / "evals" / "cases" / "{}.json".format(name))
    runner = {
        "classify": run_classify_suite,
        "route": run_route_suite,
        "route_high_risk": run_high_risk_route_suite,
        "route_security_holdout": run_security_holdout_route_suite,
    }[name]
    return runner(cases, client, model=client.model, min_confidence=min_confidence)


def _combined_report(reports: Iterable, model: str):
    case_results = []
    for report in reports:
        case_results.extend(report.cases)
    return aggregate_report("all", model, case_results)


def main(argv: Optional[list[str]] = None) -> int:
    """Run selected suites and return a process-safe status code."""
    arguments = _parser().parse_args(argv)
    try:
        api_key = load_api_key(_PROJECT_ROOT)
    except MissingCredentialError:
        print("error: Jev credential is not configured.", file=sys.stderr)
        return 2

    client = JevClient(api_key=api_key)
    try:
        suite_names = (
            ("classify", "route", "route_high_risk", "route_security_holdout")
            if arguments.suite == "all"
            else (arguments.suite,)
        )
        reports = [_run_suite(name, client, arguments.min_confidence) for name in suite_names]
        report = (
            _combined_report(reports, client.model)
            if arguments.suite == "all"
            else reports[0]
        )
        report_path = write_report(report, arguments.report_dir)
    finally:
        client.close()

    print(
        "total={} passed={} incorrect={} high_confidence_misses={} uncertain={} unavailable={}".format(
            report.total,
            report.passed,
            report.incorrect,
            report.high_confidence_misses,
            report.uncertain,
            report.unavailable,
        )
    )
    print("report={}".format(report_path))
    return 0 if report.passed == report.total else 1


if __name__ == "__main__":
    raise SystemExit(main())
