"""Validation and loading for checked-in evaluation scenarios."""

from dataclasses import dataclass
import json
from pathlib import Path
from types import MappingProxyType
from typing import Mapping, Tuple, Union


@dataclass(frozen=True)
class EvalCase:
    """One immutable scenario for a classification or routing evaluation."""

    id: str
    input: str
    candidates: Mapping[str, str]
    expected: str


def load_cases(path: Union[str, Path]) -> Tuple[EvalCase, ...]:
    """Load validated evaluation cases from a JSON array at *path*."""
    source = Path(path)
    try:
        raw_cases = json.loads(source.read_text(encoding="utf-8"))
    except json.JSONDecodeError as error:
        raise ValueError("Evaluation cases must be valid JSON.") from error

    if not isinstance(raw_cases, list):
        raise ValueError("Evaluation cases must be a JSON array.")

    loaded = []
    seen_ids = set()
    for raw_case in raw_cases:
        if not isinstance(raw_case, dict):
            raise ValueError("Each evaluation case must be a JSON object.")

        case_id = raw_case.get("id")
        if not isinstance(case_id, str) or not case_id.strip():
            raise ValueError("Each evaluation case must have a non-empty string id.")
        if case_id in seen_ids:
            raise ValueError("Duplicate case id: {}".format(case_id))
        seen_ids.add(case_id)

        input_text = raw_case.get("input")
        if not isinstance(input_text, str) or not input_text.strip():
            raise ValueError("Case {} must have a non-empty string input.".format(case_id))

        if "expected" not in raw_case:
            raise ValueError("Case {} is missing expected.".format(case_id))
        expected = raw_case["expected"]
        if not isinstance(expected, str) or not expected.strip():
            raise ValueError("Case {} must have a non-empty string expected value.".format(case_id))

        candidates = raw_case.get("candidates")
        if not isinstance(candidates, dict) or not candidates:
            raise ValueError("Case {} must have a non-empty candidates object.".format(case_id))
        validated_candidates = {}
        for key, description in candidates.items():
            if not isinstance(key, str) or not key.strip():
                raise ValueError("Case {} has a non-string candidate key.".format(case_id))
            if not isinstance(description, str) or not description.strip():
                raise ValueError(
                    "Case {} has a non-string candidate description.".format(case_id)
                )
            validated_candidates[key] = description
        if expected not in validated_candidates:
            raise ValueError("Case {} expected must name a candidate.".format(case_id))

        loaded.append(
            EvalCase(
                id=case_id,
                input=input_text,
                candidates=MappingProxyType(validated_candidates),
                expected=expected,
            )
        )

    return tuple(loaded)
