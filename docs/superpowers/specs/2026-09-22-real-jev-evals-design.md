# Real Jev Evals Design

## Goal

Add a framework-independent, local-only evaluation harness that calls real Jev
to measure the correctness of JevShield's typed intent classification and
route selection APIs.

## Scope

The first suite evaluates `IntentClassifier` and `Router` against checked-in
Chinese Agent scenarios. It records aggregate accuracy, uncertainty rate, and
per-case IDs without persisting request text, raw responses, or credentials.

This is not a unit-test replacement. Existing unit tests remain deterministic
and network-free. Evals are an explicit developer command and require a real
Jev API key.

## Security and Execution Rules

- Load `JEV_API_KEY` from the process environment first, then from a project
  root `.env` file if present.
- Never print, serialize, commit, or include the key in reports.
- `.env` remains ignored by Git. Do not create a placeholder containing a key.
- If no key is available, exit before a network request with an actionable
  message; do not mock or silently pass.
- Evals run only through `python -m evals.run`; CI continues to run only
  deterministic unit tests.
- Reports contain case ID, suite, expected value, predicted value, decision
  status, confidence, latency, and pass/fail. They exclude full prompt text,
  tool descriptions, and raw gateway payloads.

## Layout

```text
evals/
  __init__.py
  cases/
    classify.json
    route.json
  loader.py       # validates immutable case records
  runner.py       # runs one suite against real Jev and creates a safe report
  run.py          # argparse module entry point
tests/
  test_evals.py   # network-free loader, report, .env, and CLI unit tests
```

## Scenario Format

Each JSON case uses an ID, a prompt, a fixed candidate set, and an expected
decision. Candidate descriptions model real Agent capability metadata.

```json
{
  "id": "route-order-address-change",
  "input": "把订单 1024 的收货地址改成上海",
  "candidates": {
    "orders": "查询、修改订单和配送信息",
    "knowledge": "检索产品、政策和使用文档",
    "human": "高风险、投诉或需要人工判断的请求"
  },
  "expected": "orders"
}
```

The initial committed corpus has 30 Chinese cases: 15 classification and 15
routing. It includes normal tasks, semantically adjacent tasks, ambiguous
requests, multi-intent requests, similar tool descriptions, and requests that
should route to human review.

## Runtime Behavior

`evals.run` accepts `--suite classify|route|all`, `--report-dir`, and
`--min-confidence`. It builds one `JevClient` from the loaded credential and
uses the public `IntentClassifier`/`Router` APIs; it does not call internal
payload builders.

For every case:

1. Instantiate the candidate Enum or route registry from the case.
2. Invoke the public SDK method against real Jev.
3. Mark a pass only when `status == resolved` and predicted equals expected.
4. Record uncertainty and unavailability separately from incorrect resolved
   answers.

Exit status is zero only when every case is resolved and matches expectation.
This makes regressions visible to a manual caller without claiming that an
evaluation corpus is a complete safety guarantee.

## Output

The runner writes one timestamped JSON report to the selected local report
directory. Its schema is:

```json
{
  "suite": "classify",
  "model": "jev-latest",
  "total": 15,
  "passed": 12,
  "incorrect": 1,
  "uncertain": 1,
  "unavailable": 1,
  "cases": [
    {
      "id": "classify-order-address-change",
      "expected": "modify_order",
      "predicted": "modify_order",
      "status": "resolved",
      "confidence": 0.92,
      "latency_ms": 123.4,
      "passed": true
    }
  ]
}
```

## Non-goals

- Do not test the future Guard intent-consistency gate until it exists.
- Do not perform live network calls in normal tests or CI.
- Do not treat a small fixed corpus as a benchmark of general Agent safety.
- Do not build a third-party evaluation framework dependency for the first
  version.

## Acceptance Criteria

- `python -m evals.run --suite classify` and `--suite route` execute only with
  a real configured key and public SDK APIs.
- Missing credentials prevent network use and produce a non-zero exit status.
- Committed cases and reports contain no credentials or raw payload text.
- The initial corpus has at least 15 cases per suite and all required scenario
  categories.
- `tests/test_evals.py` verifies loader validation, report redaction, missing
  key behavior, and deterministic aggregation without real network access.
