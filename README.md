# JevShield 🛡️

[![PyPI version](https://img.shields.io/badge/pypi-v0.1.1-blue.svg)](https://pypi.org/)
[![License](https://img.shields.io/badge/License-Apache_2.0-green.svg)](https://opensource.org/licenses/Apache-2.0)
[![Python Versions](https://img.shields.io/badge/python-3.9+-blue.svg)](https://python.org)

**A framework-agnostic decision-control SDK for AI agents powered by Jev (System-1 Models).**

`jevshield` provides typed decision primitives for classifying requests and
selecting application routes. Its Guard remains the execution-time security
layer: a protected operation is evaluated before it is invoked and dangerous
operations can be denied.

* **Typed decisions** use explicit Choice results and statuses.
* **Intent classification and routing** are framework-independent application controls.
* **Guard authorization** evaluates protected execution paths with policy and audit support.

---

## Architecture: System-1 vs. System-2 Division

<p align="center">
  <img src="https://raw.githubusercontent.com/lgy1027/jevshield/main/docs/architecture.svg" alt="JevShield architecture: the System 2 agent prepares a tool call; the System 1 JevShield middleware evaluates Choice, Noul, and Score primitives before either passing safe calls or halting destructive ones.">
</p>

---

## Quick Start

### 1. Installation

```bash
pip install jevshield
```

For LangChain tool integrations:

```bash
pip install "jevshield[langchain]"
```

### 2. Basic Decorator Usage (Sync & Async)

```python
from jevshield import ProductionPolicy, SecurityViolationError, guard

# ProductionPolicy fails closed if no evaluator is configured. Set a provider
# key before running safe operations with this production example:
# export TYPESAFE_API_KEY="ts-..."
# API request timeout defaults to 2 seconds; tune it for your environment:
# export JEV_TIMEOUT_SECONDS="10"

@guard(policy=ProductionPolicy())
def run_terminal(cmd: str):
    """Executes arbitrary bash commands on the local machine."""
    print(f"Executing: {cmd}")
    return "OK"

# 1. Safe operations are evaluated before invocation
run_terminal("ls -la /var/log")

# 2. Destructive operations are halted before invocation
try:
    run_terminal("rm -rf /etc/kubernetes")
except SecurityViolationError as e:
    print(f"Blocked: {e.reason}")
```

`ProductionPolicy()` is the recommended default whenever a guarded function can
affect a real environment. It fails closed: an evaluator timeout, malformed
response, transport failure, or local-rule failure becomes a denial before the
wrapped function is invoked. Development and staging policies retain heuristic
fallback behavior for local iteration; do not use them as a production
availability workaround.

### Audit hooks and approval

Pass an `audit_sink` to receive exactly one terminal event for every guarded
call. The event's context and `redacted_arguments` are audit-safe: recognized
credentials are replaced before the event reaches your sink.

```python
import logging

from jevshield import ProductionPolicy, guard
from jevshield.audit import CallbackAuditSink

security_logger = logging.getLogger("security")

def write_security_event(event):
    # event.outcome is allow, deny, ask-approval, or ask-rejection.
    # Never rebuild an audit record from the original function arguments here.
    security_logger.info("guard decision", extra={
        "outcome": event.outcome,
        "tool": event.context.tool_name,
        "redacted_args": event.redacted_arguments,
        "source": event.evaluation.source,
    })

@guard(
    policy=ProductionPolicy(),
    audit_sink=CallbackAuditSink(write_security_event),
)
def rotate_key(service: str):
    ...
```

When a policy produces `ASK` (for example, a low-confidence result), JevShield
uses an interactive terminal confirmer only when a TTY is available. In a
headless worker, container, CI job, or Kubernetes pod, an `ASK` without an
explicit confirmer is denied immediately. An explicit confirmer is bounded by
`policy.ask_timeout` (at most 30 seconds); timeout, failure, or a non-approval
also denies the call.

### Required policy configuration

JevShield is a new policy-first API: `policy=` is required for both `guard()`
and `guard_langchain_tool()`. Configure risk thresholds and confidence routing
on a `Policy` instance, and supply a `confirmer=` when your runtime needs an
explicit approval workflow. The former decorator keywords `risk_threshold`,
`interactive`, and `min_confidence` are not accepted.

### Production API timeout

`JevClient` defaults to a 2-second HTTP timeout. Configure it explicitly for
your production latency budget; an explicit constructor value overrides the
`JEV_TIMEOUT_SECONDS` environment variable.

```python
from jevshield import JevClient, ProductionPolicy, guard

# Environment-wide default for clients created by the integration.
# export JEV_TIMEOUT_SECONDS="10"

client = JevClient(timeout=10)

@guard(policy=ProductionPolicy(), client=client)
def read_status():
    ...
```

The timeout controls client-side HTTP operations, not a provider SLA. Production
policies fail closed when the evaluator times out, so set it from observed
provider latency and the maximum blocking time your tool execution can accept.

---

## Security Posture

* **Prompt-Injection Framing**: tool docstrings and arguments are structurally enclosed as passive data before evaluation; untrusted content is not presented as instructions.
* **Two-tier redaction**: secrets are removed before an evaluator request and audit-bound data receives a second redaction pass. Original arguments are never placed on decisions, exceptions, or audit events.
* **Fast-Deny local rules**: obvious destructive and sensitive-data-exfiltration commands are denied locally without evaluator network I/O. There is intentionally no local Fast-Pass path.
* **Production fail-closed behavior**: `ProductionPolicy()` denies evaluator timeouts, malformed responses, transport errors, and local-rule failures. Unknown risk tiers and missing blast-radius scores are also never allowed through.
* **Bounded approval**: a low-confidence result can become `ASK`, but a headless process without a confirmer, an approval timeout, or an approval failure always denies.

```python
from dataclasses import replace
from jevshield import ProductionPolicy, guard

# Low-confidence evaluations are routed to the configured operator confirmer.
@guard(policy=replace(ProductionPolicy(), min_confidence=0.6))
def run_terminal(cmd: str):
    ...
```

---

## Supported Primitives & Policy Matrix

`jevshield` structures the security evaluation strictly into three Jev primitives on every pass:

| Primitive | Query | Return Type | Role in Gate |
| --- | --- | --- | --- |
| **Choice** | Risk Tier Assignment | `safe`, `medium_risk`, `critical_danger` | Sets nominal danger bracket. |
| **Noul** | `is_destructive` Statement | P(True) ∈ [0.0, 1.0] | Assesses irreversible damage (data loss, kill). |
| **Score** | Failure Blast Radius | 0–4 weighted position across 5 ordered levels | Quantifies systemic exposure. |

An action is blocked if:

```
(Tier ≥ Threshold ∧ P_destructive > 0.75) ∨ (BlastRadius ≥ 3 ∧ IsDestructive = True)
```

---

## Supported Providers & Gateway Endpoints

`jevshield` implements the official System One protocol and supports two backends:

```bash
# Option A: TypeSafe Official Direct Access (default)
export TYPESAFE_API_KEY="ts-..."
# Optional: pin a model version (default jev-latest)
export JEV_MODEL="jev-1.13.0"
# Optional: API request timeout in seconds (default 2.0)
export JEV_TIMEOUT_SECONDS="10"

# Option B: OpenRouter (OpenRouter System One endpoint — same protocol, extra id/provider/usage.cost fields)
export JEV_BACKEND="openrouter"
export OPENROUTER_API_KEY="sk-or-v1-..."
# Optional: default model is typesafe/jev-1.13; use ~typesafe/jev-latest for the rolling alias
```

Backend resolution order: `JevClient(backend=...)` argument > `JEV_BACKEND` env var > auto-detect
(TypeSafe key present -> official direct; only an OpenRouter key -> OpenRouter).

| Backend | Endpoint | Default model | Notes |
| --- | --- | --- | --- |
| `typesafe` (default) | `https://api.typesafe.ai/v1/systemone` | `jev-latest` | Official direct access |
| `openrouter` | `https://openrouter.ai/api/v1/systemone` | `typesafe/jev-1.13` | Response additionally carries `id` / `provider` / `usage.cost`; the alpha endpoint `/api/alpha/decisions` can be used instead via `JEV_BASE_URL` |

> ⚠️ Vercel AI Gateway (experimental `evaluate` interface; Noul is called Boolean there) and Cloudflare
> Workers AI (`env.AI.run('typesafe/jev')`) use different request/response shapes and are not adapted yet.

If neither key is present, development and staging policies run in
**Deterministic Heuristic Fallback Mode**, which is useful for test suites and
Docker builds. `ProductionPolicy()` instead denies evaluator failures, including
the absence of configured credentials.

## Manual Jev Evaluation Suites

The checked-in `classify`, `route`, `route_high_risk`,
`route_security_holdout`, and `guard_intent_consistency` corpora can be run
manually against a configured Jev provider. They are opt-in: normal unit tests
use a recording decision client and never make live requests. Store a local
credential as `JEV_API_KEY` in the ignored project-root `.env` file (or set it
in your shell), then run:

```bash
JEV_API_KEY="your-local-key" python -m evals.run --suite all
```

Choose one corpus with `--suite classify`, `--suite route`, `--suite
route_high_risk`, `--suite route_security_holdout`, or `--suite
guard_intent_consistency`; optionally write the redacted JSON result somewhere
else with `--report-dir PATH` and reject lower-confidence decisions with
`--min-confidence FLOAT` (from 0 to 1).
`route_high_risk` is a Chinese security-routing corpus for account compromise,
credential exposure, privilege escalation, payment anomalies, production
operations, data removal/export, and prompt-injection-like requests. Every case
must resolve to `security_review`.
`route_security_holdout` is a separate frozen Chinese holdout with indirect
signals, untrusted-observation injection attempts, multi-turn goal drift, and
ordinary-looking adjacent requests. Do not tune route candidate descriptions
against holdout results. Both security corpora fail a resolved selection that is
not `security_review` and reject cases missing that candidate.
ordinary `human` handling is deliberately a distinct, failing outcome. For
example:

```bash
python -m evals.run --suite classify --report-dir ./local-eval-reports --min-confidence 0.8

# Run the security-only routing corpus.
python -m evals.run --suite route_high_risk

# Run the separate frozen security holdout.
python -m evals.run --suite route_security_holdout

# Exercise trusted-objective versus observed-invocation enforcement.
python -m evals.run --suite guard_intent_consistency
```

The intent-consistency suite is framework-free: it passes each trusted objective
through `IntentClassifier` and each proposed tool invocation through `guard`
and `IntentPolicy`, without LangChain or another agent runtime. Its protected
function is a harmless in-memory marker. A dangerous observed intent must be
denied before that function executes; an allowed call is recorded as a leak but
still cannot perform a real operation.

The default TypeSafe provider needs only `JEV_API_KEY`. To run the same suite
against the OpenRouter System One endpoint, select that backend explicitly while
using the local key:

```bash
# JEV_API_KEY is read from the ignored .env file.
JEV_BACKEND=openrouter python -m evals.run --suite guard_intent_consistency
```

The command prints aggregate outcome counts and the report path only. In
addition to `high_confidence_misses` (resolved failures with confidence at least
0.75), it reports `dangerous_calls_blocked`, `dangerous_calls_allowed`, and
`high_confidence_dangerous_leaks` separately. Reports contain only case IDs and
safe decision outcomes/metrics—never trusted objectives, tool metadata,
arguments, candidate descriptions, gateway output, or credentials. Keep their
destination private as a sensible operational precaution. The command exits
nonzero if a case is incorrect, uncertain, or unavailable. These evaluations
measure behavior on a bounded checked-in corpus; they do not prove general
safety or correctness for all prompts and workloads.

---

## LangChain Integration

```python
from langchain_core.tools import tool
from jevshield import ProductionPolicy, guard_langchain_tool

@tool
def format_volume(device: str):
    """Erases and formats a block storage partition."""
    return f"Formatted {device}"

# Automatically patches both sync (_run) and async (_arun) paths
guarded_format = guard_langchain_tool(format_volume, policy=ProductionPolicy())
```

## Typed Intent Classification

Classify application requests with a string `Enum` and complete descriptions
for every intent. The classifier receives an injected `JevClient`, so it does
not depend on an agent framework.

```python
from enum import Enum

from jevshield import DecisionStatus, IntentClassifier, JevClient


class SupportIntent(str, Enum):
    ORDER_STATUS = "order_status"
    KNOWLEDGE_BASE = "knowledge_base"


client = JevClient(api_key="ts-...")
classifier = IntentClassifier(
    SupportIntent,
    {
        SupportIntent.ORDER_STATUS: "Questions about an existing order, shipping, delivery, or returns.",
        SupportIntent.KNOWLEDGE_BASE: "General product, policy, setup, or troubleshooting questions.",
    },
    client=client,
    min_confidence=0.7,
)

result = classifier.classify({"request": "Where is order 12345?"})
if result.status is DecisionStatus.RESOLVED:
    handle_intent(result.value)
elif result.status is DecisionStatus.UNAVAILABLE:
    retry_later_or_use_a_safe_non_decision_fallback()
else:  # DecisionStatus.UNCERTAIN
    ask_for_clarification()
```

## Route Before Tool Exposure

`Router` chooses a registered target but never invokes or authorizes it. The
application explicitly decides whether and how to call `selection.target`.

```python
from jevshield import DecisionStatus, JevClient, Route, Router


def answer_order_question(request: str) -> str:
    return lookup_order(request)


def answer_knowledge_question(request: str) -> str:
    return search_knowledge_base(request)


router = Router(
    {
        "orders": Route(
            description="Questions about existing orders, shipping, delivery, or returns.",
            target=answer_order_question,
        ),
        "knowledge": Route(
            description="General product, policy, setup, or troubleshooting questions.",
            target=answer_knowledge_question,
        ),
    },
    client=JevClient(api_key="ts-..."),
    min_confidence=0.7,
)

selection = router.select({"request": user_request})
if selection.status is DecisionStatus.RESOLVED and selection.target is not None:
    response = selection.target(user_request)  # Application code chooses this invocation.
elif selection.status is DecisionStatus.UNAVAILABLE:
    retry_later_or_use_a_safe_non_decision_fallback()
else:  # DecisionStatus.UNCERTAIN
    ask_for_clarification()
```

For a target that can affect a real environment, Guard is the separate,
execution-time authorization layer. Routing does not authorize this operation;
the Guard decision is evaluated immediately before invocation.

```python
from jevshield import ProductionPolicy, guard


@guard(policy=ProductionPolicy())
def cancel_order(order_id: str) -> str:
    return orders_api.cancel(order_id)
```

## Local Agent Loop Termination

`LoopTerminator` is an optional, framework-independent local control for
stopping retry loops. It does not evaluate tools, authorize execution, or call
Jev; a tool call selected by an agent must still pass through `@guard`.

```python
from jevshield import LoopAction, LoopPolicy, LoopStep, LoopTerminator

terminator = LoopTerminator(LoopPolicy(
    max_iterations=12,
    max_repeated_tool_calls=3,
    max_stagnant_iterations=3,
))

# Call after each completed agent iteration. Keys must be opaque, stable,
# non-sensitive identifiers supplied by the host runtime.
decision = terminator.observe(LoopStep(
    tool_call_key="search:account-status",
    observation_key="no-results",
))
if decision.action != LoopAction.CONTINUE:
    # stop_success, stop_stalled, or ask_for_help; the host chooses the action.
    handle_loop_decision(decision)
```

Use `goal_completed=True` only when the host has independently established
success. `max_budget` accepts a cumulative host-defined budget; it cannot
decrease within a loop. Set `stall_action=LoopAction.ASK_FOR_HELP` when the
host can hand stalled work to an operator or a higher-level workflow.

---

## License

This project is licensed under the **Apache License, Version 2.0**. See the [LICENSE](LICENSE) file for details.

## Disclaimer

JevShield is an independent, community-driven project and is **not affiliated with, endorsed by, or sponsored by TypeSafe AI**. "Jev", "System One", and "TypeSafe" are trademarks of TypeSafe AI. JevShield interacts with TypeSafe's public API under their published terms of use.
