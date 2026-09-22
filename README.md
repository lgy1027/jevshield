# JevShield 🛡️

[![PyPI version](https://img.shields.io/badge/pypi-v0.1.1-blue.svg)](https://pypi.org/)
[![License](https://img.shields.io/badge/License-Apache_2.0-green.svg)](https://opensource.org/licenses/Apache-2.0)
[![Python Versions](https://img.shields.io/badge/python-3.9+-blue.svg)](https://python.org)

**Framework-agnostic runtime security gate for AI Agents powered by Jev (System-1 Models).**

Traditional LLM guardrails rely on slow, autoregressive generation: calling GPT-4o or Claude to review an action can take 1.5 to 4 seconds, burn thousands of output tokens, and occasionally fail due to JSON parsing syntax errors.

`jevshield` cuts out the conversational fluff. By taking advantage of **TypeSafe AI's Jev model**, it performs single-pass, typed evaluations directly on logits:
* **Zero Output Token Billing** (Jev charges $0 for output generation).
* **Typed single-pass evaluation** via prefill logits readout.
* **Dual-Validation Matrix**: Cross-evaluates **Severity Tier (Choice)** with **Irreversibility Probability (Noul/Boolean)** to eliminate false alarms.
* **Zero-Config Local Fallback**: Instant local heuristic evaluation out of the box when no API key is provided.

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

---

## License

This project is licensed under the **Apache License, Version 2.0**. See the [LICENSE](LICENSE) file for details.

## Disclaimer

JevShield is an independent, community-driven project and is **not affiliated with, endorsed by, or sponsored by TypeSafe AI**. "Jev", "System One", and "TypeSafe" are trademarks of TypeSafe AI. JevShield interacts with TypeSafe's public API under their published terms of use.
