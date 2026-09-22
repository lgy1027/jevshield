# JevShield Decision-Control SDK Design

## Status

Proposed. This document defines the next product direction for JevShield while
keeping the project name and the existing guard API.

## Problem

Agent applications need small, reliable decision points around a much larger
language-model loop:

- classify a request into a business intent;
- select the next handler, agent, or a small set of tools;
- stop a loop which has succeeded or is not making progress;
- decide whether an imminent tool invocation is allowed.

These are not reasons to build an Agent framework. Applications should retain
their own loop, state store, prompts, tool registry, and framework choice.
JevShield should provide framework-independent, typed decision primitives that
an application can call at those boundaries.

The existing security guard remains the highest-consequence consumer of this
capability. Jev can recognize both the declared task intent and what a tool
call actually attempts to do; JevShield must turn that signal into a
deterministic enforcement decision before the tool runs.

## Product Position

JevShield is an **Agent decision-control SDK powered by Jev**. It is not an
Agent framework and it is not merely a thin HTTP wrapper around Jev.

Its product value is:

1. Python-native, strongly typed inputs and outputs rather than ad-hoc JSON.
2. One reliable transport, response-validation, confidence, timeout, and
   failure model for Jev decisions.
3. Deterministic local policies around model outputs.
4. Reusable control modules: `classify`, `route`, `guard`, and `loop`.
5. Optional framework adapters which do not leak framework types into the
   core API.

## Goals

- Retain the `jevshield` package and the existing public `guard()` API.
- Allow callers to classify arbitrary text or structured state into a caller
  supplied Python `Enum`.
- Allow callers to select exactly one typed route from a caller supplied route
  registry.
- Make uncertain, malformed, unavailable, and timed-out decisions explicit.
- Let Guard use Jev-derived intent signals to detect a mismatch between a
  trusted task objective and an actual tool call.
- Preserve synchronous and asynchronous APIs.
- Preserve the existing production fail-closed behavior for security control.

## Non-goals

- Do not own an Agent event loop, prompt, memory, planner, tool executor, or
  persistence layer.
- Do not automatically discover tools or infer permissions from tool names.
- Do not make a matching intent automatically authorize a tool invocation.
- Do not make Router the final authorization mechanism for a tool.
- Do not promise a fixed Jev latency or invoke Jev on every Agent loop turn.
- Do not include ToolPruner in the first delivery; it is a later optimization
  module, not a control-plane prerequisite.
- Do not claim adapters for frameworks that have not been implemented and
  tested.

## Design Principles

### Framework independence

Core modules use Python values, standard-library types, and protocols. A
LangChain adapter, for example, converts framework state into core types and
calls the same public API that a plain `while` loop can call.

### Jev decides meaning; local code decides consequences

Jev performs the classification, choice, score, or boolean assessment. Local
code validates the response, records confidence, selects fallback behavior,
and enforces a configured action. No remote answer is executable by itself.

### Typed uncertainty is safer than silent fallback

A decision response always identifies whether it is resolved, uncertain, or
unavailable. `route` may use an application-provided fallback route, but only
when the caller has explicitly requested one. `guard` uses its own stricter
security policy and never silently converts evaluator failure into permission.

### Trusted objective and untrusted evidence stay separate

The application supplies a trusted objective from its own request/session
state. Web content, tool observations, and model-generated text may be passed
as evidence, but cannot declare the expected intent. This prevents prompt
injection from redefining authorization scope.

### Compatibility before cleanup

`JevClient.evaluate_context()`, `guard()`, `Policy`, and existing guard result
models remain supported. The generic runtime is introduced beneath them; the
security-specific methods become adapters rather than being removed.

## Existing Starting Point

The current package has the necessary enforcement foundation:

- `JevClient` owns backend selection, HTTP transport, retries, and sync/async
  request paths.
- `GuardContext` already has fields for `environment`, `actor_id`,
  `resource_scope`, and `intent`.
- `guard()` runs local Fast-Deny rules, remote evaluation, deterministic
  `decide()`, then enforcement and audit.
- `LoopTerminator` is a separate local, framework-independent component.

The limiting point is `JevClient._build_payload()`: it always builds the three
security questions. It must become a security-specific payload factory built
on a generic request executor, not the only request construction path.

## Architecture

```text
                  Application-owned Agent runtime
        objective, session state, handler registry, tool registry
                                |
      +-------------------------+-------------------------+
      |                                                   |
 classify / route                                         guard
      |                                                   |
      +------------------ JevRuntime --------------------+
                transport, schema validation,
              confidence, timeout, sync/async I/O
                                |
                       TypeSafe / Jev backend

 loop: local termination rules; optional future semantic checkpoint
```

The core must have no imports from framework adapters. `guard` consumes the
runtime through a small protocol. `classify` and `route` consume the same
protocol. This prevents different retry, parsing, and error behaviors from
appearing across modules.

## Core Runtime

### Public types

The first implementation introduces these public, immutable types in
`jevshield.runtime`:

```python
class DecisionStatus(str, Enum):
    RESOLVED = "resolved"
    UNCERTAIN = "uncertain"
    UNAVAILABLE = "unavailable"

@dataclass(frozen=True)
class ChoiceQuestion:
    name: str
    instructions: str
    criteria: Mapping[str, str]

@dataclass(frozen=True)
class ChoiceAnswer:
    value: Optional[str]
    confidence: float
    status: DecisionStatus
    latency_ms: float
    source: str
    reason: str = ""

class DecisionClient(Protocol):
    def choose(self, state: str, question: ChoiceQuestion) -> ChoiceAnswer: ...
    async def achoose(self, state: str, question: ChoiceQuestion) -> ChoiceAnswer: ...
```

The initial runtime surface is deliberately limited to `Choice`. It is enough
for typed classification and route selection. The existing guard keeps its
specialized Choice + Noul + Score composition. Generic Noul and Score APIs are
added only when a concrete module requires them.

### Status rules

- `RESOLVED`: a known criterion is returned and confidence is finite in
  `[0.0, 1.0]`.
- `UNCERTAIN`: the response was structurally valid but confidence is below the
  caller's minimum, or no unique valid criterion was returned.
- `UNAVAILABLE`: no key, timeout, non-200 response, malformed response, or
  transport failure. The reason is safe to log but contains no secret state.

The raw backend response is not exposed by default. It can be added later as
an opt-in debugging hook after redaction requirements are defined.

## Typed Intent Classification

### API

`jevshield.classify` turns a caller-defined `Enum` into Choice criteria and
maps the validated answer back to an enum instance.

```python
class Intent(str, Enum):
    LOOK_UP_ORDER = "look_up_order"
    MODIFY_ORDER = "modify_order"
    DELETE_ORDER = "delete_order"
    ESCALATE = "escalate"

classifier = IntentClassifier(
    Intent,
    descriptions={
        Intent.LOOK_UP_ORDER: "Read order data without changing it.",
        Intent.MODIFY_ORDER: "Change an existing order.",
        Intent.DELETE_ORDER: "Cancel or permanently delete an order.",
        Intent.ESCALATE: "Hand the request to a human operator.",
    },
    client=client,
)
result = classifier.classify("Please change order 1024's delivery address")
```

`IntentResult` is a `Generic[TIntent]` and contains
`value: Optional[TIntent]`, `status`, `confidence`, `latency_ms`, `source`,
and `reason`. `aclassify()` mirrors the method for async callers.

### Requirements

- Enum values must be unique non-empty strings.
- Every enum member requires a non-empty human-readable description.
- The input state must be bounded before remote transmission. Callers can pass
  a string, or a mapping that is serialized with the existing redaction and
  bounded-state helpers.
- `min_confidence` defaults to `0.0` for classification; callers opt into a
  stricter threshold.
- The classifier does not invent a fallback enum member.
- Public annotations use `Optional[...]` and `typing.Generic`, not Python 3.10
  union or generic syntax, because the package supports Python 3.9.

### Why an Enum rather than a fixed taxonomy

Business intent is domain-specific. A support service, a finance workflow,
and an infrastructure Agent do not share one useful exhaustive intent list.
JevShield provides the type-safe mechanism; applications own their domain
vocabulary and explanations.

## Typed Route Selection

### API

`jevshield.route` selects one registered route key. The registry can route to
a callable, an Agent, a queue name, or any other application-owned value.

```python
router = Router(
    {
        "orders": Route("Order operations and order-status questions", orders_handler),
        "knowledge": Route("Product and policy knowledge questions", knowledge_handler),
        "human": Route("Requests requiring a human operator", human_handler),
    },
    client=client,
    min_confidence=0.70,
)
selection = router.select(message)
```

`RouteSelection` is a `Generic[TTarget]` and contains
`route_key: Optional[str]`, `target: Optional[TTarget]`, `status`,
`confidence`, `latency_ms`, `source`, and `reason`. A resolved selection
returns the exact target registered under the returned key.

### Requirements

- Route keys are unique non-empty strings.
- Route descriptions are mandatory and are the semantic criteria sent to Jev.
- A route key returned by Jev but absent from the registry is `UNCERTAIN`, not
  a `KeyError` or a guessed route.
- An uncertain or unavailable selection is returned to the caller. Optional
  `fallback_key` is allowed only when explicitly configured and is represented
  in the result as `source="configured_fallback"`.
- Router never invokes the selected target. Invocation remains application
  code, so route selection cannot bypass Guard.

## Guard Intent-Consistency Gate

### Objective

Block an invocation when a trusted objective and the observed tool invocation
have incompatible intents. This specifically catches a task that began as a
read-only request but was transformed by prompt injection, hallucination, or
bad planning into a destructive or exfiltrating tool call.

### Data flow

1. The host provides a `GuardContext` containing trusted `intent`, environment,
   actor identity, and resource scope through a context provider.
2. The classifier maps the trusted objective and the redacted actual tool call
   into the application's declared `Intent` enum.
3. `IntentPolicy` evaluates their relation locally.
4. The result is combined with existing Fast-Deny rules and risk evaluation.
5. `guard` enforces the most restrictive resulting action.

### API shape

```python
@guard(
    policy=ProductionPolicy(),
    context_provider=request_context,
    intent_policy=IntentPolicy(
        classifier=order_intent_classifier,
        on_mismatch=Action.DENY,
        on_uncertain=Action.DENY,
    ),
)
def execute_order_tool(command: str) -> str:
    ...
```

`context_provider` receives `args` and `kwargs` and returns an additive
`GuardContextMetadata` value with trusted values for `intent`, `environment`,
`actor_id`, and `resource_scope`. Function metadata and call arguments remain
owned by the decorator so a provider cannot spoof the invoked tool.

`IntentPolicy` starts with equality comparison: expected and observed intents
must match. The next compatible extension is a caller-provided relation
function, for example allowing `LOOK_UP_ORDER` to invoke a read-only status
tool while rejecting `DELETE_ORDER`. No implicit semantic compatibility table
is provided by the SDK.

### Enforcement matrix

| Condition | Intent gate result | Guard consequence |
| --- | --- | --- |
| No trusted `context.intent` | skipped | existing Guard behavior |
| Expected and observed intent resolve and match | pass | existing Guard behavior |
| Both resolve and differ | mismatch | configured `ask` or `deny` |
| Either is uncertain | uncertain | configured `ask` or `deny` |
| Either is unavailable | unavailable | configured `ask` or `deny` |
| Local Fast-Deny detects known critical pattern | n/a | deny before remote intent evaluation |

The intent gate can never convert a Guard denial into `allow`. It is an
additional restrictive signal only.

## Loop and Tool Pruning

### Loop

The shipped `LoopTerminator` remains local and deterministic: maximum
iterations, repeated tool calls, stagnant observations, and budget exhaustion.
It should not call Jev on every turn. A later `LoopReviewer` may run only at a
local checkpoint (near a stop condition or host-requested review) and return
`continue`, `ask_for_help`, or `stop_stalled`; local terminal rules remain the
authority.

### ToolPruner

Tool pruning is intentionally deferred. When introduced, it selects a bounded
candidate list before a main model call. It reduces prompt size and accidental
tool exposure, but never authorizes execution and must not be marketed as a
security boundary. Guard remains the last control point.

## Package Layout

```text
jevshield/
  runtime.py       # ChoiceQuestion, ChoiceAnswer, DecisionStatus, DecisionClient
  client.py        # Jev transport and runtime implementation; legacy guard adapters
  classify.py      # IntentClassifier, IntentResult
  route.py         # Route, Router, RouteSelection
  intent.py        # IntentPolicy and intent consistency evaluation
  models.py        # Existing Guard models; narrowly extended context metadata
  decorators.py    # context_provider and intent_policy composition
  core.py          # Existing deterministic Guard decision/enforcement
  loop.py          # Existing local LoopTerminator
  integrators.py   # Framework adapters only
```

`runtime.py`, `classify.py`, `route.py`, and `intent.py` must not import
`decorators.py` or framework integrations. `guard` may import intent types.

## Failure and Privacy Rules

- Remote state is redacted and size-bounded before every request, including
  classify and route.
- Timeout, network error, malformed response, and missing credentials become
  typed `UNAVAILABLE` results outside Guard.
- Security-policy defaults remain fail-closed in `ProductionPolicy`.
- Route fallback is opt-in and auditable in the returned result; it is not a
  hidden retry strategy.
- No automatic retries are added beyond the existing transport behavior until
  retries can be configured consistently for every runtime call.
- No latency SLO is included in docs or APIs. The SDK exposes measured
  `latency_ms` for the caller to observe if desired.

## Compatibility and Migration

1. Keep all existing exported Guard symbols and decorator behavior working.
2. Introduce the generic runtime behind new APIs without altering legacy
   `evaluate()` behavior.
3. Refactor `evaluate_context()` to use the shared transport executor while
   retaining its current return type and policy semantics.
4. Add `context_provider` and `intent_policy` as optional keyword-only
   decorator parameters; absent parameters preserve current behavior.
5. Update README positioning and examples only after all documented APIs are
   implemented and integration-tested.

## Delivery Sequence

### Milestone 1 — Runtime and classification

Deliver `DecisionStatus`, Choice request/answer validation, sync/async choice
execution, and `IntentClassifier`. Test successful conversion, unknown choice,
low confidence, timeout, malformed payload, redaction, and async parity.

### Milestone 2 — Route selection

Deliver typed route registration/selection, explicit fallback semantics, and
sync/async parity. Test no target invocation, duplicate keys, unknown returned
keys, fallback attribution, and confidence behavior.

### Milestone 3 — Guard intent consistency

Deliver trusted context metadata injection, `IntentPolicy`, and restrictive
composition with existing Guard decisions. Test match, mismatch, uncertainty,
unavailability, production defaults, and Fast-Deny-before-network ordering.

### Milestone 4 — Documentation and adapters

Document plain-Python usage first. Add framework adapters only for frameworks
covered by executable integration tests. Do not claim OpenClaw, Hermes-Agent,
or LangGraph compatibility before these adapters exist.

### Deferred milestone — LoopReviewer and ToolPruner

Define these only after a concrete application demonstrates the need and an
evaluation set proves the decision quality. Their failure behavior must not
weaken LoopTerminator or Guard.

## Acceptance Criteria

- A plain Python application can classify text into a caller-defined Enum with
  synchronous and asynchronous APIs.
- A plain Python application can select a typed target from a route registry;
  unresolved choices do not invoke a target.
- Every runtime outcome exposes a status and a bounded confidence value.
- Existing guard tests remain green without caller changes.
- A production Guard can deny a high-confidence mismatch between a trusted
  objective and a classified tool invocation.
- Missing trusted intent preserves existing Guard behavior.
- No runtime or documentation claim describes Jev calls as guaranteed
  sub-100-millisecond operations.
- No core module requires a third-party Agent framework.

## Explicit Product Decisions

- Keep the project name `JevShield` for now.
- Broaden its positioning to decision control, without dropping the security
  focus that gives the package its clearest concrete value.
- Ship classification and routing as first-class SDK capabilities.
- Make Guard an independent final authorization layer, not an outcome of
  routing.
- Keep observability and performance work outside these milestones unless they
  are required to preserve correctness or safety.
