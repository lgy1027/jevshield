# Loop Review and Tool Pruning Design

## Status

Proposed for the next JevShield decision-control milestone.

## Purpose

Extend JevShield's framework-independent decision layer for applications that
run both multi-tool Agents and retrieval-augmented generation (RAG) flows.
The extension must not own a loop, a retriever, tools, memory, or a framework
runtime. Applications keep those responsibilities and call JevShield only at
their own decision checkpoints.

## Goals

- Add an optional semantic `LoopReviewer` beside the local `LoopTerminator`.
- Define a typed, framework-independent contract for `ToolPruner` without
  prematurely committing the transport to an unvalidated multi-select schema.
- Keep `guard()` as the execution-time authorization control. Neither module
  authorizes a tool invocation.
- Make every remote outcome explicit as resolved, uncertain, or unavailable.
- Permit thin, optional framework adapters without framework imports in core
  modules.

## Non-goals

- Do not build an Agent framework, RAG framework, tool executor, retriever,
  vector store, prompt template, or persistence layer.
- Do not call Jev on every loop iteration.
- Do not let semantic review override a terminal local loop decision.
- Do not claim ToolPruner is a security boundary or a replacement for Guard.
- Do not ship adapters for frameworks without executable integration tests.

## Architecture

```text
Application-owned Agent or RAG flow
  ├─ local LoopTerminator ── terminal decision remains authoritative
  ├─ optional LoopReviewer ── recommendation at application checkpoint
  ├─ optional ToolPruner ──── candidate list before a model/tool-selection call
  └─ guard() ─────────────── execution-time enforcement for every tool call
```

Core modules consume only standard-library immutable values and the existing
`DecisionClient` protocol. Framework adapters translate framework state into
these values and apply returned recommendations; they never pass framework
objects into core APIs.

## LoopReviewer

### API shape

```python
class LoopReviewAction(str, Enum):
    CONTINUE = "continue"
    ASK_FOR_HELP = "ask_for_help"
    STOP_STALLED = "stop_stalled"

@dataclass(frozen=True)
class LoopReviewInput:
    trusted_objective: str
    checkpoint: str
    iteration: int
    spent_budget: Optional[float] = None
    step_summaries: Tuple[str, ...] = ()
    evidence_summary: Optional[str] = None

@dataclass(frozen=True)
class LoopReviewDecision:
    action: Optional[LoopReviewAction]
    status: DecisionStatus
    confidence: float
    latency_ms: float
    source: str
    reason: str = ""
```

`LoopReviewer.review()` and `areview()` classify a redacted, bounded review
state into one of the three actions. A caller supplies the checkpoint, such as
`"stagnant_observation"`, `"evidence_insufficient"`, or
`"near_budget_limit"`; it is never inferred from a framework callback.

On uncertainty or unavailability, `action` is `None`. The host selects an
explicit fallback; the SDK must not silently continue a risky workflow. A
reviewer cannot return `stop_success`: completion remains an application fact
or a deterministic `LoopTerminator` result.

### Composition with local rules

The host always calls `LoopTerminator.observe()` first. If it returns a
terminal action, the host stops and must not use a reviewer result to revive
the loop. Only a non-terminal local decision may lead to a semantic review at
an opt-in checkpoint.

RAG applications may use the same contract: `step_summaries` describe
retrieval/re-ranking attempts and `evidence_summary` describes evidence
sufficiency without exposing raw documents or secrets.

## ToolPruner contract

### Typed input and output

```python
@dataclass(frozen=True)
class ToolCandidate:
    id: str
    description: str
    risk_tags: Tuple[str, ...] = ()

@dataclass(frozen=True)
class ToolPruneInput:
    trusted_objective: str
    candidates: Tuple[ToolCandidate, ...]
    resource_scope: Tuple[str, ...] = ()
    state_summary: Optional[str] = None

@dataclass(frozen=True)
class ToolPruneDecision:
    selected_ids: Tuple[str, ...]
    status: DecisionStatus
    confidence: float
    latency_ms: float
    source: str
    reason: str = ""
```

`selected_ids` is an ordered, duplicate-free subset of candidate IDs. A
resolved decision may be empty; uncertain or unavailable decisions must have
an empty selection. The application decides whether an empty/failed selection
means retry, ask for help, or use a conservative static list.

### Delivery constraint

The current generic runtime supports a validated single `Choice`, not a
validated multi-selection response. ToolPruner implementation is therefore
deferred until a concrete Agent/RAG evaluation establishes a stable Jev
multi-select response contract. The next milestone will first add that generic
runtime primitive, including schema validation, redaction, sync/async behavior,
and unavailable semantics; ToolPruner will consume it rather than parse raw
model JSON.

Until then, applications can use `Router` for one-next-handler selection. It
must not be presented as tool pruning.

## Framework adapters

Adapters live outside core modules and use optional dependencies, for example
`jevshield[integration-name]`. Each adapter owns only:

1. converting framework state into `LoopReviewInput` or `ToolPruneInput`;
2. invoking the core API;
3. mapping the typed decision back into the framework's own control flow.

The first adapter is selected only after identifying the framework used by the
production multi-tool Agent or RAG application. The existing LangChain guard
integration remains separate from this future loop/pruning adapter.

## Safety and privacy

- Trusted objectives are host-provided and remain distinct from untrusted
  observations, retrieved documents, tool output, and framework state.
- Every remote review/prune state uses existing redaction and bounded framing.
- Tool IDs and descriptions are candidates, not permissions; selected tools
  still pass through existing local rules and `guard()` before execution.
- Reports and eval fixtures store only safe identifiers, action/status,
  confidence, latency, and aggregate outcomes.

## Evaluation requirements

Before implementation, add deterministic fixtures for:

- Agent repeated-call and no-new-observation checkpoints;
- RAG insufficient-evidence and conflicting-evidence checkpoints;
- terminal local loop actions that cannot be overridden by semantic review;
- ToolPruner selection containing only supplied IDs, empty selection on
  unavailable/uncertain outcomes, and no authorization side effect.

Run real Jev evaluations only when local credentials are configured. A future
ToolPruner eval must include an independent holdout that has not been used to
tune tool descriptions or selection instructions.

## Delivery order

1. Implement and evaluate `LoopReviewer` core contracts plus plain-Python
   Agent/RAG examples.
2. Establish a generic validated multi-selection runtime primitive.
3. Implement `ToolPruner` against that primitive and its holdout evals.
4. Add one thin adapter for the production framework actually in use.
