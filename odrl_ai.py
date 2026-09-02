"""ODRL-AI reference implementation.

A minimal, dependency-free engine that parses ODRL-AI policies (JSON-LD),
decides each request in the UCON phase appropriate to its action, and manages
the revocation obligations. It is a proof that the AI-specific evaluation logic
a generic ODRL enforcement engine would need is small; it is NOT a data space, a
connector, or production enforcement infrastructure.

Python 3.12, standard library only.
"""
from __future__ import annotations

import json
from dataclasses import dataclass, field

# ---------------------------------------------------------------------------
# Action taxonomy (Table 1): parameter incorporation, persistence, and the UCON
# phase at which the action is evaluated.
# ---------------------------------------------------------------------------
INCORPORATION = {
    "Train": "yes", "FineTune": "yes", "Distill": "indirect",
    "Embed": "no", "Retrieve": "no", "Evaluate": "no", "Synthesize": "no",
}
PERSISTENCE = {
    "Train": "weights", "FineTune": "weights", "Distill": "weights",
    "Embed": "index", "Retrieve": "none", "Evaluate": "none", "Synthesize": "dataset",
}
PHASE = {  # UCON phase: pre-authorisation, ongoing authorisation
    "Train": "pre", "FineTune": "pre", "Distill": "pre", "Synthesize": "pre",
    "Embed": "pre", "Evaluate": "pre", "Retrieve": "ongoing",
}
ACTIONS = tuple(INCORPORATION)


def is_incorporating(action: str) -> bool:
    """True for actions whose effect persists in model parameters (irreversible)."""
    return INCORPORATION.get(_bare(action)) in ("yes", "indirect")


# Member states of the European Union, used to evaluate isPartOf(EU).
EU = {
    "EU", "AT", "BE", "BG", "HR", "CY", "CZ", "DK", "EE", "FI", "FR", "DE",
    "GR", "HU", "IE", "IT", "LV", "LT", "LU", "MT", "NL", "PL", "PT", "RO",
    "SK", "SI", "ES", "SE",
}


def _bare(term):
    """Strip a namespace prefix, e.g. 'aia:Retrieve' -> 'Retrieve'."""
    if isinstance(term, str) and ":" in term:
        return term.split(":")[-1]
    return term


# ---------------------------------------------------------------------------
# Constraint evaluation
# ---------------------------------------------------------------------------
def satisfies(constraint: dict, attrs: dict) -> bool:
    """Evaluate one ODRL constraint against the attested attributes of a request."""
    op = constraint["operator"]
    left = _bare(constraint["leftOperand"])
    right = _bare(constraint["rightOperand"])
    value = attrs.get(left)
    if value is None:
        return False
    value = _bare(value)
    if op == "eq":
        return value == right
    if op == "neq":
        return value != right
    if op == "isPartOf":
        if right == "EU":
            return value in EU
        return value == right
    raise ValueError(f"unsupported operator: {op}")


# ---------------------------------------------------------------------------
# Policy model and parsing
# ---------------------------------------------------------------------------
@dataclass
class Rule:
    action: str
    constraints: list = field(default_factory=list)
    duties: list = field(default_factory=list)


@dataclass
class Policy:
    target: str = ""
    permissions: list = field(default_factory=list)
    prohibitions: list = field(default_factory=list)
    obligations: list = field(default_factory=list)

    @staticmethod
    def from_jsonld(doc) -> "Policy":
        if isinstance(doc, str):
            doc = json.loads(doc)
        p = Policy(target=doc.get("target", ""))
        for perm in doc.get("permission", []):
            p.permissions.append(Rule(
                action=_bare(perm["action"]),
                constraints=perm.get("constraint", []),
                duties=[_bare(x["action"]) for x in perm.get("duty", [])],
            ))
        for pro in doc.get("prohibition", []):
            p.prohibitions.append(Rule(action=_bare(pro["action"])))
        for ob in doc.get("obligation", []):
            p.obligations.append(Rule(action=_bare(ob["action"])))
        return p

    @staticmethod
    def from_file(path) -> "Policy":
        with open(path, "r", encoding="utf-8") as fh:
            return Policy.from_jsonld(fh.read())

    def permits(self, action: str) -> bool:
        return any(r.action == _bare(action) for r in self.permissions)

    def prohibits(self, action: str) -> bool:
        return any(r.action == _bare(action) for r in self.prohibitions)

    def permission_for(self, action: str):
        for r in self.permissions:
            if r.action == _bare(action):
                return r
        return None


# ---------------------------------------------------------------------------
# Decision (UCON pre-use / ongoing evaluation, with deny-overrides)
# ---------------------------------------------------------------------------
@dataclass
class Decision:
    permitted: bool
    reason: str
    phase: str = ""
    duties: list = field(default_factory=list)

    def __bool__(self):
        return self.permitted


def decide(policy: Policy, action: str, attrs: dict | None = None) -> Decision:
    """Decide a request for `action` under `policy`. Prohibition overrides."""
    attrs = attrs or {}
    action = _bare(action)
    phase = PHASE.get(action, "pre")
    if policy.prohibits(action):
        return Decision(False, "prohibited", phase)
    rule = policy.permission_for(action)
    if rule is None:
        return Decision(False, "no matching permission", phase)
    for c in rule.constraints:
        if not satisfies(c, attrs):
            return Decision(False, f"constraint {_bare(c['leftOperand'])}", phase)
    return Decision(True, "permitted", phase, list(rule.duties))


# ---------------------------------------------------------------------------
# Admission routing (pre-authorisation at ingestion)
# ---------------------------------------------------------------------------
def route_admission(policy: Policy):
    """Decide where a contributed dataset is placed: training corpus or
    retrieval store. A dataset is admitted to the corpus only if an
    incorporating action is permitted and not prohibited; otherwise it is
    confined to the retrieval store. Returns (placement, duties)."""
    for action in ("Train", "FineTune"):
        if policy.permits(action) and not policy.prohibits(action):
            rule = policy.permission_for(action)
            return "corpus", list(rule.duties)
    return "retrieval_store", []


# ---------------------------------------------------------------------------
# Obligation manager (post-use phase; revocation)
# ---------------------------------------------------------------------------
@dataclass
class Obligation:
    member: str
    deadline_days: int
    discharged: bool = False
    breached: bool = False


class ObligationManager:
    """Tracks retrieval-index membership and the revocation obligations that
    fall due when a contributor withdraws."""

    def __init__(self):
        self.indexed: set[str] = set()       # members present in retrieval indices
        self.pending: dict[str, Obligation] = {}

    def admit(self, member: str, placement: str) -> None:
        if placement in ("retrieval_store", "corpus"):
            self.indexed.add(member)

    def revoke(self, member: str, permitted_incorporating: bool,
               deadline_days: int = 30) -> str:
        """Handle a revocation event. Removes deletable state immediately and,
        for members whose data was admitted to an incorporating use, schedules
        exclusion from the next training run, attested within a deadline."""
        self.indexed.discard(member)  # de-index now (deletable state)
        if permitted_incorporating:
            self.pending[member] = Obligation(member, deadline_days)
            return (f"de-index now; excluded from next training run; "
                    f"non-inclusion attested ({deadline_days}-day deadline)")
        return "de-index only"

    def attest(self, member: str) -> bool:
        """Discharge the obligation by attesting non-inclusion."""
        ob = self.pending.get(member)
        if ob and not ob.breached:
            ob.discharged = True
            return True
        return False

    def tick(self, days_elapsed: int) -> None:
        """Advance time; an undischarged obligation past its deadline is a breach."""
        for ob in self.pending.values():
            if not ob.discharged and days_elapsed > ob.deadline_days:
                ob.breached = True
