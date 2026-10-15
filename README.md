# ODRL-AI reference implementation

A minimal, dependency-free engine for the ODRL-AI policy profile. It parses
ODRL-AI policies (JSON-LD), decides each request in the UCON phase appropriate
to its action, routes contributed datasets at admission, and manages the
revocation obligations.

It is a proof that the AI-specific evaluation logic a generic ODRL enforcement
engine (for example ODRE, or a data-space connector) would need is small. It is
**not** a data space, a connector, or production enforcement infrastructure: it
operates on policies and simulated requests, not on real data or models.

Python 3.12, standard library only.

## Files
- `odrl_ai.py` - the engine: action taxonomy (Table 1), policy parser,
  phase-routed evaluator with deny-overrides and constraint satisfaction,
  admission routing, and the revocation obligation manager.
- `policies/retrieval_only.json` - a contributor permitting only retrieval.
- `policies/fine_tune.json` - a contributor additionally permitting fine-tuning.
  Its revocation duty (`aia:AttestDeletion`) carries the profile refinements
  `aia:trigger` (`aia:RevocationEvent`), `aia:deadline` (`P30D`) and
  `aia:discharge` (`aia:NonInclusionAttestation`), from which the engine reads
  the deadline.
- `scenario.py` - runs the Section 4.6 demonstration end to end and prints the
  Table 2 outcomes.

Both policies are ODRL 2.2 JSON-LD: they use the W3C ODRL context, bind the
`aia:` prefix to the profile namespace `https://w3id.org/odrl-ai#`, and declare
the profile with `"profile": "https://w3id.org/odrl-ai"`, as ODRL 2.2 requires
of a policy that conforms to a profile. The profile IRI is an identifier; it
need not resolve.
- `test_odrl_ai.py` - 15 automated tests: taxonomy classification, permit and
  deny decisions across phases, prohibition and constraint handling, the
  full revocation lifecycle, and the conformance of the shipped policies to the
  ODRL 2.2 requirements for an Agreement (uid, assigner, assignee).

## Run
```
python -m unittest -v     # run the tests
python scenario.py        # reproduce the Table 2 outcomes
```

## What it shows
The engine is 259 lines. That it suffices to enforce the profile across
the pre-use, ongoing-use and post-use phases is the point: the layer an existing
ODRL enforcement engine must add to honour AI-specific terms is minimal.
