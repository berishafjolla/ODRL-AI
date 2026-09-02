"""Execute the Section 7 demonstration end to end and print the Table 3 outcomes.

A shared AI advisory service is fed by two contributors: one permitting only
retrieval, one additionally permitting fine-tuning. The script runs admission,
inference-time requests, and revocation, and prints what the engine decides.

Run with:  python scenario.py
"""
import os

from odrl_ai import Policy, decide, route_admission, ObligationManager

HERE = os.path.dirname(__file__)
retrieval_only = Policy.from_file(os.path.join(HERE, "policies", "retrieval_only.json"))
fine_tune = Policy.from_file(os.path.join(HERE, "policies", "fine_tune.json"))

mgr = ObligationManager()


def show(step, request, outcome):
    print(f"  {step:<34} {request:<26} {outcome}")


print("Lifecycle step                     Request / event            Engine outcome")
print("-" * 92)

# --- Admission (pre-authorisation) ---
d = decide(retrieval_only, "FineTune")
placement, _ = route_admission(retrieval_only)
mgr.admit("retrieval-only-member", placement)
show("Admission (retrieval-only member)", "FineTune",
     f"Denied ({d.reason}) -> {placement}")

d = decide(fine_tune, "FineTune", {"modelClass": "domain-specific"})
placement, duties = route_admission(fine_tune)
mgr.admit("fine-tune-member", placement)
show("Admission (fine-tune member)", "FineTune, domain-specific",
     f"Permitted -> {placement}; duties {', '.join(duties)}")

# --- Ongoing use (ongoing authorisation at the retrieval gateway) ---
d = decide(retrieval_only, "Retrieve",
           {"modelPurpose": "aia:SectorAdvisory", "deploymentJurisdiction": "EU"})
show("Ongoing use", "Retrieve, advisory, EU",
     "Permitted" if d else f"Denied ({d.reason})")

d = decide(retrieval_only, "Retrieve",
           {"modelPurpose": "aia:RiskScoring", "deploymentJurisdiction": "EU"})
show("Ongoing use", "Retrieve, risk-scoring, EU",
     "Permitted" if d else f"Denied ({d.reason})")

d = decide(retrieval_only, "Retrieve",
           {"modelPurpose": "aia:SectorAdvisory", "deploymentJurisdiction": "US"})
show("Ongoing use", "Retrieve, advisory, US",
     "Permitted" if d else f"Denied ({d.reason})")

# --- Revocation (post-use; attribute mutation) ---
out = mgr.revoke("fine-tune-member", permitted_incorporating=True)
show("Revocation (fine-tune member)", "RevocationEvent", out)
mgr.attest("fine-tune-member")

out = mgr.revoke("retrieval-only-member", permitted_incorporating=False)
show("Revocation (retrieval-only member)", "RevocationEvent", out)
