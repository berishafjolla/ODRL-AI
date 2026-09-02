"""Automated tests for the ODRL-AI reference implementation.

They check the taxonomy classification, the permit and deny decisions across
the UCON phases, prohibition and constraint handling, and the full revocation
lifecycle, reproducing the outcomes of Table 3 in the paper.

Run with:  python -m unittest -v
"""
import json
import os
import unittest

from odrl_ai import (
    Policy, decide, route_admission, ObligationManager,
    INCORPORATION, PERSISTENCE, PHASE, is_incorporating,
)

HERE = os.path.dirname(__file__)
RETRIEVAL_ONLY = Policy.from_file(os.path.join(HERE, "policies", "retrieval_only.json"))
FINE_TUNE = Policy.from_file(os.path.join(HERE, "policies", "fine_tune.json"))


class TestTaxonomy(unittest.TestCase):
    def test_incorporating_actions(self):
        self.assertTrue(is_incorporating("Train"))
        self.assertTrue(is_incorporating("FineTune"))
        self.assertTrue(is_incorporating("aia:Distill"))  # indirect counts

    def test_non_incorporating_actions(self):
        for a in ("Retrieve", "Evaluate", "Embed", "Synthesize"):
            self.assertFalse(is_incorporating(a))

    def test_persistence_classification(self):
        self.assertEqual(PERSISTENCE["Train"], "weights")
        self.assertEqual(PERSISTENCE["Embed"], "index")
        self.assertEqual(PERSISTENCE["Synthesize"], "dataset")
        self.assertEqual(PERSISTENCE["Retrieve"], "none")

    def test_ucon_phases(self):
        self.assertEqual(PHASE["Retrieve"], "ongoing")
        self.assertEqual(PHASE["Train"], "pre")
        self.assertEqual(PHASE["FineTune"], "pre")


class TestAdmission(unittest.TestCase):
    def test_retrieval_only_finetune_denied(self):
        d = decide(RETRIEVAL_ONLY, "FineTune")
        self.assertFalse(d.permitted)
        self.assertEqual(d.reason, "prohibited")
        self.assertEqual(route_admission(RETRIEVAL_ONLY)[0], "retrieval_store")

    def test_retrieval_only_distill_prohibited(self):
        self.assertFalse(decide(RETRIEVAL_ONLY, "Distill"))

    def test_finetune_member_admitted_to_corpus(self):
        d = decide(FINE_TUNE, "FineTune", {"modelClass": "domain-specific"})
        self.assertTrue(d.permitted)
        placement, duties = route_admission(FINE_TUNE)
        self.assertEqual(placement, "corpus")
        self.assertIn("RecordProvenance", duties)
        self.assertIn("NotifyDownstream", duties)

    def test_finetune_wrong_modelclass_denied(self):
        d = decide(FINE_TUNE, "FineTune", {"modelClass": "general-purpose"})
        self.assertFalse(d.permitted)
        self.assertEqual(d.reason, "constraint modelClass")


class TestOngoing(unittest.TestCase):
    def test_retrieve_advisory_eu_permitted(self):
        d = decide(RETRIEVAL_ONLY, "Retrieve",
                   {"modelPurpose": "aia:SectorAdvisory", "deploymentJurisdiction": "EU"})
        self.assertTrue(d.permitted)
        self.assertEqual(d.phase, "ongoing")
        self.assertIn("RecordProvenance", d.duties)

    def test_retrieve_riskscoring_denied_on_purpose(self):
        d = decide(RETRIEVAL_ONLY, "Retrieve",
                   {"modelPurpose": "aia:RiskScoring", "deploymentJurisdiction": "EU"})
        self.assertFalse(d.permitted)
        self.assertEqual(d.reason, "constraint modelPurpose")

    def test_retrieve_non_eu_denied_on_jurisdiction(self):
        d = decide(RETRIEVAL_ONLY, "Retrieve",
                   {"modelPurpose": "aia:SectorAdvisory", "deploymentJurisdiction": "US"})
        self.assertFalse(d.permitted)
        self.assertEqual(d.reason, "constraint deploymentJurisdiction")


class TestRevocation(unittest.TestCase):
    def test_finetune_member_revocation(self):
        mgr = ObligationManager()
        mgr.admit("m1", "corpus")
        out = mgr.revoke("m1", permitted_incorporating=True)
        self.assertIn("excluded from next training run", out)
        self.assertNotIn("m1", mgr.indexed)
        self.assertTrue(mgr.attest("m1"))
        self.assertTrue(mgr.pending["m1"].discharged)

    def test_retrieval_only_revocation_deindex_only(self):
        mgr = ObligationManager()
        mgr.admit("m2", "retrieval_store")
        out = mgr.revoke("m2", permitted_incorporating=False)
        self.assertEqual(out, "de-index only")
        self.assertNotIn("m2", mgr.indexed)
        self.assertNotIn("m2", mgr.pending)

    def test_breach_when_deadline_passes(self):
        mgr = ObligationManager()
        mgr.revoke("m3", permitted_incorporating=True, deadline_days=30)
        mgr.tick(31)
        self.assertTrue(mgr.pending["m3"].breached)
        self.assertFalse(mgr.attest("m3"))  # cannot discharge after breach


class TestODRLConformance(unittest.TestCase):
    """The shipped policies must satisfy the ODRL 2.2 requirements for an
    Agreement: a uid on the Policy, and one assigner and one assignee."""

    def test_shipped_policies_are_conformant_agreements(self):
        for name in ("retrieval_only.json", "fine_tune.json"):
            with open(os.path.join(HERE, "policies", name), encoding="utf-8") as fh:
                doc = json.load(fh)
            self.assertEqual(doc["@type"], "Agreement", name)
            for prop in ("uid", "assigner", "assignee"):
                self.assertIn(prop, doc, f"{name} is missing {prop}")


if __name__ == "__main__":
    unittest.main()
