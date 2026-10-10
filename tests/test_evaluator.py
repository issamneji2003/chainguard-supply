import sys
import os

# Ajoute le dossier parent au chemin pour importer app.evaluator
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '../app')))

from evaluator import evaluate_artifact

def test_evaluate_allow():
    """Vérifie qu'un artefact entièrement conforme est accepté (ALLOW)."""
    evidence = {
        "artifact_name": "app:v1",
        "signed": True,
        "sbom_present": True,
        "critical_vulnerabilities": 0,
        "moderate_vulnerabilities": 0
    }
    decision, reason = evaluate_artifact(evidence)
    assert decision == "ALLOW"

def test_evaluate_deny_unsigned():
    """Vérifie qu'un artefact non signé est refusé (DENY)."""
    evidence = {
        "artifact_name": "app:v1",
        "signed": False,
        "sbom_present": True,
        "critical_vulnerabilities": 0,
        "moderate_vulnerabilities": 0
    }
    decision, reason = evaluate_artifact(evidence)
    assert decision == "DENY"

def test_evaluate_deny_critical_vuln():
    """Vérifie qu'un artefact avec une vulnérabilité critique est refusé (DENY)."""
    evidence = {
        "artifact_name": "app:v1",
        "signed": True,
        "sbom_present": True,
        "critical_vulnerabilities": 1,
        "moderate_vulnerabilities": 0
    }
    decision, reason = evaluate_artifact(evidence)
    assert decision == "DENY"