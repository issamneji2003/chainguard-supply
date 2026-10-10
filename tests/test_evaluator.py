import sys
import os

# Ajoute le dossier parent au chemin
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from app.evaluator import evaluate_artifact

def test_evaluate_allow():
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
    evidence = {
        "artifact_name": "app:v1",
        "signed": True,
        "sbom_present": True,
        "critical_vulnerabilities": 1,
        "moderate_vulnerabilities": 0
    }
    decision, reason = evaluate_artifact(evidence)
    assert decision == "DENY"