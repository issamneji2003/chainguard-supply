# tests/test_evaluator.py
import json
import os
import pytest
from app.evaluator import evaluate_artifact
from app.policy import DecisionStatus, SecurityPolicy

@pytest.fixture(autouse=True)
def mock_cosign_verification(monkeypatch):
    """Simule une vérification Cosign valide par défaut pour les tests de l'évaluateur."""
    monkeypatch.setattr("app.evaluator.verify_cosign_signature", lambda s, sig, pub: (True, "Mocked signature valid"))

def create_mock_artifacts(sbom_content={"bomFormat": "CycloneDX"}, report_content={"Results": []}, meta_content={"image": "chainguard-app:latest", "digest": "sha256:abcdef1234567890"}, is_sbom_raw=False, is_report_raw=False, create_meta=True):
    os.makedirs("reports", exist_ok=True)
    
    # Création du fichier de métadonnées (Liaison immuable)
    meta_path = "reports/artifact-meta.json"
    if create_meta:
        with open(meta_path, "w", encoding="utf-8") as f:
            json.dump(meta_content, f)
    elif os.path.exists(meta_path):
        os.remove(meta_path)
    
    # Création du SBOM
    sbom_path = "reports/sbom.json"
    if is_sbom_raw:
        with open(sbom_path, "w", encoding="utf-8") as f:
            f.write(sbom_content)
    else:
        with open(sbom_path, "w", encoding="utf-8") as f:
            json.dump(sbom_content, f)
            
    # Création du rapport Trivy
    report_path = "reports/trivy-report.json"
    if is_report_raw:
        with open(report_path, "w", encoding="utf-8") as f:
            f.write(report_content)
    else:
        with open(report_path, "w", encoding="utf-8") as f:
            json.dump(report_content, f)

def test_evaluator_allow_clean_report():
    SecurityPolicy.MAX_CRITICAL_ALLOWED = 0
    SecurityPolicy.MAX_HIGH_ALLOWED = 0

    create_mock_artifacts()
    success, decision, reason = evaluate_artifact()
    assert success is True
    assert decision == DecisionStatus.ALLOW

def test_evaluator_deny_critical():
    create_mock_artifacts(report_content={
        "Results": [{"Vulnerabilities": [{"Severity": "CRITICAL"}]}]
    })
    success, decision, reason = evaluate_artifact()
    assert success is False
    assert decision == DecisionStatus.DENY
    assert "CRITICAL" in reason

def test_evaluator_missing_meta():
    # Cas : Métadonnées absentes -> DENY (Fail-Closed)
    create_mock_artifacts(create_meta=False)
    success, decision, reason = evaluate_artifact()
    assert success is False
    assert decision == DecisionStatus.DENY
    assert "métadonnées" in reason.lower() or "artifact-meta" in reason.lower()

def test_evaluator_missing_sbom():
    # Cas : SBOM absent -> DENY (Fail-Closed)
    create_mock_artifacts()
    if os.path.exists("reports/sbom.json"):
        os.remove("reports/sbom.json")
        
    success, decision, reason = evaluate_artifact()
    assert success is False
    assert decision == DecisionStatus.DENY
    assert "sbom" in reason.lower()

def test_evaluator_malformed_sbom():
    # Cas : SBOM mal formé -> DENY (Fail-Closed)
    create_mock_artifacts(sbom_content="{ invalid json ...", is_sbom_raw=True)
    success, decision, reason = evaluate_artifact()
    assert success is False
    assert decision == DecisionStatus.DENY

def test_evaluator_missing_report():
    # Cas : Rapport Trivy absent -> DENY (Fail-Closed)
    create_mock_artifacts()
    if os.path.exists("reports/trivy-report.json"):
        os.remove("reports/trivy-report.json")
        
    success, decision, reason = evaluate_artifact()
    assert success is False
    assert decision == DecisionStatus.DENY
    assert "trivy" in reason.lower()

def test_evaluator_malformed_json():
    # Cas : Rapport JSON mal formé -> DENY (Fail-Closed)
    create_mock_artifacts(report_content="{ invalid json content ...", is_report_raw=True)
    success, decision, reason = evaluate_artifact()
    assert success is False
    assert decision == DecisionStatus.DENY

def test_evaluator_unexpected_structure():
    # Cas : Structure JSON inattendue -> DENY
    create_mock_artifacts(report_content={"UnexpectedKey": "Data"})
    success, decision, reason = evaluate_artifact()
    assert success is False
    assert decision == DecisionStatus.DENY
    assert "structure" in reason.lower()