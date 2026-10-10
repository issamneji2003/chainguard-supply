import json
import os
import pytest
from app.evaluator import evaluate_artifact

def create_mock_report(vulnerabilities):
    os.makedirs("reports", exist_ok=True)
    report_data = {
        "Results": [
            {
                "Target": "test-container (debian)",
                "Vulnerabilities": vulnerabilities
            }
        ]
    }
    with open("reports/trivy-report.json", "w", encoding="utf-8") as f:
        json.dump(report_data, f)

def test_evaluator_success():
    # Cas 0 faille critique, 1 faille high (en dessous du seuil de 2) -> Doit réussir
    create_mock_report([
        {"VulnerabilityID": "CVE-2023-XXXX", "Severity": "HIGH"}
    ])
    success, message = evaluate_artifact()
    assert success is True

def test_evaluator_blocks_critical():
    # Cas avec 1 faille critique -> Doit bloquer
    create_mock_report([
        {"VulnerabilityID": "CVE-2023-YYYY", "Severity": "CRITICAL"}
    ])
    success, message = evaluate_artifact()
    assert success is False
    assert "CRITICAL" in message

def test_evaluator_blocks_too_many_high():
    # Cas avec 3 failles high (au-dessus du seuil max de 2) -> Doit bloquer
    create_mock_report([
        {"VulnerabilityID": "CVE-1", "Severity": "HIGH"},
        {"VulnerabilityID": "CVE-2", "Severity": "HIGH"},
        {"VulnerabilityID": "CVE-3", "Severity": "HIGH"}
    ])
    success, message = evaluate_artifact()
    assert success is False
    assert "HIGH" in message