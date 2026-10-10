import json
import os
import pytest
from app.evaluator import evaluate_artifact

def create_mock_report(vulnerabilities):
    os.makedirs("reports", exist_ok=True)
    report_data = {
        "Results": [
            {
                "Vulnerabilities": vulnerabilities
            }
        ]
    }
    with open("reports/trivy-report.json", "w", encoding="utf-8") as f:
        json.dump(report_data, f)

def test_evaluator_blocks_critical():
    create_mock_report([
        {"VulnerabilityID": "CVE-CRIT", "Severity": "CRITICAL"}
    ])
    success, message = evaluate_artifact()
    assert success is False
    assert "CRITICAL" in message

def test_evaluator_blocks_too_many_high():
    # Cas avec 51 failles high (au-dessus du nouveau seuil max de 50) -> Doit bloquer
    vulns = [{"VulnerabilityID": f"CVE-{i}", "Severity": "HIGH"} for i in range(51)]
    create_mock_report(vulns)
    success, message = evaluate_artifact()
    assert success is False
    assert "HIGH" in message

def test_evaluator_passes_within_limit():
    # Cas avec 10 failles high (en dessous du seuil de 50) -> Doit passer
    vulns = [{"VulnerabilityID": f"CVE-{i}", "Severity": "HIGH"} for i in range(10)]
    create_mock_report(vulns)
    success, message = evaluate_artifact()
    assert success is True