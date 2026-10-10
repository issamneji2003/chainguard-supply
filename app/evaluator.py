import json
import os
from unittest.mock import patch
import unittest.mock
from app.evaluator import evaluate_artifact

def test_evaluator_blocks_critical():
    mock_data = {
        "Results": [
            {
                "Vulnerabilities": [
                    {"Severity": "CRITICAL"},
                    {"Severity": "HIGH"}
                ]
            }
        ]
    }
    
    with patch("os.path.exists", return_value=True), \
         patch("builtins.open", unittest.mock.mock_open(read_data=json.dumps(mock_data))):
        success, message = evaluate_artifact()
        assert success is False
        assert "CRITICAL" in message

def test_evaluator_blocks_too_many_high():
    # Simuler 51 failles HIGH pour dépasser le nouveau seuil MAX_HIGH_ALLOWED = 50
    vulns = [{"Severity": "HIGH"} for _ in range(51)]
    mock_data = {
        "Results": [
            {
                "Vulnerabilities": vulns
            }
        ]
    }
    
    with patch("os.path.exists", return_value=True), \
         patch("builtins.open", unittest.mock.mock_open(read_data=json.dumps(mock_data))):
        success, message = evaluate_artifact()
        assert success is False  # Doit bloquer car 51 > 50
        assert "HIGH" in message

def test_evaluator_success_within_limits():
    # Simuler un nombre acceptable de failles HIGH (ex: 10, ce qui est inférieur à 50)
    vulns = [{"Severity": "HIGH"} for _ in range(10)]
    mock_data = {
        "Results": [
            {
                "Vulnerabilities": vulns
            }
        ]
    }
    
    with patch("os.path.exists", return_value=True), \
         patch("builtins.open", unittest.mock.mock_open(read_data=json.dumps(mock_data))):
        success, message = evaluate_artifact()
        assert success is True
        assert "succès" in message