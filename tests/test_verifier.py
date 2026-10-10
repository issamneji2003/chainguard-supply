# tests/test_verifier.py
import os
import pytest
from app.verifier import verify_cosign_signature

def test_verify_missing_files():
    # Cas : Fichiers absents -> Doit retourner False (Fail-Closed)
    valid, msg = verify_cosign_signature("non_existent.json", "non_existent.sig", "non_existent.pub")
    assert valid is False
    assert "introuvable" in msg.lower() or "absent" in msg.lower()

def test_verify_with_mocked_subprocess(monkeypatch):
    # Simulation d'un échec de vérification cryptographique par Cosign
    class MockCompletedProcess:
        returncode = 1
        stderr = "error: signature verification failed"
        stdout = ""

    monkeypatch.setattr("subprocess.run", lambda *args, **kwargs: MockCompletedProcess())
    
    os.makedirs("reports", exist_ok=True)
    with open("reports/dummy.json", "w", encoding="utf-8") as f:
        f.write("{}")
    with open("reports/dummy.sig", "w", encoding="utf-8") as f:
        f.write("sig")
    with open("cosign.pub", "w", encoding="utf-8") as f:
        f.write("pub")

    valid, msg = verify_cosign_signature("reports/dummy.json", "reports/dummy.sig", "cosign.pub")
    assert valid is False
    assert "échec" in msg.lower() or "failed" in msg.lower() or "rejet" in msg.lower()

    # Nettoyage
    for p in ["reports/dummy.json", "reports/dummy.sig", "cosign.pub"]:
        if os.path.exists(p):
            os.remove(p)