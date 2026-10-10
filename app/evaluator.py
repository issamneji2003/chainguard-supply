import json
import os

def evaluate_artifact(evidence):
    """Évalue un artefact en fonction des preuves fournies (signature, SBOM, vulnérabilités)."""
    if not evidence.get("sbom_present", True):
        return "DENY", "SBOM manquant"
    if not evidence.get("signed", True):
        return "DENY", "Artefact non signé"
    if evidence.get("critical_vulnerabilities", 0) > 0:
        return "DENY", "Présence de vulnérabilités critiques"
    return "ALLOW", "Artefact conforme"

def evaluate_supply_chain():
    sbom_path = "reports/sbom.json"
    trivy_path = "reports/trivy-report.json"

    if not os.path.exists(sbom_path):
        return "DENY: SBOM manquant !"

    if os.path.exists(trivy_path):
        with open(trivy_path, "r") as f:
            data = json.load(f)
        
        results = data.get("Results", [])
        for target in results:
            vulnerabilities = target.get("Vulnerabilities", [])
            for vuln in vulnerabilities:
                if vuln.get("Severity") == "CRITICAL":
                    return "DENY: Vulnérabilité CRITICAL détectée !"

    return "ALLOW: Pipeline validé avec succès !"