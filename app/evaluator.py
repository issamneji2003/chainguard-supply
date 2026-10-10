import os
import json

def evaluate_artifact():
    """
    Vérifie la présence du SBOM et analyse le rapport Trivy à la recherche de vulnérabilités CRITICAL.
    Renvoie (True, "Message") si tout est OK, ou (False, "Raison du blocage") si la Quality Gate échoue.
    """
    sbom_path = "reports/sbom.json"
    trivy_path = "reports/trivy-report.json"

    # Porte 1 : Vérification du SBOM
    if not os.path.exists(sbom_path):
        return False, "Quality Gate ÉCHOUÉE : SBOM manquant (sbom.json introuvable)."

    # Porte 2 : Analyse des vulnérabilités Trivy
    if os.path.exists(trivy_path):
        with open(trivy_path, "r", encoding="utf-8") as f:
            try:
                data = json.load(f)
            except json.JSONDecodeError:
                return False, "Quality Gate ÉCHOUÉE : Rapport Trivy corrompu ou mal formé."

        results = data.get("Results", [])
        for target in results:
            vulnerabilities = target.get("Vulnerabilities", [])
            for vuln in vulnerabilities:
                severity = vuln.get("Severity")
                if severity == "CRITICAL":
                    vuln_id = vuln.get("VulnerabilityID", "UNKNOWN")
                    pkg_name = vuln.get("PkgName", "UNKNOWN")
                    return False, f"Quality Gate ÉCHOUÉE : Vulnérabilité CRITICAL détectée [{vuln_id}] sur le paquet '{pkg_name}'."
    
    return True, "Toutes les Quality Gates ont été validées avec succès !"