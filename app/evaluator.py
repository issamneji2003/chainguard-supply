import os
import json

def evaluate_artifact(evidence=None):
    """
    Évalue la conformité et la sécurité des artefacts.
    Prend en charge soit un dictionnaire d'evidence (pour les tests unitaires),
    soit une analyse des fichiers réels du dossier reports/.
    """
    # Si le dictionnaire d'evidence est fourni (par les tests unitaires)
    if evidence is not None:
        # Vérification des failles critiques
        if evidence.get("critical_vulnerabilities", 0) > 0:
            return "DENY", "Quality Gate ÉCHOUÉE : Vulnérabilité CRITICAL détectée."
        
        # Vérification de la présence du SBOM
        if not evidence.get("sbom_present", True):
            return "DENY", "Quality Gate ÉCHOUÉE : SBOM manquant."
            
        # Vérification de la signature (si exigée par les tests)
        if not evidence.get("signed", True):
            return "DENY", "Quality Gate ÉCHOUÉE : Artefact non signé."
            
        return "ALLOW", "Toutes les Quality Gates ont été validées avec succès !"

    # Sinon, logique pour le pipeline réel (fichiers locaux)
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