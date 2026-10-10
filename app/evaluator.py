# app/evaluator.py
import json
import os
from app.policy import SecurityPolicy, DecisionStatus
from app.verifier import verify_cosign_signature

def evaluate_artifact() -> tuple[bool, str, str]:
    """
    Exécute l'évaluation des Quality Gates, valide l'intégrité des preuves,
    la liaison immuable et la signature cryptographique Cosign.
    Retourne : (is_success: bool, decision: str, reason: str)
    """
    meta_path = "reports/artifact-meta.json"
    sbom_path = "reports/sbom.json"
    sig_path = "reports/sbom.json.sig"
    report_path = "reports/trivy-report.json"
    pub_key_path = "cosign.pub"
    
    # 1. Validation de la présence des métadonnées de l'artefact (Liaison immuable)
    if not os.path.exists(meta_path):
        decision, reason = SecurityPolicy.evaluate(0, 0, structural_validity=False)
        return False, decision, "Violation Fail-Closed : Métadonnées d'artefact (artifact-meta.json) absentes."

    try:
        with open(meta_path, "r", encoding="utf-8") as f:
            meta_data = json.load(f)
        if not isinstance(meta_data, dict) or "digest" not in meta_data:
            raise ValueError("Le fichier de métadonnées est incomplet ou ne contient pas de digest.")
    except Exception as e:
        decision, reason = SecurityPolicy.evaluate(0, 0, structural_validity=False)
        return False, decision, f"Violation Fail-Closed : Erreur de lecture des métadonnées d'artefact ({str(e)})."

    # 2. Validation de la présence du SBOM (Preuve d'inventaire obligatoire)
    if not os.path.exists(sbom_path):
        decision, reason = SecurityPolicy.evaluate(0, 0, structural_validity=False)
        return False, decision, "Violation Fail-Closed : SBOM introuvable (reports/sbom.json manquant)."

    try:
        with open(sbom_path, "r", encoding="utf-8") as f:
            sbom_data = json.load(f)
        if not isinstance(sbom_data, dict):
            raise ValueError("Le contenu du SBOM n'est pas un dictionnaire JSON valide.")
    except Exception as e:
        decision, reason = SecurityPolicy.evaluate(0, 0, structural_validity=False)
        return False, decision, f"Violation Fail-Closed : SBOM corrompu ou mal formé ({str(e)})."

    # 3. Vérification cryptographique de la signature du SBOM avec Cosign (Fail-Closed)
    sig_valid, sig_message = verify_cosign_signature(sbom_path, sig_path, pub_key_path)
    if not sig_valid:
        decision, reason = SecurityPolicy.evaluate(0, 0, structural_validity=False)
        return False, decision, f"Violation Fail-Closed (Cosign) : {sig_message}"

    # 4. Validation de la présence du rapport Trivy (Preuve de scan obligatoire)
    if not os.path.exists(report_path):
        decision, reason = SecurityPolicy.evaluate(0, 0, structural_validity=False)
        return False, decision, f"Violation Fail-Closed : Rapport Trivy introuvable ({report_path} manquant)."

    try:
        with open(report_path, "r", encoding="utf-8") as f:
            data = json.load(f)
    except Exception as e:
        decision, reason = SecurityPolicy.evaluate(0, 0, structural_validity=False)
        return False, decision, f"Violation Fail-Closed : Erreur de lecture/parsing JSON du rapport Trivy ({str(e)})."

    # 5. Validation de la structure minimale attendue du rapport Trivy
    if not isinstance(data, dict) or "Results" not in data:
        decision, reason = SecurityPolicy.evaluate(0, 0, structural_validity=False)
        return False, decision, "Violation Fail-Closed : Structure du rapport Trivy invalide (clé 'Results' absente)."

    critical_count = 0
    high_count = 0

    results = data.get("Results", [])
    for target in results:
        vulnerabilities = target.get("Vulnerabilities", [])
        if vulnerabilities and isinstance(vulnerabilities, list):
            for vuln in vulnerabilities:
                severity = vuln.get("Severity", "")
                if severity == "CRITICAL":
                    critical_count += 1
                elif severity == "HIGH":
                    high_count += 1

    print(f"[*] Audit des Quality Gates (Artefact SHA: {meta_data.get('digest')}) : {critical_count} failles CRITICAL, {high_count} failles HIGH détectées.")

    # 6. Application de la Source Unique de Vérité (SSOT)
    decision, reason = SecurityPolicy.evaluate(critical_count, high_count, structural_validity=True)
    is_success = (decision == DecisionStatus.ALLOW)

    return is_success, decision, reason