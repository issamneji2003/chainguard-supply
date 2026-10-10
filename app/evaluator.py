import json
import os

def evaluate_artifact():
    report_path = "reports/trivy-report.json"
    
    if not os.path.exists(report_path):
        return False, f"Rapport Trivy introuvable à l'emplacement : {report_path}"

    try:
        with open(report_path, "r", encoding="utf-8") as f:
            data = json.load(f)
    except Exception as e:
        return False, f"Erreur lors de la lecture du rapport JSON : {str(e)}"

    critical_count = 0
    high_count = 0

    # Analyse des résultats de Trivy (par cibles / résultats)
    results = data.get("Results", [])
    for target in results:
        vulnerabilities = target.get("Vulnerabilities", [])
        if vulnerabilities:
            for vuln in vulnerabilities:
                severity = vuln.get("Severity", "")
                if severity == "CRITICAL":
                    critical_count += 1
                elif severity == "HIGH":
                    high_count += 1

    print(f"[*] Audit des Quality Gates : {critical_count} failles CRITICAL, {high_count} failles HIGH détectées.")

    # Règles des Quality Gates renforcées :
    # 1. Tolérance zéro sur les failles CRITICAL
    if critical_count > 0:
        return False, f"Échec Quality Gate : {critical_count} vulnérabilité(s) CRITICAL détectée(s). Déploiement bloqué."

    # 2. Plafond sur les failles HIGH (ajusté à 50 pour l'image de base Python Slim)
    MAX_HIGH_ALLOWED = 50
    if high_count > MAX_HIGH_ALLOWED:
        return False, f"Échec Quality Gate : {high_count} vulnérabilité(s) HIGH détectée(s) (Seuil max autorisé : {MAX_HIGH_ALLOWED}). Déploiement bloqué."

    return True, "Toutes les Quality Gates ont été validées avec succès !"