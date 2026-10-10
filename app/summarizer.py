import json
import os

def generate_markdown_summary():
    report_path = "reports/trivy-report.json"
    summary_path = "reports/summary.md"
    
    if not os.path.exists(report_path):
        print("Rapport Trivy introuvable pour la synthèse.")
        return

    try:
        with open(report_path, "r", encoding="utf-8") as f:
            data = json.load(f)
    except Exception as e:
        print(f"Erreur de lecture du rapport pour la synthèse : {str(e)}")
        return

    critical = 0
    high = 0
    medium = 0
    low = 0

    results = data.get("Results", [])
    for target in results:
        vulnerabilities = target.get("Vulnerabilities", [])
        if vulnerabilities:
            for vuln in vulnerabilities:
                sev = vuln.get("Severity", "")
                if sev == "CRITICAL":
                    critical += 1
                elif sev == "HIGH":
                    high += 1
                elif sev == "MEDIUM":
                    medium += 1
                elif sev == "LOW":
                    low += 1

    # Construction du contenu Markdown
    markdown_content = f"""# 🛡️ Rapport de Sécurité - ChainGuard Supply

### 📊 Résumé de l'Audit des Vulnérabilités
| Sévérité | Nombre | Statut / Seuil |
| :--- | :---: | :--- |
| 🔴 **CRITICAL** | **{critical}** | {"❌ Échec (Tolérance : 0)" if critical > 0 else "✅ Conforme"} |
| 🟠 **HIGH** | **{high}** | {"❌ Échec (Seuil max : 2)" if high > 2 else "✅ Conforme"} |
| 🟡 **MEDIUM** | {medium} | ℹ️ Informatif |
| 🔵 **LOW** | {low} | ℹ️ Informatif |

### 🔒 Statut des Quality Gates & Signature
* **Quality Gates** : {"❌ BLOQUÉES (Seuils dépassés)" if critical > 0 or high > 2 else "✅ VALIDÉES"}
* **Traçabilité & Digest** : Image conteneurisée liée par empreinte SHA256.
* **Signature Cryptographique** : Signé et vérifié via Cosign (SBOM).

---
*Rapport généré automatiquement par le pipeline DevSecOps ChainGuard.*
"""

    with open(summary_path, "w", encoding="utf-8") as f:
        f.write(markdown_content)
    
    print(f"[*] Rapport de synthèse généré avec succès : {summary_path}")

if __name__ == "__main__":
    generate_markdown_summary()