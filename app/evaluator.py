import json
import os

def evaluate_supply_chain():
    sbom_path = "reports/sbom.json"
    trivy_path = "reports/trivy-report.json"
    
    # 1. Vérification du SBOM
    if not os.path.exists(sbom_path):
        return "DENY: SBOM manquant !"
        
    # 2. Vérification du rapport de vulnérabilités Trivy
    if os.path.exists(trivy_path):
        with open(trivy_path, "r") as f:
            data = json.load(f)
            
            # On parcourt les résultats pour chercher des failles CRITICAL
            results = data.get("Results", [])
            for target in results:
                vulnerabilities = target.get("Vulnerabilities", [])
                for vuln in vulnerabilities:
                    if vuln.get("Severity") == "CRITICAL":
                        return "DENY: Vulnérabilité CRITIQUE détectée !"
                        
    return "ALLOW: Supply chain sécurisée !"

if __name__ == "__main__":
    print(evaluate_supply_chain())