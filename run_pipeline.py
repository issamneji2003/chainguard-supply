import subprocess
import os
import sys

# Import de la fonction d'évaluation (assure-toi que PYTHONPATH=. est actif)
from app.evaluator import evaluate_artifact

def run_command(command):
    print(f"Exécution : {command}")
    result = subprocess.run(command, shell=True)
    if result.returncode != 0:
        print(f"Erreur lors de l'exécution de : {command}")
    return result.returncode

def main():
    os.makedirs("reports", exist_ok=True)
    
    # 1. Build de l'image Docker sécurisée
    if run_command("docker build -t chainguard-app:latest .") != 0:
        print("Erreur : Échec du build Docker.")
        sys.exit(1)

    # 2. Génération du SBOM via Syft
    if run_command("syft dir:. -o cyclonedx-json=reports/sbom.json") != 0:
        print("Erreur : Échec de la génération du SBOM.")
        sys.exit(1)

    # 3. Scan des vulnérabilités via Trivy
    if run_command("trivy image --format json -o reports/trivy-report.json chainguard-app:latest") != 0:
        print("Erreur : Échec du scan Trivy.")
        sys.exit(1)

    # 4. Évaluation stricte via les Quality Gates
    print("Évaluation des Quality Gates en cours...")
    success, message = evaluate_artifact()
    
    if not success:
        print(f"\n[BLOQUÉ] {message}")
        sys.exit(2) # Code d'erreur non nul pour stopper le pipeline CI/CD
    else:
        print(f"\n[SUCCÈS] {message}")
        print("Pipeline exécuté et validé avec succès !")

if __name__ == "__main__":
    main()