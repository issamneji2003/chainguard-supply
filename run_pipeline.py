import subprocess
import os
import sys
import json

from app.evaluator import evaluate_artifact
from app.summarizer import generate_markdown_summary

def run_command(command):
    print(f"Exécution : {command}")
    result = subprocess.run(command, shell=True, capture_output=True, text=True, encoding='utf-8', errors='ignore')
    print(result.stdout)
    if result.returncode != 0:
        print(f"Erreur : {result.stderr}")
    return result.returncode, result.stdout

def main():
    os.makedirs("reports", exist_ok=True)
    
    # 1. Build de l'image Docker sécurisée
    code, _ = run_command("docker build -t chainguard-app:latest .")
    if code != 0:
        print("Erreur : Échec du build Docker.")
        sys.exit(1)

    # 2. Récupération de l'ID unique de l'image pour la traçabilité
    _, output_id = run_command("docker images --no-trunc --quiet chainguard-app:latest")
    image_digest = f"sha256:{output_id.strip()}"
    print(f"[*] Artefact lié au Digest : {image_digest}")

    # 3. Génération du SBOM via Trivy
    if subprocess.run("trivy image --format cyclonedx -o reports/sbom.json chainguard-app:latest", shell=True).returncode != 0:
        print("Erreur : Échec de la génération du SBOM.")
        sys.exit(1)

    # 4. Scan des vulnérabilités via Trivy
    if subprocess.run("trivy image --format json -o reports/trivy-report.json chainguard-app:latest", shell=True).returncode != 0:
        print("Erreur : Échec du scan Trivy.")
        sys.exit(1)

    # 5. Évaluation stricte via les Quality Gates
    print("Évaluation des Quality Gates en cours...")
    success, message = evaluate_artifact()
    
    # Génération du rapport de synthèse Markdown dans tous les cas
    generate_markdown_summary()

    if not success:
        print(f"\n[BLOQUÉ] {message}")
        sys.exit(2)
    else:
        print(f"\n[SUCCÈS] {message}")

    # 6. Gestion de Cosign (Signature et Vérification)
    if subprocess.run("cosign version", shell=True, capture_output=True).returncode == 0:
        if not os.path.exists("cosign.key"):
            run_command("cosign generate-key-pair --output-key-prefix cosign")

        print("Signature cryptographique du SBOM en cours...")
        code, _ = run_command("cosign sign-blob --key cosign.key reports/sbom.json --output-signature reports/sbom.json.sig --yes")
        if code != 0:
            print("Erreur : Échec de la signature du SBOM.")
            sys.exit(1)

        print("Vérification de la signature cryptographique du SBOM...")
        code, _ = run_command("cosign verify-blob --key cosign.pub --signature reports/sbom.json.sig reports/sbom.json")
        if code != 0:
            print("Erreur : La vérification de la signature du SBOM a échoué !")
            sys.exit(3)
        else:
            print("[SUCCÈS] La signature cryptographique du SBOM est valide et authentique.")
    else:
        print("[AVERTISSEMENT] Cosign n'est pas détecté localement. Signature gérée par GitHub Actions.")

    print("\nPipeline complet exécuté et validé avec succès !")

if __name__ == "__main__":
    main()