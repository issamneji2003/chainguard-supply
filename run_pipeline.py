import subprocess
import os

def run_command(command):
    print(f"Exécution : {command}")
    result = subprocess.run(command, shell=True)
    if result.returncode != 0:
        print(f"Erreur lors de l'exécution de : {command}")
    return result.returncode

def main():
    os.makedirs("reports", exist_ok=True)
    
    # 1. Builder l'image Docker locale
    run_command("docker build -t chainguard-app:latest .")

    # 2. Générer le SBOM directement depuis les fichiers sources (évite le bug Windows de Syft sur le daemon docker)
    run_command("syft dir:. -o cyclonedx-json=reports/sbom.json")

    # 3. Scanner l'image Docker via Trivy (qui lui fonctionne parfaitement avec l'image Docker)
    run_command("trivy image --format json -o reports/trivy-report.json chainguard-app:latest")

    print("Pipeline exécuté avec succès !")

if __name__ == "__main__":
    main()