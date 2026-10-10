import subprocess
import sys

def run_step(command, description):
    print(f"\n--> [ETAPE] {description}...")
    result = subprocess.run(command, shell=True)
    if result.returncode != 0:
        print(f"❌ Échec lors de : {description}")
        sys.exit(1)

print("=== DEBUT DE LA CHAINE DE SECURITE CHAINGUARD ===")

# 1. Génération du SBOM avec Syft
run_step("syft dir:. -o cyclonedx-json=reports/sbom.json", "Génération du SBOM")

# 2. Scan de vulnérabilités avec Trivy
run_step("trivy sbom --format json --output reports/trivy-report.json reports/sbom.json", "Scan de sécurité Trivy")

# 3. Évaluation par le moteur de décision Python
run_step("python app/evaluator.py", "Contrôle de sécurité")

print("\n=== PIPELINE TERMINE AVEC SUCCES ===")