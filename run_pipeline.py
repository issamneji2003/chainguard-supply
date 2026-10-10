# run_pipeline.py
import subprocess
import json
import os
import sys
from app.evaluator import evaluate_artifact
from app.policy import DecisionStatus
from app.summarizer import generate_summary_report

def get_docker_image_digest(image_name: str) -> str:
    """
    Récupère l'identifiant immuable (Digest SHA-256) de l'image Docker construite.
    """
    try:
        result = subprocess.run(
            ["docker", "inspect", "--format='{{index .RepoDigests 0}}'", image_name],
            capture_output=True,
            text=True,
            check=True
        )
        digest = result.stdout.strip().strip("'")
        if "@sha256:" in digest:
            return digest.split("@")[1]
    except Exception:
        try:
            result = subprocess.run(
                ["docker", "inspect", "--format='{{.Id}}'", image_name],
                capture_output=True,
                text=True,
                check=True
            )
            return result.stdout.strip().strip("'")
        except Exception as e:
            print(f"[-] Erreur critique lors de la récupération du digest de l'image : {e}")
            return ""
    return ""

def main():
    print("==================================================")
    print("[*] Lancement du pipeline ChainGuard Supply - DevSecOps")
    print("==================================================")
    
    image_tag = "chainguard-app:latest"
    
    # 1. Capture du digest immuable de l'artefact évalué
    digest = get_docker_image_digest(image_tag)
    if not digest:
        print("[-] Violation d'intégrité : Impossible de lier l'artefact à un identifiant immuable.")
        generate_summary_report("DENY", "Violation Fail-Closed : Impossible de récupérer le digest de l'image.")
        sys.exit(1)
        
    print(f"[+] Artefact identifié par son empreinte immuable : {digest}")
    
    # Consignation du manifeste de l'artefact
    os.makedirs("reports", exist_ok=True)
    meta_path = "reports/artifact-meta.json"
    with open(meta_path, "w", encoding="utf-8") as f:
        json.dump({"image": image_tag, "digest": digest}, f, indent=2)

    # 2. Exécution de l'évaluation unifiée (Politique SSOT + Fail-Closed + Cosign)
    is_success, decision, reason = evaluate_artifact()
    
    print(f"[*] Décision finale calculée : {decision}")
    print(f"[*] Motif : {reason}")

    # 3. Génération du rapport de synthèse final
    generate_summary_report(decision, reason)

    # 4. Sortie normalisée du pipeline
    if decision == DecisionStatus.ALLOW:
        print("[+] Pipeline validé avec succès : Déploiement autorisé.")
        sys.exit(0)
    elif decision == DecisionStatus.REVIEW:
        print("[!] Statut nécessitant une revue humaine (REVIEW).")
        sys.exit(2)
    else:
        print("[-] Pipeline bloqué par la politique de sécurité (DENY).")
        sys.exit(1)

if __name__ == "__main__":
    main()