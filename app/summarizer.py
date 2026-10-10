# app/summarizer.py
import json
import os

def generate_summary_report(decision: str, reason: str, metadata_path: str = "reports/artifact-meta.json", output_path: str = "reports/summary-report.json") -> dict:
    """
    Génère un rapport de synthèse structuré retraçant l'évaluation de sécurité de l'artefact.
    Retourne le dictionnaire du rapport.
    """
    digest = "unknown"
    image_tag = "unknown"
    
    if os.path.exists(metadata_path):
        try:
            with open(metadata_path, "r", encoding="utf-8") as f:
                meta = json.load(f)
                digest = meta.get("digest", "unknown")
                image_tag = meta.get("image", "unknown")
        except Exception:
            pass

    report_content = {
        "image": image_tag,
        "digest": digest,
        "decision": decision,
        "reason": reason,
        "status": "PASSED" if decision == "ALLOW" else "BLOCKED"
    }

    os.makedirs(os.path.dirname(output_path), exist_ok=True)
    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(report_content, f, indent=2)

    print(f"[*] Rapport de synthèse généré avec succès : {output_path}")
    return report_content