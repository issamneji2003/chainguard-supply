# app/verifier.py
import subprocess
import os

def verify_cosign_signature(target_file: str, signature_path: str, public_key_path: str) -> tuple[bool, str]:
    """
    Vérifie cryptographiquement la signature d'un fichier (ex: SBOM) avec Cosign.
    Utilise 'cosign verify-blob' pour garantir le lien direct avec les données exactes.
    Retourne : (is_valid: bool, message: str)
    """
    # 1. Vérification de l'existence des prérequis (Fail-Closed)
    if not os.path.exists(target_file):
        return False, f"Échec vérification Cosign : Fichier cible introuvable ({target_file})."
    
    if not os.path.exists(signature_path):
        return False, f"Échec vérification Cosign : Fichier de signature absent ({signature_path})."
        
    if not os.path.exists(public_key_path):
        return False, f"Échec vérification Cosign : Clé publique de confiance absente ({public_key_path})."

    # 2. Exécution de la commande de vérification cryptographique stricte
    cmd = [
        "cosign", "verify-blob",
        "--key", public_key_path,
        "--signature", signature_path,
        target_file
    ]

    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            check=False # On récupère le code de retour manuellement pour une gestion propre
        )
        
        if result.returncode == 0:
            return True, "Vérification cryptographique Cosign réussie : Signature valide et authentique."
        else:
            error_msg = result.stderr.strip() or result.stdout.strip()
            return False, f"Échec vérification Cosign (Rejet cryptographique) : {error_msg}"
            
    except FileNotFoundError:
        return False, "Erreur système : L'exécutable 'cosign' est introuvable sur l'environnement d'exécution."
    except Exception as e:
        return False, f"Erreur interne lors de l'appel à Cosign : {str(e)}"