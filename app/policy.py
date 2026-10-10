# app/policy.py
import os

class DecisionStatus:
    ALLOW = "ALLOW"
    DENY = "DENY"
    REVIEW = "REVIEW"

class SecurityPolicy:
    # Politique stricte par défaut (Best Practice DevSecOps : 0 critique, 0 high)
    # Permet une surcharge contrôlée via variables d'environnement si l'image de base l'exige.
    MAX_CRITICAL_ALLOWED = int(os.getenv("POLICY_MAX_CRITICAL", 0))
    MAX_HIGH_ALLOWED = int(os.getenv("POLICY_MAX_HIGH", 0))

    @classmethod
    def evaluate(cls, critical_count: int, high_count: int, structural_validity: bool = True) -> tuple[str, str]:
        """
        Source Unique de Vérité (SSOT) pour la prise de décision.
        Retourne un tuple : (DecisionStatus, Raison détaillée).
        """
        # Principe Fail-Closed en cas de problème de structure des preuves
        if not structural_validity:
            return DecisionStatus.DENY, "Violation de politique : Rapport de preuve absent, corrompu ou structure inattendue. Rejet par défaut (Fail-Closed)."

        if critical_count > cls.MAX_CRITICAL_ALLOWED:
            return DecisionStatus.DENY, f"Échec Quality Gate : {critical_count} vulnérabilité(s) CRITICAL détectée(s) (Seuil max autorisé : {cls.MAX_CRITICAL_ALLOWED})."

        if high_count > cls.MAX_HIGH_ALLOWED:
            return DecisionStatus.DENY, f"Échec Quality Gate : {high_count} vulnérabilité(s) HIGH détectée(s) (Seuil max autorisé : {cls.MAX_HIGH_ALLOWED})."

        return DecisionStatus.ALLOW, "Conforme : Aucune vulnérabilité bloquante détectée par rapport aux Quality Gates."