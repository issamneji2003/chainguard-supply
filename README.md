![ChainGuard Security Pipeline](https://github.com/issamneji2003/chainguard-supply/actions/workflows/security-pipeline.yml/badge.svg)

# ChainGuard Supply 🛡️

**ChainGuard Supply** est une solution automatisée de sécurité de la chaîne d'approvisionnement logicielle (*Software Supply Chain Security*).

## 🚀 Fonctionnalités
- **Génération de SBOM** : Détection des composants via Syft (CycloneDX JSON).
- **Analyse des vulnérabilités** : Scan automatisé via Trivy.
- **Moteur d'évaluation** : Blocage ou validation dynamique des déploiements.
- **Pipeline CI/CD** : Intégration continue avec GitHub Actions.

## 🛠️ Exécution locale
```bash
python run_pipeline.py