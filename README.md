# 🛡️ ChainGuard Supply

**ChainGuard Supply** est un pipeline DevSecOps et de sécurité cloud conçu pour garantir l'intégrité de bout en bout, l'authenticité cryptographique et la conformité des artefacts logiciels avant leur déploiement.

Ce projet met en œuvre des pratiques rigoureuses de sécurisation de la chaîne d'approvisionnement logicielle (*Software Supply Chain Security*).

---

## 🏗️ Architecture et Piliers de Sécurité

Le moteur de décision repose sur 5 piliers fondamentaux :

1. **Source Unique de Vérité (SSOT - `app/policy.py`)** : Centralisation des seuils de vulnérabilités acceptés (`CRITICAL`, `HIGH`) avec des statuts de décision explicites (`ALLOW`, `DENY`, `REVIEW`).
2. **Posture *Fail-Closed* (`app/evaluator.py`)** : Rejet strict et immédiat de tout artéfact si une preuve obligatoire (SBOM, rapport Trivy, métadonnées) est absente, corrompue ou mal formée.
3. **Liaison Cryptographique des Artefacts** : Utilisation d'un identifiant immuable (Digest SHA-256 du manifeste de l'image consigné dans `artifact-meta.json`) pour lier indissociablement l'image conteneur à ses preuves d'audit.
4. **Vérification Réelle des Signatures Cosign (`app/verifier.py`)** : Encapsulation sécurisée de `cosign verify-blob` pour valider cryptographiquement l'intégrité et l'authenticité des signatures de SBOM via une clé publique de confiance.
5. **Traçabilité & Rapports de Synthèse (`app/summarizer.py`)** : Génération automatique de rapports structurés (`reports/summary-report.json`) retraçant chaque décision de pipeline pour l'audit et la conformité.

---

## 📁 Structure du Projet

```text
chainguard-supply/
├── app/
│   ├── __init__.py           # Initialisation du package
│   ├── evaluator.py          # Évaluateur global des Quality Gates et des preuves
│   ├── policy.py             # Source Unique de Vérité (SSOT) & seuils de sécurité
│   ├── summarizer.py         # Génération du rapport de synthèse final
│   └── verifier.py           # Module de vérification des signatures Cosign
├── reports/                  # Dossier de consignation des preuves et métadonnées
├── tests/                    # Suite de tests unitaires robustes
│   ├── test_evaluator.py     # Tests de l'évaluateur et de la logique Fail-Closed
│   └── test_verifier.py      # Tests du module de signature Cosign
├── run_pipeline.py           # Script d'orchestration global du pipeline DevSecOps
└── README.md                 # Documentation du projet
🚀 Guide d'Utilisation
1. Prérequis
Python 3.11+

pytest (pour l'exécution des tests unitaires)

Docker (pour la récupération des digests immuables en production)

Cosign (optionnel en local si les tests utilisent des mocks, requis pour la signature réelle)

2. Exécution des tests unitaires
Le projet dispose d'une suite complète de tests validant la robustesse de chaque composant :

PowerShell
python -m pytest tests/
3. Exécution du pipeline complet
Pour lancer l'orchestration complète de l'évaluation de sécurité :

PowerShell
python run_pipeline.py
📊 Codes de Sortie du Pipeline
0 (ALLOW) : L'artéfact est sain, signé et conforme aux politiques de sécurité. Déploiement autorisé.

1 (DENY) : Violation de politique de sécurité ou échec Fail-Closed (vulnérabilités critiques, SBOM absent, signature invalide). Pipeline bloqué.

2 (REVIEW) : Situation nécessitant une revue humaine ou un arbitrage de sécurité.


---

### Comment l'utiliser :
1. Crée un fichier nommé **`README.md`** à la racine de ton projet `chainguard-supply/`.
2. Colle ce contenu dedans et sauvegarde-le.
3. Tu disposes ainsi d'une documentation claire, technique et professionnelle, idéale