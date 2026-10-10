# 🛡️ ChainGuard Supply

[![ChainGuard Supply CI/CD Pipeline](https://github.com/issamneji2003/chainguard-supply/actions/workflows/pipeline.yml/badge.svg)](https://github.com/issamneji2003/chainguard-supply/actions/workflows/pipeline.yml)
![Python Version](https://img.shields.io/badge/python-3.11%2B-blue.svg)
![Security Posture](https://img.shields.io/badge/security-Fail--Closed-red.svg)
![License](https://img.shields.io/badge/license-MIT-green.svg)

**ChainGuard Supply** est une plateforme DevSecOps et un pipeline de sécurité pour la chaîne d'approvisionnement logicielle (*Software Supply Chain Security*). Conçu pour des environnements Cloud-Native rigoureux, il automatise la validation de l'intégrité, l'authentification cryptographique et le respect des portes de qualité (*Quality Gates*) des artefacts logiciels avant tout déploiement en production.

---

## 🏗️ Architecture et Piliers de Sécurité

Le moteur de décision s'articule autour de 5 piliers fondamentaux implémentés dans le code :

1. **Source Unique de Vérité (SSOT - `app/policy.py`)** : Centralisation stricte des seuils de tolérance aux vulnérabilités (`CRITICAL`, `HIGH`) et définition des statuts de gouvernance (`ALLOW`, `DENY`, `REVIEW`).
2. **Posture *Fail-Closed* (`app/evaluator.py`)** : Rejet automatique, immédiat et sécurisé de tout artefact si une preuve obligatoire (SBOM, rapport Trivy, métadonnées, signature) est manquante, altérée ou malformée.
3. **Liaison Cryptographique des Artefacts** : Utilisation d'un identifiant immuable (Digest SHA-256 du manifeste de l'image Docker) pour lier indissociablement l'image à ses preuves d'audit et éviter toute substitution d'artefact.
4. **Vérification Réelle des Signatures Cosign (`app/verifier.py`)** : Encapsulation sécurisée de l'outil `cosign verify-blob` pour garantir l'intégrité et l'authenticité cryptographique des signatures de SBOM à l'aide d'une clé publique de confiance (`cosign.pub`).
5. **Traçabilité et Rapports de Synthèse (`app/summarizer.py`)** : Génération systématique de rapports d'audit structurés (`reports/summary-report.json`) retraçant chaque évaluation pour la conformité et la gouvernance.

---

## 🚀 Pipeline CI/CD (GitHub Actions)

Le projet intègre un pipeline d'intégration continue entièrement automatisé (`.github/workflows/pipeline.yml`) basé sur les standards de sécurité modernes (exécuté sur `ubuntu-latest`) :

* **Validation Unitaire** : Exécution de la suite de tests automatisés via `pytest`.
* **Build Conteneurisé** : Construction locale de l'image Docker (`chainguard-app:latest`) pour extraction et vérification de son empreinte immuable.
* **Sécurité & Signature Non-Interactive** : Génération de paires de clés éphémères et signature numérique des preuves SBOM via **Sigstore Cosign**.
* **Publication des Artefacts** : Archivage sécurisé du rapport de synthèse final via `actions/upload-artifact@v4`.

---

## 📁 Structure du Projet

```text
chainguard-supply/
├── .github/
│   └── workflows/
│       └── pipeline.yml          # Pipeline CI/CD GitHub Actions (v4)
├── app/
│   ├── __init__.py               # Initialisation du package applicatif
│   ├── evaluator.py              # Évaluateur global des Quality Gates et règles Fail-Closed
│   ├── policy.py                 # Source Unique de Vérité (SSOT) & seuils de sécurité
│   ├── summarizer.py             # Générateur de rapports de synthèse (JSON)
│   └── verifier.py               # Module de vérification des signatures Cosign
├── reports/                      # Dossier de consignation des preuves et métadonnées
├── tests/                        # Suite de tests unitaires
│   ├── test_evaluator.py         # Tests unitaires de l'évaluateur et de la logique Fail-Closed
│   └── test_verifier.py          # Tests unitaires du module de signature Cosign
├── Dockerfile                    # Configuration de conteneurisation de référence
├── run_pipeline.py               # Script d'orchestration global du pipeline DevSecOps
└── README.md                     # Documentation technique du projet
🛠️ Guide d'Utilisation
1. Prérequis techniques
Python 3.11+

Docker (pour l'évaluation des digests immuables en environnement local)

Cosign (requis pour la signature et la vérification cryptographique réelle)

Pytest (pour l'exécution des tests unitaires)

2. Exécution locale de la suite de tests
Pour valider la robustesse de chaque composant de sécurité :

PowerShell
python -m pytest tests/
3. Exécution locale du pipeline d'orchestration
Pour lancer l'évaluation complète de la chaîne d'approvisionnement :

PowerShell
python run_pipeline.py
📊 Codes de Sortie et Politique d'Orchestration
Le script de pipeline retourne des codes de sortie normalisés pour s'intégrer dans des chaînes d'automatisation d'entreprise :

0 (ALLOW) : L'artefact est validé, authentifié, signé et conforme aux politiques de sécurité. Déploiement autorisé.

1 (DENY) : Violation de la politique de sécurité ou déclenchement du mode Fail-Closed (vulnérabilités critiques détectées, SBOM manquant, signature invalide). Le pipeline est immédiatement bloqué.

2 (REVIEW) : Situation ambigüe nécessitant une revue humaine ou une dérogation de sécurité.

## 🧪 Démonstration & Scénarios de Sécurité

* **Quand tout va bien (`ALLOW` - Code 0) :** L'image Docker est construite, les rapports et la signature cryptographique sont valides. Le pipeline autorise le déploiement.
* **En cas d'alerte (`DENY` - Code 1) :** Si un élément de sécurité manque ou est invalide, le système bloque tout immédiatement (règle *Fail-Closed*).

👤 Auteur
Issam Neji — Étudiant en ingénierie informatique à ESPRIT (Spécialisation cybersecurity & Cloud).

Dépôt GitHub : issamneji2003/chainguard-supply