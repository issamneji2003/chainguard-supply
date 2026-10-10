# ChainGuard Supply 🛡️

**ChainGuard Supply** est un pipeline DevSecOps complet, automatisé et axé sur la sécurité de la chaîne d'approvisionnement logicielle (*Software Supply Chain Security*). Ce projet a été développé dans le cadre du cursus d'ingénieur en Cloud et Cybersécurité à l'ESPRIT.

## 🚀 Architecture et Fonctionnalités Clés

Le projet intègre une approche de **Sécurité par Conception** (*Security by Design*) à travers plusieurs briques automatisées :

1. **Durcissement des Conteneurs (Container Hardening) :**
   - Le `Dockerfile` utilise un utilisateur non-privilégié (`appuser`) pour respecter le principe du moindre privilège et éviter toute élévation de privilèges en cas de compromission.
2. **Génération de SBOM (Software Bill of Materials) :**
   - Utilisation de **Syft** pour inventorier précisément tous les composants et dépendances de l'application au format standard CycloneDX (`reports/sbom.json`).
3. **Analyse des Vulnérabilités (Vulnerability Scanning) :**
   - Intégration de **Trivy** pour scanner dynamiquement l'image conteneurisée à la recherche de failles de sécurité et de secrets exposés (`reports/trivy-report.json`).
4. **Portes de Qualité Strictes (Quality Gates) :**
   - Un script programmatique (`app/evaluator.py`) analyse automatiquement les rapports et bloque immédiatement le pipeline (code de sortie non nul) dès qu'une vulnérabilité critique (`CRITICAL`) est détectée ou qu'un SBOM est manquant.
5. **Signature Cryptographique des Artefacts :**
   - Utilisation de **Cosign (Sigstore)** dans la CI/CD pour générer des clés éphémères et signer numériquement le SBOM (`reports/sbom.json.sig`), garantissant l'intégrité et l'authentification des livrables.
6. **Tests Unitaires & Automatisation :**
   - Validation continue du code via **Pytest** et orchestration globale via un script python unifié (`run_pipeline.py`).

---

## 📂 Structure du Projet

```text
chainguard-supply/
├── .github/
│   └── workflows/
│       └── security-pipeline.yml   # Workflow CI/CD GitHub Actions
├── app/
│   ├── __init__.py
│   └── evaluator.py                # Logique des Quality Gates
├── tests/
│   ├── __init__.py
│   └── test_evaluator.py           # Tests unitaires des portes de qualité
├── reports/                        # Dossier généré contenant SBOM, rapports Trivy et signatures
├── Dockerfile                      # Image conteneurisée sécurisée (non-root)
├── run_pipeline.py                 # Script orchestrateur local du pipeline
└── README.md                       # Documentation du projet