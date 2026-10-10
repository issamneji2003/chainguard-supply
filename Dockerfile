# Utilisation d'une image de base officielle Python allégée (Slim)
FROM python:3.10-slim

# Définition du répertoire de travail
WORKDIR /app

# Copie du code source de l'application
COPY . .

# Commande par défaut (optionnelle si tu lances via run_pipeline.py en local)
CMD ["python", "run_pipeline.py"]