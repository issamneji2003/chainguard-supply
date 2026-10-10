FROM python:3.10-slim

# Création d'un utilisateur non-privilégié pour des raisons de sécurité
RUN useradd -m -u 1000 appuser

WORKDIR /app

# Copie des dépendances et du code source
COPY . /app

# Installation de pytest (ou des dépendances du projet)
RUN pip install --no-cache-dir pytest

# Attribution de la propriété du dossier au nouvel utilisateur
RUN chown -R appuser:appuser /app

# Passage à l'utilisateur non-privilégié
USER appuser

# Exposition du port (si nécessaire) et commande par défaut
CMD ["python", "run_pipeline.py"]