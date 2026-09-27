"""
migrate_add_api_key.py — Octix
================================
Ajoute les colonnes liées à la clé API (api_key_hash, api_key_preview,
api_key_created_at) sur une table "user" Postgres déjà existante.

Pourquoi ce script existe :
    db.create_all() (utilisé au chargement de app.py et dans init_db.py) ne
    modifie JAMAIS une table déjà créée : il ne crée que les tables
    manquantes. Sur un déploiement Octix existant, la table "user" existe
    déjà sans ces colonnes -- il faut donc les ajouter à la main, UNE FOIS,
    avant de déployer cette version de app.py.

    Sans cette migration, /account/api-key et /verify-api-key échoueront
    avec une erreur Postgres du type "column user.api_key_hash does not
    exist".

Usage :
    export POSTGRES_URL="postgresql://user:password@host:5432/dbname"
    # ou POSTGRES_URL_NON_POOLING / DATABASE_URL, comme dans app.py
    python migrate_add_api_key.py

Sans danger à relancer : chaque ALTER TABLE utilise IF NOT EXISTS, donc
une deuxième exécution ne fait rien de plus.
"""

from sqlalchemy import text

from app import app, db

STATEMENTS = [
    'ALTER TABLE "user" ADD COLUMN IF NOT EXISTS api_key_hash VARCHAR(64) UNIQUE',
    'ALTER TABLE "user" ADD COLUMN IF NOT EXISTS api_key_preview VARCHAR(20)',
    'ALTER TABLE "user" ADD COLUMN IF NOT EXISTS api_key_created_at TIMESTAMP',
]

with app.app_context():
    for statement in STATEMENTS:
        db.session.execute(text(statement))
    db.session.commit()
    print(f"Colonnes clé API ajoutées (ou déjà présentes) sur : {app.config['SQLALCHEMY_DATABASE_URI'].split('@')[-1]}")
