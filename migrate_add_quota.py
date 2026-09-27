"""
migrate_add_quota.py — Octix
================================
Ajoute les colonnes liées au quota de tokens partagé par compte
(tokens_used_today, quota_date) sur une table "user" Postgres déjà
existante.

Pourquoi ce script existe :
    db.create_all() (utilisé au chargement de app.py et dans init_db.py) ne
    modifie JAMAIS une table déjà créée : il ne crée que les tables
    manquantes. Sur un déploiement Octix existant, la table "user" existe
    déjà sans ces colonnes -- il faut donc les ajouter à la main, UNE FOIS,
    avant de déployer cette version de app.py.

    Sans cette migration, /account/quota et /account/quota/consume
    échoueront avec une erreur Postgres du type "column user.quota_date
    does not exist".

Usage :
    export POSTGRES_URL="postgresql://user:password@host:5432/dbname"
    # ou POSTGRES_URL_NON_POOLING / DATABASE_URL, comme dans app.py
    python migrate_add_quota.py

Sans danger à relancer : chaque ALTER TABLE utilise IF NOT EXISTS, donc
une deuxième exécution ne fait rien de plus.
"""

from sqlalchemy import text

from app import app, db

STATEMENTS = [
    'ALTER TABLE "user" ADD COLUMN IF NOT EXISTS tokens_used_today INTEGER NOT NULL DEFAULT 0',
    'ALTER TABLE "user" ADD COLUMN IF NOT EXISTS quota_date DATE NOT NULL DEFAULT CURRENT_DATE',
]

with app.app_context():
    for statement in STATEMENTS:
        db.session.execute(text(statement))
    db.session.commit()
    print(f"Colonnes de quota ajoutées (ou déjà présentes) sur : {app.config['SQLALCHEMY_DATABASE_URI'].split('@')[-1]}")
