"""
migrate_add_plans.py — Octix
================================
Ajoute les colonnes du système de forfaits (plan, lab, suivi d'activité
Opsiom, cache de progression) sur la table "user" Postgres existante.

À lancer UNE FOIS avant de déployer cette version de app.py (db.create_all()
ne modifie jamais une table déjà créée — voir migrate_add_quota.py).
Sans danger à relancer : IF NOT EXISTS partout. Les comptes existants
démarrent en forfait "free".

Usage :
    export POSTGRES_URL="postgresql://user:password@host:5432/dbname"
    python migrate_add_plans.py
"""
from sqlalchemy import text

from app import app, db

STATEMENTS = [
    "ALTER TABLE \"user\" ADD COLUMN IF NOT EXISTS plan VARCHAR(16) NOT NULL DEFAULT 'free'",
    'ALTER TABLE "user" ADD COLUMN IF NOT EXISTS plan_updated_at TIMESTAMP',
    'ALTER TABLE "user" ADD COLUMN IF NOT EXISTS lab BOOLEAN NOT NULL DEFAULT FALSE',
    "ALTER TABLE \"user\" ADD COLUMN IF NOT EXISTS active_days_json TEXT NOT NULL DEFAULT '[]'",
    'ALTER TABLE "user" ADD COLUMN IF NOT EXISTS conversations_total INTEGER NOT NULL DEFAULT 0',
    'ALTER TABLE "user" ADD COLUMN IF NOT EXISTS progression_json TEXT',
    'ALTER TABLE "user" ADD COLUMN IF NOT EXISTS progression_checked_at TIMESTAMP',
]

with app.app_context():
    for statement in STATEMENTS:
        db.session.execute(text(statement))
    db.session.commit()
    print(f"Colonnes de forfaits ajoutées (ou déjà présentes) sur : {app.config['SQLALCHEMY_DATABASE_URI'].split('@')[-1]}")
