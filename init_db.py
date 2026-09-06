"""
init_db.py — Octix
===================
Crée les tables Postgres d'Octix si elles n'existent pas encore.

Pourquoi ce script existe :
    Sur Vercel, `app.py` est importé comme module (jamais exécuté avec
    `python app.py`), donc le bloc `if __name__ == "__main__":` qui
    appelait `db.create_all()` ne se déclenche jamais en prod. Résultat :
    sur une base neuve (ou après un `DROP TABLE`), la table "user"
    n'existe pas et /register échoue avec `relation "user" does not
    exist`, en boucle, tant que personne ne crée les tables.

Ce script fait exactement ce que `db.create_all()` fait d'habitude,
mais en une exécution manuelle, à lancer UNE FOIS avant le premier
déploiement (ou après avoir modifié le schéma à la main).

Usage :
    export POSTGRES_URL="postgresql://user:password@host:5432/dbname"
    # ou POSTGRES_URL_NON_POOLING / DATABASE_URL, comme dans app.py
    python init_db.py

Sans danger à relancer : db.create_all() ne touche jamais une table
déjà existante, il ne crée que celles qui manquent. Il ne modifie
JAMAIS une colonne existante (voir le cas du "role" NOT NULL fantôme
rencontré précédemment) — pour ça, il faut une vraie migration SQL.
"""

from app import app, db

with app.app_context():
    db.create_all()
    print(f"Tables créées (ou déjà existantes) sur : {app.config['SQLALCHEMY_DATABASE_URI'].split('@')[-1]}")
