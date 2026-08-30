"""
Octix — service d'authentification centralisé
================================================
Un point d'entrée unique pour créer des comptes, se connecter,
et VÉRIFIER un token depuis n'importe quelle autre app (LearnCode, classroom, etc.)

Version adaptée pour Vercel : utilise une vraie base Postgres (Vercel Postgres,
Neon, Supabase...) au lieu de SQLite, car le système de fichiers de Vercel est
en lecture seule (sauf /tmp, qui n'est PAS persistant entre deux invocations
de la fonction serverless). Avec SQLite sur /tmp, chaque cold start repartirait
d'une base vide : les comptes créés disparaîtraient.

Installation :
    pip install flask flask_sqlalchemy pyjwt psycopg2-binary --break-system-packages

Lancement en local (avec Postgres) :
    export POSTGRES_URL="postgresql://user:password@host:5432/dbname"
    export OCTIX_SECRET_KEY="une-vraie-cle-secrete"
    python octix.py
    -> service disponible sur http://localhost:5050

Déploiement sur Vercel :
    1. Ajoute l'intégration "Vercel Postgres" (ou Neon/Supabase) à ton projet
       -> Vercel injecte automatiquement POSTGRES_URL / POSTGRES_URL_NON_POOLING
    2. Définis OCTIX_SECRET_KEY dans les variables d'environnement du projet
    3. Crée les tables UNE SEULE FOIS avant le premier déploiement (voir init_db.py),
       plutôt que de compter sur db.create_all() à chaque cold start
    4. Déploie via `vercel` (voir vercel.json + api/index.py)

Endpoints :
    POST /register   {username, password}   -> 201 (compte créé) / 409 (existe déjà)
    POST /login       {username, password}   -> {token, username, expires_in_hours}
    GET|POST /verify   {token}                -> {valid: true, username} ou {valid: false, error}
"""

import os
import datetime
import jwt
from flask import Flask, request, jsonify
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)


def _normalize_db_url(url: str) -> str:
    """Vercel Postgres / Heroku-style fournissent souvent 'postgres://',
    or SQLAlchemy 1.4+ exige le préfixe 'postgresql://'."""
    if url and url.startswith("postgres://"):
        url = url.replace("postgres://", "postgresql://", 1)
    return url


# Ordre de priorité des variables d'environnement :
# - POSTGRES_URL_NON_POOLING : connexion directe (sans pgbouncer), utile pour
#   les opérations de schéma (create_all, migrations)
# - POSTGRES_URL : connexion "pooled" fournie automatiquement par l'intégration
#   Vercel Postgres, à utiliser pour les requêtes normales de l'app
# - DATABASE_URL : fallback générique si tu utilises Neon/Supabase directement
# - sqlite en mémoire : UNIQUEMENT pour tourner le code sans base configurée
#   (tests rapides) — ne jamais utiliser en prod sur Vercel
db_uri = (
    os.environ.get("POSTGRES_URL")
    or os.environ.get("DATABASE_URL")
    or os.environ.get("POSTGRES_URL_NON_POOLING")
    or "sqlite:///:memory:"
)
app.config["SQLALCHEMY_DATABASE_URI"] = _normalize_db_url(db_uri)
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
app.config["SQLALCHEMY_ENGINE_OPTIONS"] = {
    # essentiel en environnement serverless : évite d'utiliser une connexion
    # que la base a déjà fermée de son côté entre deux invocations
    "pool_pre_ping": True,
    # recycle la connexion avant que le Postgres managé ne la coupe lui-même
    "pool_recycle": 280,
}

SECRET_KEY = os.environ.get("OCTIX_SECRET_KEY", "change-moi-en-production")
TOKEN_DURATION_HOURS = 12

db = SQLAlchemy(app)


class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password_hash = db.Column(db.String(255), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.datetime.utcnow)

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)


def generate_token(username):
    payload = {
        "sub": username,
        "iat": datetime.datetime.utcnow(),
        "exp": datetime.datetime.utcnow() + datetime.timedelta(hours=TOKEN_DURATION_HOURS),
        "iss": "octix",
    }
    return jwt.encode(payload, SECRET_KEY, algorithm="HS256")


def decode_token(token):
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=["HS256"])
        return payload, None
    except jwt.ExpiredSignatureError:
        return None, "token expiré"
    except jwt.InvalidTokenError:
        return None, "token invalide"


@app.route("/register", methods=["POST"])
def register():
    data = request.get_json(silent=True) or request.form
    username = (data.get("username") or "").strip()
    password = data.get("password") or ""

    if not username or not password:
        return jsonify({"error": "username et password requis"}), 400
    if len(password) < 6:
        return jsonify({"error": "mot de passe trop court (6 caractères minimum)"}), 400
    if User.query.filter_by(username=username).first():
        return jsonify({"error": "ce pseudo existe déjà"}), 409

    user = User(username=username)
    user.set_password(password)
    db.session.add(user)
    db.session.commit()
    return jsonify({"message": "compte créé", "username": username}), 201


@app.route("/login", methods=["POST"])
def login():
    data = request.get_json(silent=True) or request.form
    username = (data.get("username") or "").strip()
    password = data.get("password") or ""

    user = User.query.filter_by(username=username).first()
    if not user or not user.check_password(password):
        return jsonify({"error": "identifiants invalides"}), 401

    token = generate_token(user.username)
    return jsonify({
        "token": token,
        "username": user.username,
        "expires_in_hours": TOKEN_DURATION_HOURS,
    })


@app.route("/verify", methods=["GET", "POST"])
def verify():
    token = (
        request.args.get("token")
        or (request.get_json(silent=True) or {}).get("token")
        or request.form.get("token")
    )
    if not token:
        return jsonify({"valid": False, "error": "token manquant"}), 400

    payload, error = decode_token(token)
    if error:
        return jsonify({"valid": False, "error": error}), 401

    return jsonify({"valid": True, "username": payload["sub"]})


@app.route("/")
def index():
    return jsonify({"service": "Octix", "status": "en ligne"})


# En local uniquement : sur Vercel, c'est api/index.py qui expose `app`,
# et les tables doivent déjà exister (voir init_db.py) avant le déploiement.
if __name__ == "__main__":
    with app.app_context():
        db.create_all()
    app.run(debug=True, port=5050)
