"""
Octix — service d'authentification centralisé
================================================
Un point d'entrée unique pour créer des comptes, se connecter,
et VÉRIFIER un token depuis n'importe quelle autre app (LearnCode, classroom, etc.)

Installation :
    pip install flask flask_sqlalchemy pyjwt --break-system-packages

Lancement :
    python octix.py
    -> service disponible sur http://localhost:5050

Endpoints :
    POST /register   {username, password}   -> 201 (compte créé) / 409 (existe déjà)
    POST /login       {username, password}   -> {token, username, expires_in_hours}
    GET|POST /verify   {token}                -> {valid: true, username} ou {valid: false, error}

Pour la prod, pense à :
    - fixer OCTIX_SECRET_KEY dans les variables d'environnement (pas la valeur par défaut)
    - passer à une vraie base (Postgres) plutôt que SQLite
    - servir en HTTPS
"""

import os
import datetime
import jwt
from flask import Flask, request, jsonify
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash

# Désactive la création automatique du dossier 'instance/' de Flask
app = Flask(__name__, instance_relative_config=False)

# Stocke SQLite dans le dossier temporaire /tmp (seul dossier inscriptible sur Vercel)
# Ou utilise une base distante via variable d'environnement (ex: PostgreSQL / Neon / Supabase)
db_uri = os.environ.get("DATABASE_URL", "sqlite:////tmp/octix.db")
app.config["SQLALCHEMY_DATABASE_URI"] = db_uri
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False

SECRET_KEY = os.environ.get("OCTIX_SECRET_KEY", "change-moi-en-production")
TOKEN_DURATION_HOURS = 12

db = SQLAlchemy(app)

# Initialise les tables au chargement du module
with app.app_context():
    db.create_all()


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


if __name__ == "__main__":
    with app.app_context():
        db.create_all()
    app.run(debug=True, port=5050)
