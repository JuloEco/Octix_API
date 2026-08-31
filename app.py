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
    export OCTIX_INTERNAL_KEY="une-cle-partagee-avec-le-portail"
    python octix.py
    -> service disponible sur http://localhost:5050

Déploiement sur Vercel :
    1. Ajoute l'intégration "Vercel Postgres" (ou Neon/Supabase) à ton projet
       -> Vercel injecte automatiquement POSTGRES_URL / POSTGRES_URL_NON_POOLING
    2. Définis OCTIX_SECRET_KEY et OCTIX_INTERNAL_KEY dans les variables d'environnement
    3. Si la table "user" existe déjà (déploiement pré-existant), lance
       migrate_add_email.py UNE FOIS avant de déployer cette version : db.create_all()
       ne modifie jamais une table déjà créée, il ne crée que les tables manquantes.
    4. Déploie via `vercel` (voir vercel.json + api/index.py)

Endpoints publics (utilisés par les apps clientes) :
    POST /register   {username, password, email, classroom_role}   -> 201 / 409
    POST /login       {username, password}          -> {token, username, expires_in_hours, missing_fields}
    GET|POST /verify   {token}                       -> {valid: true, username} ou {valid: false, error}
    POST /complete-profile   {email?, classroom_role?}   (Authorization: Bearer <token>)
        -> comble les champs manquants sur un compte créé avant leur ajout,
           sans jamais toucher au mot de passe (voir missing_fields ci-dessus)

Endpoints internes (utilisés uniquement par le portail Octix, jamais par un
navigateur — protégés par le header X-Internal-Key si OCTIX_INTERNAL_KEY est défini) :
    GET  /user/<username>/email      -> {email} ou 404
    POST /reset-password  {username, new_password}   -> {ok: true} ou 404
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

# Clé partagée avec le portail pour protéger les endpoints internes
# (/user/<username>/email et /reset-password). Si non définie, ces routes
# restent ouvertes (pratique en dev local) mais un avertissement est loggé :
# à définir obligatoirement avant tout déploiement public.
INTERNAL_KEY = os.environ.get("OCTIX_INTERNAL_KEY")

db = SQLAlchemy(app)


class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(255), unique=True, nullable=True)
    classroom_role = db.Column(db.String(20), nullable=True)  # 'prof' ou 'eleve'
    password_hash = db.Column(db.String(255), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.datetime.utcnow)

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)


REQUIRED_PROFILE_FIELDS = ("email", "classroom_role")


def missing_profile_fields(user):
    """Champs manquants sur un compte — typiquement des comptes créés avant
    l'ajout de ces colonnes. Le mot de passe n'apparaît jamais ici : il est
    obligatoire depuis la toute première version du formulaire, donc jamais
    manquant."""
    missing = []
    if not user.email:
        missing.append("email")
    if not user.classroom_role:
        missing.append("classroom_role")
    return missing


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


def _internal_auth_ok(req) -> bool:
    """True si l'appelant a le droit d'utiliser un endpoint interne.
    Ces routes ne doivent jamais être exposées à un navigateur : seul le
    portail (le seul autre service à parler à octix.py) doit connaître
    OCTIX_INTERNAL_KEY."""
    if not INTERNAL_KEY:
        app.logger.warning("OCTIX_INTERNAL_KEY non défini : endpoints internes non protégés.")
        return True
    return req.headers.get("X-Internal-Key") == INTERNAL_KEY


@app.route("/register", methods=["POST"])
def register():
    data = request.get_json(silent=True, force=True) or request.form
    username = (data.get("username") or "").strip()
    password = data.get("password") or ""
    email = (data.get("email") or "").strip()
    classroom_role = (data.get("classroom_role") or "").strip().lower()

    if not username or not password or not email or not classroom_role:
        return jsonify({"error": "username, password, email et classroom_role requis"}), 400
    if len(password) < 6:
        return jsonify({"error": "mot de passe trop court (6 caractères minimum)"}), 400
    if "@" not in email or "." not in email.split("@")[-1]:
        return jsonify({"error": "e-mail invalide"}), 400
    if classroom_role not in ("prof", "eleve"):
        return jsonify({"error": "classroom_role doit être 'prof' ou 'eleve'"}), 400
    if User.query.filter_by(username=username).first():
        return jsonify({"error": "ce pseudo existe déjà"}), 409
    if User.query.filter_by(email=email).first():
        return jsonify({"error": "cet e-mail est déjà associé à un compte"}), 409

    user = User(username=username, email=email, classroom_role=classroom_role)
    user.set_password(password)
    db.session.add(user)
    db.session.commit()
    return jsonify({"message": "compte créé", "username": username}), 201


@app.route("/login", methods=["POST"])
def login():
    data = request.get_json(silent=True, force=True) or request.form
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
        # Permet à n'importe quelle app cliente (Classroom, LearnCode...) de
        # savoir si elle doit afficher le pop-up "informations manquantes"
        # -- typique des comptes créés avant l'ajout de ces champs.
        "missing_fields": missing_profile_fields(user),
    })


@app.route("/verify", methods=["GET", "POST"])
def verify():
    token = (
        request.args.get("token")
        or (request.get_json(silent=True, force=True) or {}).get("token")
        or request.form.get("token")
    )
    if not token:
        return jsonify({"valid": False, "error": "token manquant"}), 400

    payload, error = decode_token(token)
    if error:
        return jsonify({"valid": False, "error": error}), 401

    return jsonify({"valid": True, "username": payload["sub"]})


@app.route("/user/<username>/email", methods=["GET"])
def get_user_email(username):
    """Interne — utilisé par le portail pour savoir où envoyer le code de
    réinitialisation. Ne jamais exposer ça à un formulaire public."""
    if not _internal_auth_ok(request):
        return jsonify({"error": "non autorisé"}), 403

    user = User.query.filter_by(username=username).first()
    if not user or not user.email:
        return jsonify({"error": "compte introuvable"}), 404

    return jsonify({"email": user.email})


@app.route("/reset-password", methods=["POST"])
def reset_password():
    """Interne — appelé par le portail une fois le code à 6 chiffres validé.
    Volontairement sans vérification de l'ancien mot de passe : le code déjà
    vérifié côté portail fait office de preuve d'identité."""
    if not _internal_auth_ok(request):
        return jsonify({"error": "non autorisé"}), 403

    data = request.get_json(silent=True, force=True) or request.form
    username = (data.get("username") or "").strip()
    new_password = data.get("new_password") or ""

    if not username or not new_password:
        return jsonify({"error": "username et new_password requis"}), 400
    if len(new_password) < 6:
        return jsonify({"error": "mot de passe trop court (6 caractères minimum)"}), 400

    user = User.query.filter_by(username=username).first()
    if not user:
        return jsonify({"error": "compte introuvable"}), 404

    user.set_password(new_password)
    db.session.commit()
    return jsonify({"ok": True})


@app.route("/complete-profile", methods=["POST"])
def complete_profile():
    """Appelé par le pop-up 'informations manquantes' de n'importe quelle app
    (Classroom, LearnCode...) une fois l'utilisateur connecté. Authentifié
    par le token JWT obtenu au login -- pas besoin de redemander le mot de
    passe. Ne met à jour QUE les champs fournis, jamais le reste du profil."""
    auth_header = request.headers.get("Authorization", "")
    token = auth_header[7:].strip() if auth_header.startswith("Bearer ") else None
    if not token:
        return jsonify({"error": "authentification requise (Authorization: Bearer <token>)"}), 401

    payload, error = decode_token(token)
    if error:
        return jsonify({"error": error}), 401

    user = User.query.filter_by(username=payload["sub"]).first()
    if not user:
        return jsonify({"error": "compte introuvable"}), 404

    data = request.get_json(silent=True, force=True) or request.form
    updated = []

    if data.get("email"):
        email = data["email"].strip()
        if "@" not in email or "." not in email.split("@")[-1]:
            return jsonify({"error": "e-mail invalide"}), 400
        existing = User.query.filter_by(email=email).first()
        if existing and existing.id != user.id:
            return jsonify({"error": "cet e-mail est déjà associé à un compte"}), 409
        user.email = email
        updated.append("email")

    if data.get("classroom_role"):
        role = data["classroom_role"].strip().lower()
        if role not in ("prof", "eleve"):
            return jsonify({"error": "classroom_role doit être 'prof' ou 'eleve'"}), 400
        user.classroom_role = role
        updated.append("classroom_role")

    if not updated:
        return jsonify({"error": "aucun champ valide à mettre à jour (email et/ou classroom_role attendus)"}), 400

    db.session.commit()
    return jsonify({"ok": True, "updated": updated, "missing_fields": missing_profile_fields(user)})


@app.route("/")
def index():
    return jsonify({"service": "Octix", "status": "en ligne"})

@app.route("/debug", methods=["GET", "POST"])
def debug():
    return jsonify({
        "method": request.method,
        "args": request.args.to_dict(),
        "form": request.form.to_dict(),
        "json": request.get_json(silent=True, force=True),
        "raw_data": request.get_data(as_text=True),
        "content_type": request.content_type,
        "content_length": request.content_length,
    })


# En local uniquement : sur Vercel, c'est api/index.py qui expose `app`,
# et les tables doivent déjà exister (voir init_db.py) avant le déploiement.
if __name__ == "__main__":
    with app.app_context():
        db.create_all()
    app.run(debug=True, port=5050)
