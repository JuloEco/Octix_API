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
       (et, si besoin, DAILY_TOKEN_QUOTA — défaut 500)
    3. Si la table "user" existe déjà (déploiement pré-existant), lance
       migrate_add_email.py, migrate_add_quota.py puis migrate_add_plans.py
       UNE FOIS avant de déployer
       cette version : db.create_all() ne modifie jamais une table déjà créée,
       il ne crée que les tables manquantes.
    4. Déploie via `vercel` (voir vercel.json + api/index.py)

Endpoints publics (utilisés par les apps clientes) :
    POST /register   {username, password, email, classroom_role}   -> 201 / 409
    POST /login       {username, password}          -> {token, username, expires_in_hours, missing_fields}
    GET|POST /verify   {token}                       -> {valid: true, username} ou {valid: false, error}
    POST /complete-profile   {email?, classroom_role?}   (Authorization: Bearer <token>)
        -> comble les champs manquants sur un compte créé avant leur ajout,
           sans jamais toucher au mot de passe (voir missing_fields ci-dessus)

Endpoints de gestion de compte (Authorization: Bearer <token>, obtenu via /login) :
    GET    /account/me                    -> profil (username, email, classroom_role, created_at,
                                              api_key_preview, api_key_created_at)
    PUT    /account/classroom-role  {classroom_role}                      -> {ok, classroom_role}
    PUT    /account/password        {current_password, new_password}      -> {ok} ou 403 si mdp actuel faux
    DELETE /account                 {password}                            -> {ok} ou 403 si mdp faux
    GET    /account/learncode-progress    -> progression LearnCode (lue directement dans sa table)
    POST   /account/api-key               -> génère (ou régénère) une clé API pour le compte.
                                              La clé en clair n'est renvoyée QUE dans cette réponse
                                              ({api_key, api_key_preview, api_key_created_at}) ; elle
                                              n'est jamais stockée ni ré-affichée ensuite (seul le
                                              hash l'est). Régénérer invalide immédiatement l'ancienne.

Endpoint machine-à-machine (utilisé par les apps clientes pour s'authentifier avec
une clé API plutôt qu'un token JWT — utile pour un appel serveur-à-serveur sans
passer par /login) :
    GET|POST /verify-api-key  {api_key}     -> {valid: true, username} ou {valid: false, error}

Quota de tokens partagé par COMPTE (Authorization: Bearer <token> OU X-Api-Key /
api_key — les deux résolvent le même compte, donc le même compteur) :
    GET  /account/quota                    -> {used, limit, remaining}
    POST /account/quota/consume  {tokens}  -> décompte "tokens" sur le compteur du
                                               jour et renvoie le nouveau statut, ou
                                               409/429 si le quota est déjà atteint.
    Le compteur est attaché au COMPTE (colonnes tokens_used_today / quota_date sur
    User), jamais à la clé API elle-même : régénérer sa clé API ne le remet donc
    plus à zéro, et créer plusieurs clés pour un même compte ne donne plusieurs
    quotas — un compte = un quota, quel que soit le nombre de clés ou d'apps qui
    l'utilisent (portail web, CLI...).

Forfaits (Free / Plus / Pro, voir plans.py) — le quota ci-dessus dépend du forfait
du compte, qui se débloque en accomplissant des missions LearnCode / Classroom /
Omnia Mind / Opsiom (lues directement dans la base commune, voir progression.py) :
    GET  /account/progression[?force=1]  -> forfait courant, missions par forfait,
                                             quota (token JWT ou clé API). Passe le
                                             compte au forfait supérieur si mérité.
    GET  /admin/progression-debug?username=  -> diagnostic des lectures (X-Internal-Key obligatoire)
    POST /admin/plan  {username, plan}   -> force un forfait   (X-Internal-Key obligatoire)
    POST /admin/lab   {username, lab}    -> statut Opsiom Lab  (X-Internal-Key obligatoire)

Endpoints internes (utilisés uniquement par le portail Octix, jamais par un
navigateur — protégés par le header X-Internal-Key si OCTIX_INTERNAL_KEY est défini) :
    GET  /user/<username>/email      -> {email} ou 404
    POST /reset-password  {username, new_password}   -> {ok: true} ou 404
"""

import os
import json
import secrets
import hashlib
import datetime
import jwt
from flask import Flask, request, jsonify
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import text
from werkzeug.security import generate_password_hash, check_password_hash

import plans
import progression

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
DB_ENV_USED = next(
    (name for name in ("POSTGRES_URL", "DATABASE_URL", "POSTGRES_URL_NON_POOLING") if os.environ.get(name)),
    "(aucune : sqlite en mémoire)",
)
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

# Quota de tokens/jour partagé par compte (web + CLI + toute autre app qui
# passe par /account/quota/consume). Il dépend désormais du FORFAIT du compte
# (voir plans.py : free 500 / plus 10 000 / pro 50 000). Cette variable
# d'environnement ne surcharge plus que le forfait "free", pour pouvoir
# ajuster le quota par défaut sans redéployer le code.
if os.environ.get("DAILY_TOKEN_QUOTA"):
    plans.PLANS["free"]["daily_tokens"] = int(os.environ["DAILY_TOKEN_QUOTA"])

# Intervalle minimum entre deux recalculs de progression pour un même compte
# (les lectures traversent les tables de 3 apps : inutile à chaque message).
PROGRESSION_TTL_SECONDS = int(os.environ.get("PROGRESSION_TTL_SECONDS", "300"))

db = SQLAlchemy(app)


class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(255), unique=True, nullable=True)
    classroom_role = db.Column(db.String(20), nullable=True)  # 'prof' ou 'eleve'
    password_hash = db.Column(db.String(255), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.datetime.utcnow)
    # Clé API : on ne stocke jamais la clé en clair, seulement son hash SHA-256
    # (contrairement au mot de passe, une clé API est déjà un secret à haute
    # entropie généré aléatoirement — un hash rapide suffit, pas besoin du
    # coût volontaire de bcrypt/werkzeug qui vise à ralentir le brute-force
    # sur des mots de passe choisis par un humain).
    api_key_hash = db.Column(db.String(64), unique=True, nullable=True)
    api_key_preview = db.Column(db.String(20), nullable=True)
    api_key_created_at = db.Column(db.DateTime, nullable=True)

    # Quota de tokens/jour, PARTAGÉ entre toutes les apps et toutes les clés
    # du compte (voir /account/quota/consume) : attaché à l'utilisateur, pas
    # à une clé API, pour qu'il ne suffise pas de régénérer sa clé (ou d'en
    # créer une par app) pour repartir avec un quota frais.
    tokens_used_today = db.Column(db.Integer, default=0, nullable=False)
    quota_date = db.Column(db.Date, default=datetime.date.today, nullable=False)

    # --- Forfait (voir plans.py) -----------------------------------------
    plan = db.Column(db.String(16), default=plans.DEFAULT_PLAN, nullable=False)
    plan_updated_at = db.Column(db.DateTime, nullable=True)
    # Statut Lab : séparé des forfaits (bêta-testeurs). Attribution manuelle
    # via /admin/lab pour l'instant ; aucun avantage concret tant qu'aucun
    # modèle expérimental n'existe.
    lab = db.Column(db.Boolean, default=False, nullable=False)

    # --- Activité Opsiom, alimentée par /account/quota/consume : sert aux
    # missions "utiliser Opsiom N jours" / "N conversations". Liste JSON de
    # dates ISO (90 dernières) — suffisant pour compter des jours distincts.
    active_days_json = db.Column(db.Text, default="[]", nullable=False)
    conversations_total = db.Column(db.Integer, default=0, nullable=False)

    # Cache de progression (recalcul au plus toutes les PROGRESSION_TTL_SECONDS)
    progression_json = db.Column(db.Text, nullable=True)
    progression_checked_at = db.Column(db.DateTime, nullable=True)

    def opsiom_activity_stats(self):
        try:
            days = json.loads(self.active_days_json or "[]")
        except (ValueError, TypeError):
            days = []
        return {"active_days": len(days), "conversations": self.conversations_total or 0}

    def record_opsiom_activity(self):
        today = datetime.date.today().isoformat()
        try:
            days = set(json.loads(self.active_days_json or "[]"))
        except (ValueError, TypeError):
            days = set()
        days.add(today)
        self.active_days_json = json.dumps(sorted(days)[-90:])
        self.conversations_total = (self.conversations_total or 0) + 1

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


def generate_api_key():
    """Clé lisible et préfixée (façon Stripe/GitHub) : le préfixe permet de
    reconnaître une clé Octix au premier coup d'œil (dans un log, un .env...),
    token_urlsafe(32) donne ~256 bits d'entropie, largement assez pour ne
    jamais nécessiter de vérifier son unicité en base avant insertion."""
    return f"octix_{secrets.token_urlsafe(32)}"


def hash_api_key(api_key):
    return hashlib.sha256(api_key.encode("utf-8")).hexdigest()


def preview_api_key(api_key):
    """Aperçu affiché dans l'espace compte : jamais assez pour reconstituer
    la clé, juste de quoi la reconnaître parmi plusieurs (ex. après une
    régénération)."""
    return f"{api_key[:10]}…{api_key[-4:]}"


def token_required(view_func):
    """Protège une route avec le token JWT obtenu au login. Injecte l'objet
    User correspondant en premier argument de la vue (comme g.user ailleurs,
    mais explicite pour rester simple ici)."""
    from functools import wraps

    @wraps(view_func)
    def wrapped(*args, **kwargs):
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

        return view_func(user, *args, **kwargs)

    return wrapped


def _internal_auth_ok(req) -> bool:
    """True si l'appelant a le droit d'utiliser un endpoint interne.
    Ces routes ne doivent jamais être exposées à un navigateur : seul le
    portail (le seul autre service à parler à octix.py) doit connaître
    OCTIX_INTERNAL_KEY."""
    if not INTERNAL_KEY:
        app.logger.warning("OCTIX_INTERNAL_KEY non défini : endpoints internes non protégés.")
        return True
    return req.headers.get("X-Internal-Key") == INTERNAL_KEY


# Créé les tables manquantes au chargement du module. Contrairement à un appel
# placé uniquement dans `if __name__ == "__main__":`, ce bloc s'exécute aussi
# quand gunicorn importe ce fichier (cas de la prod sur Render) — sans quoi
# les tables ne sont jamais créées et /register, /login échouent avec une
# erreur 500 (table inexistante).
with app.app_context():
    db.create_all()


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

@app.route("/admin/users", methods=["GET"])
def admin_list_users():
    if request.headers.get("X-Internal-Key") != os.environ.get("OCTIX_INTERNAL_KEY"):
        return jsonify({"error": "Unauthorized"}), 401

    users = User.query.all()  # adapte selon ton modèle SQLAlchemy
    return jsonify({"users": [{"email": u.email} for u in users if u.email]}), 200

@app.route("/account/me", methods=["GET"])
@token_required
def account_me(user):
    """Profil complet du compte connecté (jamais le mot de passe, même hashé)."""
    return jsonify({
        "username": user.username,
        "email": user.email,
        "classroom_role": user.classroom_role,
        "created_at": user.created_at.isoformat() if user.created_at else None,
        "api_key_preview": user.api_key_preview,
        "api_key_created_at": user.api_key_created_at.isoformat() if user.api_key_created_at else None,
        "quota": _quota_status(user),
        "plan": user.plan,
        "lab": bool(user.lab),
    })


@app.route("/account/api-key", methods=["POST"])
@token_required
def account_generate_api_key(user):
    """Génère une nouvelle clé API pour le compte connecté. Si une clé
    existait déjà, elle est immédiatement invalidée (un seul hash stocké
    par compte) : c'est ce qui justifie l'avertissement de confirmation
    côté portail avant de régénérer. La clé en clair n'est renvoyée
    qu'ici, une seule fois -- elle n'est jamais récupérable ensuite."""
    api_key = generate_api_key()
    user.api_key_hash = hash_api_key(api_key)
    user.api_key_preview = preview_api_key(api_key)
    user.api_key_created_at = datetime.datetime.utcnow()
    db.session.commit()

    return jsonify({
        "ok": True,
        "api_key": api_key,
        "api_key_preview": user.api_key_preview,
        "api_key_created_at": user.api_key_created_at.isoformat(),
    }), 201


@app.route("/account/api-key", methods=["DELETE"])
@token_required
def account_revoke_api_key(user):
    """Révoque la clé API du compte sans en générer une nouvelle."""
    user.api_key_hash = None
    user.api_key_preview = None
    user.api_key_created_at = None
    db.session.commit()
    return jsonify({"ok": True})


@app.route("/verify-api-key", methods=["GET", "POST"])
def verify_api_key():
    """Équivalent de /verify mais pour une clé API plutôt qu'un token JWT --
    pensé pour un appel serveur-à-serveur (une app cliente qui a stocké la
    clé API d'un compte dans sa propre config, sans repasser par /login)."""
    api_key = (
        request.args.get("api_key")
        or (request.get_json(silent=True, force=True) or {}).get("api_key")
        or request.form.get("api_key")
    )
    if not api_key:
        return jsonify({"valid": False, "error": "api_key manquante"}), 400

    user = User.query.filter_by(api_key_hash=hash_api_key(api_key)).first()
    if not user:
        return jsonify({"valid": False, "error": "clé API invalide"}), 401

    return jsonify({"valid": True, "username": user.username})


def _resolve_quota_user(req):
    """Retrouve le compte appelant depuis un token JWT (Authorization: Bearer)
    OU une clé API (header X-Api-Key, ou 'api_key' en JSON/query/form).

    C'est cette double entrée qui permet au portail web (qui n'a qu'un token
    de session) et au CLI / serveur d'inférence (qui n'a qu'une clé API) de
    partager EXACTEMENT le même compteur : les deux chemins retombent sur le
    même User, donc sur les mêmes colonnes tokens_used_today / quota_date."""
    auth_header = req.headers.get("Authorization", "")
    token = auth_header[7:].strip() if auth_header.startswith("Bearer ") else None
    if token:
        payload, error = decode_token(token)
        if error:
            return None, error
        user = User.query.filter_by(username=payload["sub"]).first()
        if not user:
            return None, "compte introuvable"
        return user, None

    api_key = (
        req.headers.get("X-Api-Key")
        or (req.get_json(silent=True, force=True) or {}).get("api_key")
        or req.args.get("api_key")
        or req.form.get("api_key")
    )
    if api_key:
        user = User.query.filter_by(api_key_hash=hash_api_key(api_key)).first()
        if not user:
            return None, "clé API invalide"
        return user, None

    return None, "authentification requise (Authorization: Bearer <token> ou X-Api-Key)"


def _reset_quota_if_needed(user):
    if user.quota_date != datetime.date.today():
        user.quota_date = datetime.date.today()
        user.tokens_used_today = 0


def _quota_status(user):
    _reset_quota_if_needed(user)
    limit = plans.daily_tokens_for(user.plan)
    return {
        "used": user.tokens_used_today,
        "limit": limit,
        "remaining": max(0, limit - user.tokens_used_today),
        "plan": user.plan,
        "lab": bool(user.lab),
    }


@app.route("/account/quota", methods=["GET"])
def account_quota():
    """Statut du quota de tokens du compte appelant, sans le décompter."""
    user, error = _resolve_quota_user(request)
    if error:
        return jsonify({"error": error}), 401
    _maybe_refresh_progression(user)
    status = _quota_status(user)
    db.session.commit()  # persiste un éventuel reset de date déclenché ci-dessus
    return jsonify(status)


@app.route("/account/quota/consume", methods=["POST"])
def account_quota_consume():
    """Décompte 'tokens' sur le quota quotidien du compte appelant.

    Le quota est vérifié avant décompte (refus 429 si déjà à zéro) et
    partagé par TOUT le compte : peu importe que l'appel vienne de la
    session web ou d'une clé API (même régénérée), c'est le même compteur
    qui est débité — voir _resolve_quota_user ci-dessus."""
    user, error = _resolve_quota_user(request)
    if error:
        return jsonify({"error": error}), 401

    data = request.get_json(silent=True, force=True) or {}
    try:
        tokens = max(0, int(data.get("tokens", 0)))
    except (TypeError, ValueError):
        return jsonify({"error": "'tokens' doit être un entier"}), 400

    _maybe_refresh_progression(user)
    _reset_quota_if_needed(user)
    if user.tokens_used_today >= plans.daily_tokens_for(user.plan):
        db.session.commit()
        return jsonify({"error": "quota quotidien de tokens atteint", "quota": _quota_status(user)}), 429

    user.tokens_used_today += tokens
    if tokens > 0:
        user.record_opsiom_activity()
    db.session.commit()
    return jsonify({"ok": True, "quota": _quota_status(user)})


@app.route("/account/classroom-role", methods=["PUT"])
@token_required
def account_update_classroom_role(user):
    data = request.get_json(silent=True, force=True) or request.form
    role = (data.get("classroom_role") or "").strip().lower()
    if role not in ("prof", "eleve"):
        return jsonify({"error": "classroom_role doit être 'prof' ou 'eleve'"}), 400

    user.classroom_role = role
    db.session.commit()
    return jsonify({"ok": True, "classroom_role": user.classroom_role})


@app.route("/account/password", methods=["PUT"])
@token_required
def account_change_password(user):
    """Contrairement à /reset-password (interne, déclenché par un code e-mail),
    ici on exige le mot de passe ACTUEL : c'est l'utilisateur lui-même,
    déjà connecté, qui choisit de le changer depuis son compte."""
    data = request.get_json(silent=True, force=True) or request.form
    current_password = data.get("current_password") or ""
    new_password = data.get("new_password") or ""

    if not user.check_password(current_password):
        return jsonify({"error": "mot de passe actuel incorrect"}), 403
    if len(new_password) < 6:
        return jsonify({"error": "le nouveau mot de passe doit faire au moins 6 caractères"}), 400

    user.set_password(new_password)
    db.session.commit()
    return jsonify({"ok": True})


@app.route("/account", methods=["DELETE"])
@token_required
def account_delete(user):
    """Suppression définitive du compte Octix. Exige le mot de passe en
    confirmation — un token seul (qui peut fuiter, rester dans un onglet
    oublié...) ne suffit jamais à autoriser une action aussi irréversible.
    Ne supprime QUE le compte Octix (identité + auth) : les données propres
    à chaque app (progression LearnCode, devoirs...) restent gérées par ces
    apps elles-mêmes."""
    data = request.get_json(silent=True, force=True) or request.form
    password = data.get("password") or ""

    if not user.check_password(password):
        return jsonify({"error": "mot de passe incorrect"}), 403

    db.session.delete(user)
    db.session.commit()
    return jsonify({"ok": True})


@app.route("/account/learncode-progress", methods=["GET"])
@token_required
def account_learncode_progress(user):
    """Lit la progression LearnCode directement depuis sa table brute
    (gérée par LearnCode via psycopg2, pas par ce modèle SQLAlchemy) --
    mais sur la même base Postgres, donc accessible sans appeler une
    autre API réseau. Une seule source de vérité pour le format des
    données : LearnCode lui-même (voir get_level_data côté LearnCode)."""
    row = db.session.execute(
        text('SELECT data FROM users WHERE id = :username'),
        {"username": user.username},
    ).fetchone()

    if not row:
        return jsonify({"has_progress": False})

    raw = row[0]
    data = raw if isinstance(raw, dict) else json.loads(raw)

    score = data.get("score", 0)
    level = (score // 100) + 1
    progress_in_level = score % 100

    return jsonify({
        "has_progress": True,
        "xp": score,
        "level": level,
        "progress_in_level": progress_in_level,
        "next_level_xp": 100,
        "cours_notes": data.get("notes", {}),
        "cours_completes": len(data.get("notes", {})),
    })


# ---------------------------------------------------------------------------
# Forfaits & progression (voir plans.py / progression.py)
# ---------------------------------------------------------------------------
def _refresh_progression(user, force=False):
    """Recalcule (ou relit le cache de) la progression du compte, et le
    passe au forfait supérieur si toutes les missions de ce forfait sont
    remplies. Le forfait ne redescend JAMAIS automatiquement : une mission
    remplie reste acquise. Renvoie (raw_stats, upgraded).

    Les stats Opsiom (jours actifs, conversations) sont toujours relues en
    direct : elles sont locales à Octix, donc gratuites."""
    now = datetime.datetime.utcnow()
    cached = None
    if not force and user.progression_json and user.progression_checked_at:
        age = (now - user.progression_checked_at).total_seconds()
        if age < PROGRESSION_TTL_SECONDS:
            try:
                cached = json.loads(user.progression_json)
            except (ValueError, TypeError):
                cached = None

    if cached is not None:
        raw = cached
        raw["opsiom"] = user.opsiom_activity_stats()
    else:
        raw = progression.gather_raw_stats(db, user)  # peut faire un rollback interne
        user.progression_json = json.dumps(raw)
        user.progression_checked_at = now

    unlocked = plans.compute_unlocked_plan(raw)
    upgraded = plans.plan_rank(unlocked) > plans.plan_rank(user.plan)
    if upgraded:
        user.plan = unlocked
        user.plan_updated_at = now
    db.session.commit()
    return raw, upgraded


def _maybe_refresh_progression(user):
    """Version silencieuse pour les endpoints de quota : ne doit JAMAIS les
    faire échouer (une source de progression en panne ne doit pas bloquer
    un message de chat)."""
    try:
        _refresh_progression(user)
    except Exception:
        db.session.rollback()
        app.logger.warning("Rafraîchissement de progression échoué", exc_info=True)


@app.route("/account/progression", methods=["GET"])
def account_progression():
    """Forfait courant + progression vers les forfaits suivants. Accepte un
    token JWT ou une clé API (comme /account/quota). ?force=1 ignore le cache."""
    user, error = _resolve_quota_user(request)
    if error:
        return jsonify({"error": error}), 401

    raw, upgraded = _refresh_progression(user, force=request.args.get("force") == "1")

    tiers = []
    for plan_id in plans.PLAN_ORDER[1:]:
        missions = plans.evaluate_missions(plan_id, raw)
        cfg = plans.plan_config(plan_id)
        tiers.append({
            "id": plan_id,
            "label": cfg["label"],
            "emoji": cfg["emoji"],
            "daily_tokens": cfg["daily_tokens"],
            "models": cfg["models"],
            "priority_inference": bool(cfg.get("priority_inference")),
            "missions": missions,
            "done_count": sum(1 for m in missions if m["done"]),
            "total_count": len(missions),
            "unlocked": plans.plan_rank(user.plan) >= plans.plan_rank(plan_id),
        })

    current = plans.plan_config(user.plan)
    sources = {
        name: {"reachable": bool((raw.get(name) or {}).get("reachable"))}
        for name in ("learncode", "classroom", "omniamind")
    }
    debug = None
    if request.args.get("debug") == "1" and INTERNAL_KEY and request.headers.get("X-Internal-Key") == INTERNAL_KEY:
        # Diagnostic réservé à l'admin (X-Internal-Key) : quelle variable
        # d'environnement Octix utilise, sur quelle base, et l'erreur exacte
        # de chaque source. Jamais d'identifiants.
        uri = app.config["SQLALCHEMY_DATABASE_URI"]
        debug = {
            "db_env_var": DB_ENV_USED,
            "db_target": uri.split("@")[-1] if "@" in uri else uri,
            "raw_stats": raw,
        }
    return jsonify({
        "sources": sources,
        **({"debug": debug} if debug else {}),
        "plan": user.plan,
        "plan_label": current["label"],
        "plan_emoji": current["emoji"],
        "models": current["models"],
        "upgraded": upgraded,
        "next_plan": plans.next_plan_after(user.plan),
        "lab": bool(user.lab),
        "lab_label": plans.LAB_LABEL,
        "lab_emoji": plans.LAB_EMOJI,
        "tiers": tiers,
        "quota": _quota_status(user),
    })


def _admin_only():
    """Endpoints d'administration : exigent OCTIX_INTERNAL_KEY. Contrairement
    aux endpoints internes existants, ils REFUSENT de fonctionner si la clé
    n'est pas définie — accorder un forfait ou Lab ne doit jamais être ouvert."""
    if not INTERNAL_KEY:
        return jsonify({"error": "OCTIX_INTERNAL_KEY non défini : endpoint d'administration désactivé"}), 503
    if request.headers.get("X-Internal-Key") != INTERNAL_KEY:
        return jsonify({"error": "clé interne invalide"}), 403
    return None


@app.route("/admin/progression-debug", methods=["GET"])
def admin_progression_debug():
    """Diagnostic sans token utilisateur : GET /admin/progression-debug?username=<pseudo>
    avec l'en-tête X-Internal-Key. Renvoie la base réellement lue, les tables
    trouvées, l'erreur exacte de chaque source et les stats calculées."""
    denied = _admin_only()
    if denied:
        return denied
    username = (request.args.get("username") or "").strip()
    user = User.query.filter_by(username=username).first()
    if not user:
        return jsonify({"error": "compte introuvable dans la base d'Octix", "db_env_var": DB_ENV_USED,
                        "octix_db": app.config["SQLALCHEMY_DATABASE_URI"].split("@")[-1]}), 404
    raw = progression.gather_raw_stats(db, user)
    return jsonify({
        "db_env_var_octix": DB_ENV_USED,
        "octix_db": app.config["SQLALCHEMY_DATABASE_URI"].split("@")[-1],
        "raw_stats": raw,
        "diagnostic": progression.diagnose(db, username),
    })


@app.route("/admin/lab", methods=["POST"])
def admin_set_lab():
    """Attribue ou retire le statut Lab. Body : {username, lab: true|false}."""
    denied = _admin_only()
    if denied:
        return denied
    data = request.get_json(silent=True, force=True) or {}
    user = User.query.filter_by(username=(data.get("username") or "").strip()).first()
    if not user:
        return jsonify({"error": "compte introuvable"}), 404
    user.lab = bool(data.get("lab", True))
    db.session.commit()
    return jsonify({"ok": True, "username": user.username, "lab": user.lab})


@app.route("/admin/plan", methods=["POST"])
def admin_set_plan():
    """Force le forfait d'un compte (dépannage, événements). Body : {username, plan}."""
    denied = _admin_only()
    if denied:
        return denied
    data = request.get_json(silent=True, force=True) or {}
    plan_id = (data.get("plan") or "").strip().lower()
    if plan_id not in plans.PLANS:
        return jsonify({"error": f"forfait inconnu (attendu : {', '.join(plans.PLAN_ORDER)})"}), 400
    user = User.query.filter_by(username=(data.get("username") or "").strip()).first()
    if not user:
        return jsonify({"error": "compte introuvable"}), 404
    user.plan = plan_id
    user.plan_updated_at = datetime.datetime.utcnow()
    db.session.commit()
    return jsonify({"ok": True, "username": user.username, "plan": user.plan})


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


# En local uniquement : sur Vercel, c'est api/index.py qui expose `app`.
# db.create_all() s'exécute désormais au chargement du module (voir plus haut),
# donc plus besoin de le refaire ici.
if __name__ == "__main__":
    app.run(debug=True, port=5050)
