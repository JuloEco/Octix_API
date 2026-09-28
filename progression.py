"""
progression.py (Octix) — calcule la progression d'un compte dans l'écosystème
en lisant, EN LECTURE SEULE, les tables des autres apps.

Toutes les apps partagent la même base Postgres (même DATABASE_URL) : on
réutilise donc la session SQLAlchemy d'Octix, exactement comme
/account/learncode-progress le fait déjà pour LearnCode. Aucune table de
progression n'est dupliquée, aucune validation n'est réinventée.

Chaque lecture est isolée : si une table n'existe pas (app pas encore
déployée sur cette base, nom différent...), la source est simplement marquée
`reachable: False` avec des compteurs à 0, et Octix continue de fonctionner.
"""
import json
import logging
import os

from sqlalchemy import create_engine, inspect, text

logger = logging.getLogger("octix.progression")

# Seuils de réussite — faciles à ajuster ici.
LEARNCODE_PASS_SCORE = 50        # note LearnCode (0-100) pour compter comme "réussi"
CLASSROOM_PASS_GRADE = 10        # note Classroom (sur 20)
OMNIAMIND_PASS_PERCENT = 70      # score % d'un quiz/swipe Omnia Mind


# Base à lire pour les tables des autres apps. Par défaut : la base d'Octix
# elle-même (même session). À définir UNIQUEMENT si Octix est branché sur une
# autre base que celle de LearnCode/Classroom/Omnia Mind — typiquement quand
# Vercel a injecté POSTGRES_URL (prioritaire dans app.py) alors que les autres
# apps utilisent DATABASE_URL. Valeur = le DATABASE_URL des autres apps.
PROGRESSION_DATABASE_URL = os.environ.get("PROGRESSION_DATABASE_URL", "")
_engine = None


def _normalize(url: str) -> str:
    return url.replace("postgres://", "postgresql://", 1) if url.startswith("postgres://") else url


def _get_engine():
    global _engine
    if _engine is None and PROGRESSION_DATABASE_URL:
        _engine = create_engine(_normalize(PROGRESSION_DATABASE_URL), pool_pre_ping=True, pool_recycle=280)
    return _engine


def target_description(db) -> str:
    """Hôte/base lus (sans identifiants), pour le diagnostic."""
    eng = _get_engine() or db.engine
    return f"{eng.url.host or 'local'}/{eng.url.database}" + (" [PROGRESSION_DATABASE_URL]" if _get_engine() else " [base d'Octix]")


def _safe_query(db, sql: str, params: dict):
    """Exécute une lecture ; renvoie (lignes, None) ou (None, message d'erreur).
    Sur erreur (table absente...), annule la transaction Postgres (sinon elle
    resterait 'aborted' pour la suite de la requête)."""
    try:
        eng = _get_engine()
        if eng is not None:
            with eng.connect() as conn:
                return conn.execute(text(sql), params).fetchall(), None
        return db.session.execute(text(sql), params).fetchall(), None
    except Exception as exc:
        if _get_engine() is None:
            db.session.rollback()
        msg = f"{type(exc).__name__}: {str(exc).splitlines()[0][:200]}"
        logger.warning("Lecture de progression impossible (%s) : %s", sql.split("FROM")[-1][:40].strip(), msg)
        return None, msg


def learncode_stats(db, username: str) -> dict:
    stats = {"lessons_completed": 0, "lessons_passed": 0, "xp": 0, "reachable": False}
    rows, err = _safe_query(db, "SELECT data FROM users WHERE id = :u", {"u": username})
    if rows is None:
        stats["error"] = err
        return stats
    stats["reachable"] = True
    if not rows:
        # Table lisible mais aucune ligne pour ce pseudo : compte jamais ouvert dans LearnCode.
        stats["error"] = f"aucune ligne dans users pour id='{username}'"
    if rows and rows[0][0]:
        raw = rows[0][0]
        data = raw if isinstance(raw, dict) else json.loads(raw)
        notes = data.get("notes", {}) or {}
        stats["lessons_completed"] = len(notes)
        stats["lessons_passed"] = sum(1 for n in notes.values() if (n or 0) >= LEARNCODE_PASS_SCORE)
        stats["xp"] = data.get("score", 0) or 0
    return stats


def classroom_stats(db, username: str) -> dict:
    stats = {"activities_graded": 0, "activities_passed": 0, "reachable": False}
    rows, err = _safe_query(
        db,
        'SELECT s.grade FROM submission s JOIN "user" u ON u.id = s.student_id '
        "WHERE u.username = :u AND s.grade IS NOT NULL",
        {"u": username},
    )
    if rows is None:
        stats["error"] = err
        return stats
    stats["reachable"] = True
    grades = [r[0] for r in rows]
    stats["activities_graded"] = len(grades)
    stats["activities_passed"] = sum(1 for g in grades if (g or 0) >= CLASSROOM_PASS_GRADE)
    return stats


def omniamind_stats(db, username: str) -> dict:
    stats = {"challenges_passed": 0, "study_sessions": 0, "reachable": False}
    rows, err = _safe_query(
        db,
        "SELECT l.mode, l.score FROM omniamind_study_logs l "
        "JOIN omniamind_users u ON u.id = l.user_id WHERE u.octix_username = :u",
        {"u": username},
    )
    if rows is None:
        stats["error"] = err
        return stats
    stats["reachable"] = True
    stats["study_sessions"] = len(rows)
    # Le score est un % pour quiz/swipe mais des SECONDES pour match : seuls
    # quiz et swipe peuvent donc compter comme "défi réussi".
    stats["challenges_passed"] = sum(
        1 for mode, score in rows if mode in ("quiz", "swipe") and (score or 0) >= OMNIAMIND_PASS_PERCENT
    )
    return stats


def gather_raw_stats(db, user) -> dict:
    return {
        "learncode": learncode_stats(db, user.username),
        "classroom": classroom_stats(db, user.username),
        "omniamind": omniamind_stats(db, user.username),
        "opsiom": user.opsiom_activity_stats(),
    }


def diagnose(db, username: str) -> dict:
    """Diagnostic complet pour l'admin : quelle base, quelles tables, et si le
    pseudo est retrouvé (y compris avec une casse différente)."""
    out = {"target": target_description(db), "username": username}
    try:
        eng = _get_engine() or db.engine
        names = set(inspect(eng).get_table_names())
        out["tables_presentes"] = sorted(
            n for n in names if n in ("users", "user", "submission", "assignment") or n.startswith("omniamind_")
        )
        out["tables_attendues_manquantes"] = [
            n for n in ("users", "user", "submission", "omniamind_users", "omniamind_study_logs") if n not in names
        ]
    except Exception as exc:
        out["tables_error"] = f"{type(exc).__name__}: {str(exc).splitlines()[0][:200]}"

    rows, err = _safe_query(db, "SELECT COUNT(*) FROM users", {})
    out["learncode_users_count"] = rows[0][0] if rows else err
    rows, err = _safe_query(db, "SELECT id FROM users WHERE LOWER(id) = LOWER(:u)", {"u": username})
    out["learncode_id_trouve"] = [r[0] for r in rows] if rows is not None else err
    rows, err = _safe_query(db, "SELECT octix_username FROM omniamind_users WHERE LOWER(octix_username) = LOWER(:u)", {"u": username})
    out["omniamind_username_trouve"] = [r[0] for r in rows] if rows is not None else err
    return out
