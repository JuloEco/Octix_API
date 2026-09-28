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

from sqlalchemy import text

logger = logging.getLogger("octix.progression")

# Seuils de réussite — faciles à ajuster ici.
LEARNCODE_PASS_SCORE = 50        # note LearnCode (0-100) pour compter comme "réussi"
CLASSROOM_PASS_GRADE = 10        # note Classroom (sur 20)
OMNIAMIND_PASS_PERCENT = 70      # score % d'un quiz/swipe Omnia Mind


def _safe_query(db, sql: str, params: dict):
    """Exécute une lecture ; sur erreur (table absente...), annule la
    transaction Postgres (sinon elle resterait 'aborted' pour la suite de la
    requête) et renvoie None."""
    try:
        return db.session.execute(text(sql), params).fetchall()
    except Exception:
        db.session.rollback()
        logger.warning("Lecture de progression impossible : %s", sql.split("FROM")[-1][:40], exc_info=True)
        return None


def learncode_stats(db, username: str) -> dict:
    stats = {"lessons_completed": 0, "lessons_passed": 0, "xp": 0, "reachable": False}
    rows = _safe_query(db, "SELECT data FROM users WHERE id = :u", {"u": username})
    if rows is None:
        return stats
    stats["reachable"] = True
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
    rows = _safe_query(
        db,
        'SELECT s.grade FROM submission s JOIN "user" u ON u.id = s.student_id '
        "WHERE u.username = :u AND s.grade IS NOT NULL",
        {"u": username},
    )
    if rows is None:
        return stats
    stats["reachable"] = True
    grades = [r[0] for r in rows]
    stats["activities_graded"] = len(grades)
    stats["activities_passed"] = sum(1 for g in grades if (g or 0) >= CLASSROOM_PASS_GRADE)
    return stats


def omniamind_stats(db, username: str) -> dict:
    stats = {"challenges_passed": 0, "study_sessions": 0, "reachable": False}
    rows = _safe_query(
        db,
        "SELECT l.mode, l.score FROM omniamind_study_logs l "
        "JOIN omniamind_users u ON u.id = l.user_id WHERE u.octix_username = :u",
        {"u": username},
    )
    if rows is None:
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
