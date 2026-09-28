"""
plans.py — Définition centrale des forfaits Octix/Opsiom et des missions qui
les débloquent.

Ce fichier vit désormais dans Octix (et non plus dans Opsiom-frontend) parce
qu'Octix est le SEUL service qui :
  - possède déjà le compteur de quota qui fait foi (tokens_used_today /
    quota_date sur User) ;
  - est déjà appelé aussi bien par le portail web que par le CLI opsiom-cli ;
  - a déjà un accès direct (même base Postgres, même session SQLAlchemy) aux
    tables de LearnCode, Classroom et Omnia Mind (voir /account/learncode-progress
    dans app.py, qui fait exactement ça pour LearnCode).

Tout est ici pour rester facile à modifier : quotas, missions et seuils.
"""

# ---------------------------------------------------------------------------
# 1. Forfaits — quotas de tokens/jour
# ---------------------------------------------------------------------------
PLAN_ORDER = ["free", "plus", "pro"]

PLANS = {
    "free": {
        "label": "Opsiom Free",
        "emoji": "🟢",
        "daily_tokens": 2000,
        "models": ["nano", "small"],
        "description": "Forfait de base, obtenu automatiquement.",
    },
    "plus": {
        "label": "Opsiom Plus",
        "emoji": "🔵",
        "daily_tokens": 10_000,
        "models": ["nano", "small", "large"],
        "description": "Débloqué en accomplissant des missions dans l'écosystème.",
    },
    "pro": {
        "label": "Opsiom Pro",
        "emoji": "🟣",
        "daily_tokens": 50_000,
        "models": ["nano", "small", "large"],
        "priority_inference": True,
        "description": "Forfait avancé, nécessite une progression plus importante.",
    },
}

DEFAULT_PLAN = "free"


def plan_rank(plan_id: str) -> int:
    try:
        return PLAN_ORDER.index(plan_id)
    except ValueError:
        return 0


def plan_config(plan_id: str) -> dict:
    return PLANS.get(plan_id, PLANS[DEFAULT_PLAN])


def daily_tokens_for(plan_id: str) -> int:
    return plan_config(plan_id)["daily_tokens"]


# ---------------------------------------------------------------------------
# 2. Missions — lisent un dict de stats brutes produit par progression.py.
#
# Clés attendues dans raw_stats :
#   learncode.lessons_completed   -> nb de cours/leçons avec une note enregistrée
#   classroom.activities_passed   -> nb de devoirs Classroom notés >= 10/20
#   omniamind.challenges_passed   -> nb de sessions quiz/match/swipe >= 70%
#   opsiom.active_days            -> nb de jours différents où le compte a discuté avec Opsiom
#   opsiom.conversations          -> nb de conversations Opsiom envoyées (compteur cumulé)
# ---------------------------------------------------------------------------
MISSIONS = {
    "plus": [
        {"key": "learncode_3_lecons", "label": "Terminer 3 leçons LearnCode",
         "stat": "learncode.lessons_completed", "target": 3},
        {"key": "omniamind_1_defi", "label": "Réussir un défi Omnia Mind",
         "stat": "omniamind.challenges_passed", "target": 1},
    ],
    "pro": [
        {"key": "learncode_10_lecons", "label": "Terminer 10 leçons LearnCode",
         "stat": "learncode.lessons_completed", "target": 10},
        {"key": "classroom_5_activites", "label": "Réussir 5 activités Classroom",
         "stat": "classroom.activities_passed", "target": 5},
        {"key": "omniamind_5_defis", "label": "Réussir 5 défis Omnia Mind",
         "stat": "omniamind.challenges_passed", "target": 5},
        {"key": "opsiom_10_jours", "label": "Utiliser Opsiom 10 jours différents",
         "stat": "opsiom.active_days", "target": 10},
        {"key": "opsiom_20_conversations", "label": "Envoyer 20 conversations à Opsiom",
         "stat": "opsiom.conversations", "target": 20},
    ],
}


def _get_stat(raw_stats: dict, dotted_key: str) -> int:
    ns, _, key = dotted_key.partition(".")
    return int((raw_stats.get(ns) or {}).get(key, 0) or 0)


def evaluate_missions(plan_id: str, raw_stats: dict) -> list:
    out = []
    for mission in MISSIONS.get(plan_id, []):
        current = _get_stat(raw_stats, mission["stat"])
        out.append({
            **mission,
            "current": min(current, mission["target"]),
            "done": current >= mission["target"],
        })
    return out


def compute_unlocked_plan(raw_stats: dict) -> str:
    """Le forfait le plus haut dont TOUTES les missions sont remplies, sans
    jamais redescendre en dessous de 'free' — les forfaits sont cumulatifs."""
    unlocked = "free"
    for plan_id in PLAN_ORDER[1:]:
        missions = evaluate_missions(plan_id, raw_stats)
        if missions and all(m["done"] for m in missions):
            unlocked = plan_id
        else:
            break
    return unlocked


def next_plan_after(plan_id: str):
    idx = plan_rank(plan_id)
    if idx + 1 < len(PLAN_ORDER):
        return PLAN_ORDER[idx + 1]
    return None


# ---------------------------------------------------------------------------
# 3. Opsiom Lab — statut séparé, attribution manuelle pour l'instant (voir
#    colonne User.lab et /admin/lab côté app.py). Pas d'avantage concret tant
#    qu'aucun modèle expérimental n'existe : seule l'architecture est prête.
# ---------------------------------------------------------------------------
LAB_LABEL = "Opsiom Lab"
LAB_EMOJI = "🧪"
