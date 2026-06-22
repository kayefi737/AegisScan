"""Transparent, weighted scoring -> A..F grade.

Every finding carries a weight and a status. A category score is the share of its
findings' weight that passed (a warning counts as half credit). The overall score
is the weighted mean across categories using the per-category weights below.

The rubric is published in the README so a grade is always reproducible and never
a black box - a deliberate improvement over opaque "security score" tools.
"""
from __future__ import annotations

# Relative importance of each category in the final grade.
CATEGORY_WEIGHTS: dict[str, float] = {
    "tls": 2.0,
    "headers": 2.0,
    "csp": 1.5,
    "cookies": 1.0,
    "dns_email": 1.5,
    "redirects": 1.0,
    "mixed_content": 1.0,
    "http_protocol": 0.5,
    "wellknown": 0.5,
}

# Credit each status earns toward its finding weight.
STATUS_CREDIT = {"pass": 1.0, "info": 1.0, "warn": 0.5, "fail": 0.0}

GRADE_BANDS = [
    (95.0, "A+"),
    (90.0, "A"),
    (80.0, "B"),
    (70.0, "C"),
    (60.0, "D"),
    (0.0, "F"),
]


def category_score(findings: list[dict]) -> tuple[float, float]:
    """Return (earned, max) weight for a category's findings."""
    earned = 0.0
    total = 0.0
    for f in findings:
        if f["status"] == "info":
            # info findings are contextual and do not move the score
            continue
        weight = float(f.get("weight", 1.0))
        total += weight
        earned += weight * STATUS_CREDIT.get(f["status"], 0.0)
    return earned, total


def grade_for(score_pct: float) -> str:
    for threshold, label in GRADE_BANDS:
        if score_pct >= threshold:
            return label
    return "F"


def compute(categories: list[dict]) -> dict:
    """Given category dicts with findings, attach scores and a final grade.

    Returns {"score": pct, "max_score": 100.0, "grade": str, "categories": [...]}.
    """
    weighted_earned = 0.0
    weighted_total = 0.0

    for cat in categories:
        earned, total = category_score(cat["findings"])
        cat["score"] = round(earned, 3)
        cat["max_score"] = round(total, 3)
        cat_pct = (earned / total) if total else 1.0
        w = CATEGORY_WEIGHTS.get(cat["key"], 1.0)
        weighted_earned += cat_pct * w
        weighted_total += w

    score_pct = round((weighted_earned / weighted_total) * 100.0, 1) if weighted_total else 100.0
    return {
        "score": score_pct,
        "max_score": 100.0,
        "grade": grade_for(score_pct),
        "categories": categories,
    }
