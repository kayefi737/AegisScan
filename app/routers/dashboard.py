"""Public dashboard: aggregate stats with privacy-aware hostname masking."""
from __future__ import annotations

from collections import Counter

from fastapi import APIRouter, Depends
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from ..database import get_db
from ..masking import mask_hostname
from ..models import Scan
from ..schemas import DashboardStats, ScanOut

router = APIRouter(prefix="/api/dashboard", tags=["dashboard"])


@router.get("", response_model=DashboardStats)
def stats(db: Session = Depends(get_db)) -> DashboardStats:
    total = db.scalar(select(func.count()).select_from(Scan)) or 0
    unique = db.scalar(select(func.count(func.distinct(Scan.hostname)))) or 0
    avg = db.scalar(select(func.avg(Scan.score))) or 0.0

    grade_rows = db.execute(select(Scan.grade, func.count()).group_by(Scan.grade)).all()
    grade_distribution = {g: c for g, c in grade_rows}

    # Aggregate the most common failing checks across the most recent 500 scans.
    failures: Counter[str] = Counter()
    for scan in db.scalars(select(Scan).order_by(Scan.created_at.desc()).limit(500)):
        for cat in scan.result.get("categories", []):
            for f in cat["findings"]:
                if f["status"] == "fail":
                    failures[f["title"]] += 1
    top_failures = [{"title": t, "count": c} for t, c in failures.most_common(8)]

    recent = list(db.scalars(select(Scan).order_by(Scan.created_at.desc()).limit(10)))
    recent_out = [
        ScanOut(
            id=s.id,
            hostname=mask_hostname(s.hostname),   # masked for public view
            grade=s.grade,
            score=s.score,
            created_at=s.created_at,
            result=None,
        )
        for s in recent
    ]

    return DashboardStats(
        total_scans=total,
        unique_domains=unique,
        grade_distribution=grade_distribution,
        average_score=round(float(avg), 1),
        top_failures=top_failures,
        recent_scans=recent_out,
    )
