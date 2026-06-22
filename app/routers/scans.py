"""Scan submission, retrieval, history, comparison, and report downloads."""
from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.responses import HTMLResponse, Response
from sqlalchemy import select
from sqlalchemy.orm import Session

from ..auth import get_current_user, get_current_user_optional
from ..database import get_db
from ..engine import run_scan
from ..engine.runner import ENGINE_VERSION
from ..guard import TargetNotAllowed
from ..models import Scan, User
from ..ratelimit import enforce
from ..reporting import build_html, build_pdf
from ..schemas import ScanComparison, ScanOut, ScanRequest

router = APIRouter(prefix="/api/scans", tags=["scans"])


@router.post("", response_model=ScanOut, status_code=201)
async def create_scan(
    body: ScanRequest,
    request: Request,
    db: Session = Depends(get_db),
    user: User | None = Depends(get_current_user_optional),
) -> Scan:
    enforce(request)
    try:
        result = await run_scan(body.hostname)
    except TargetNotAllowed as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc

    scan = Scan(
        hostname=result["hostname"],
        grade=result["grade"],
        score=result["score"],
        result=result,
        user_id=user.id if user else None,
    )
    db.add(scan)
    db.commit()
    db.refresh(scan)
    return scan


@router.get("", response_model=list[ScanOut])
def my_history(
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
    limit: int = 50,
) -> list[Scan]:
    return list(
        db.scalars(
            select(Scan).where(Scan.user_id == user.id).order_by(Scan.created_at.desc()).limit(limit)
        )
    )


@router.get("/compare", response_model=ScanComparison)
def compare(before: str, after: str, db: Session = Depends(get_db)) -> ScanComparison:
    b = db.get(Scan, before)
    a = db.get(Scan, after)
    if not a or not b:
        raise HTTPException(status_code=404, detail="One or both scans were not found")
    if a.hostname != b.hostname:
        raise HTTPException(status_code=400, detail="Scans are for different hostnames")

    def status_map(scan: Scan) -> dict[str, str]:
        out = {}
        for cat in scan.result["categories"]:
            for f in cat["findings"]:
                out[f["title"]] = f["status"]
        return out

    bm, am = status_map(b), status_map(a)
    rank = {"fail": 0, "warn": 1, "info": 2, "pass": 3}
    improved, regressed, unchanged = [], [], []
    for title in set(bm) | set(am):
        before_s, after_s = bm.get(title), am.get(title)
        if before_s is None or after_s is None or before_s == after_s:
            unchanged.append(title)
        elif rank.get(after_s, 0) > rank.get(before_s, 0):
            improved.append(title)
        else:
            regressed.append(title)
    return ScanComparison(
        hostname=a.hostname, before=b, after=a,
        improved=sorted(improved), regressed=sorted(regressed), unchanged=sorted(unchanged),
    )


@router.get("/{scan_id}", response_model=ScanOut)
def get_scan(scan_id: str, db: Session = Depends(get_db)) -> Scan:
    scan = db.get(Scan, scan_id)
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    return scan


@router.get("/{scan_id}/report.html", response_class=HTMLResponse)
def report_html(scan_id: str, db: Session = Depends(get_db)) -> HTMLResponse:
    scan = _require(db, scan_id)
    return HTMLResponse(build_html(scan.result))


@router.get("/{scan_id}/report.pdf")
def report_pdf(
    scan_id: str,
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),  # PDF export is an authenticated extra
) -> Response:
    scan = _require(db, scan_id)
    pdf = build_pdf(scan.result)
    return Response(
        content=pdf,
        media_type="application/pdf",
        headers={"Content-Disposition": f'attachment; filename="aegisscan-{scan.hostname}.pdf"'},
    )


def _require(db: Session, scan_id: str) -> Scan:
    scan = db.get(Scan, scan_id)
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    return scan
