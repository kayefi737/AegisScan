"""Authenticated domain tracking."""
from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy import select
from sqlalchemy.orm import Session

from ..auth import get_current_user
from ..database import get_db
from ..guard import TargetNotAllowed, normalize_hostname
from ..models import TrackedDomain, User
from ..schemas import DomainCreate, DomainOut

router = APIRouter(prefix="/api/domains", tags=["domains"])


@router.get("", response_model=list[DomainOut])
def list_domains(db: Session = Depends(get_db), user: User = Depends(get_current_user)) -> list[TrackedDomain]:
    return list(db.scalars(select(TrackedDomain).where(TrackedDomain.user_id == user.id)))


@router.post("", response_model=DomainOut, status_code=201)
def add_domain(
    body: DomainCreate, db: Session = Depends(get_db), user: User = Depends(get_current_user)
) -> TrackedDomain:
    try:
        hostname = normalize_hostname(body.hostname)
    except TargetNotAllowed as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc

    if db.scalar(
        select(TrackedDomain).where(
            TrackedDomain.user_id == user.id, TrackedDomain.hostname == hostname
        )
    ):
        raise HTTPException(status_code=409, detail="You are already tracking that domain")

    domain = TrackedDomain(hostname=hostname, note=body.note, user_id=user.id)
    db.add(domain)
    db.commit()
    db.refresh(domain)
    return domain


@router.delete("/{domain_id}", status_code=204)
def delete_domain(domain_id: str, db: Session = Depends(get_db), user: User = Depends(get_current_user)) -> None:
    domain = db.get(TrackedDomain, domain_id)
    if not domain or domain.user_id != user.id:
        raise HTTPException(status_code=404, detail="Domain not found")
    db.delete(domain)
    db.commit()
