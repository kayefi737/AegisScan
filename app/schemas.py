"""Pydantic request/response schemas."""
from __future__ import annotations

import datetime as dt

from pydantic import BaseModel, EmailStr, Field


# ---- Auth ----
class UserCreate(BaseModel):
    email: EmailStr
    password: str = Field(min_length=8, max_length=128)


class UserOut(BaseModel):
    id: str
    email: EmailStr
    created_at: dt.datetime

    model_config = {"from_attributes": True}


class Token(BaseModel):
    access_token: str
    token_type: str = "bearer"


# ---- Scans ----
class ScanRequest(BaseModel):
    hostname: str = Field(min_length=1, max_length=255, examples=["github.com"])


class FindingOut(BaseModel):
    id: str
    title: str
    status: str            # pass | warn | fail | info
    severity: str          # info | low | medium | high
    detail: str
    fix: str | None = None
    owasp: list[str] = []
    weight: float = 1.0


class CategoryOut(BaseModel):
    key: str
    label: str
    score: float
    max_score: float
    findings: list[FindingOut]


class ScanResult(BaseModel):
    hostname: str
    grade: str
    score: float
    max_score: float
    categories: list[CategoryOut]
    summary: dict[str, int]   # counts of pass/warn/fail/info
    engine_version: str
    duration_ms: int


class ScanOut(BaseModel):
    id: str
    hostname: str            # may be masked depending on the endpoint
    grade: str
    score: float
    created_at: dt.datetime
    result: ScanResult | None = None

    model_config = {"from_attributes": True}


class ScanComparison(BaseModel):
    hostname: str
    before: ScanOut
    after: ScanOut
    improved: list[str]
    regressed: list[str]
    unchanged: list[str]


# ---- Domains ----
class DomainCreate(BaseModel):
    hostname: str = Field(min_length=1, max_length=255)
    note: str = ""


class DomainOut(BaseModel):
    id: str
    hostname: str
    note: str
    created_at: dt.datetime

    model_config = {"from_attributes": True}


# ---- Dashboard ----
class DashboardStats(BaseModel):
    total_scans: int
    unique_domains: int
    grade_distribution: dict[str, int]
    average_score: float
    top_failures: list[dict]
    recent_scans: list[ScanOut]
