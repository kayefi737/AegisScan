# 🛡️ AegisScan

**Grade any website's external security posture in about ten seconds.**

You type a hostname. AegisScan runs 20+ passive, read-only checks across **nine**
categories, computes a transparent **A+ → F** grade, and hands back a report where
every failure carries the *exact configuration line to fix it* and its *OWASP Top-10
mapping*. No installation, no signup, no external services required to run it.

AegisScan is a stronger sibling of **PostureScan** (TechCrush Cloud Computing
cohort 6, Group 12). It keeps what made PostureScan good (instant grading,
concrete fixes, guest scanning, a privacy-aware public dashboard) and pushes
several items straight off PostureScan's own "future work" slide into the product:
deeper checks, OWASP mapping, and a first-class documented REST API. It also runs
with a **single command and zero managed services**, which the original could not.

> Built: 17 June 2026. The code in this repo was authored carefully but **not executed
> in the environment it was written in** (no sandbox was available). The
> [Quick start](#-quick-start) and [Testing](#-testing) sections give you exact
> commands to run and verify it locally; start there.

---

## Table of contents

1. [The idea](#-the-idea)
2. [What's stronger than PostureScan](#-whats-stronger-than-posturescan)
3. [How it works (the flow)](#-how-it-works-the-flow)
4. [Architecture](#-architecture)
5. [Tech stack](#-tech-stack)
6. [The checks (all nine categories)](#-the-checks-all-nine-categories)
7. [Scoring rubric](#-scoring-rubric)
8. [Quick start](#-quick-start)
9. [Configuration](#-configuration)
10. [REST API reference](#-rest-api-reference)
11. [Reports](#-reports)
12. [Security model & the SSRF guard](#-security-model--the-ssrf-guard)
13. [Testing](#-testing)
14. [Project structure](#-project-structure)
15. [Deployment & CI/CD](#-deployment--cicd)
16. [Roadmap](#-roadmap)
17. [Responsible use](#-responsible-use)
18. [License](#-license)

---

## 💡 The idea

Three things are true about web security today:

1. **Almost every production site has at least one trivially fixable
   misconfiguration**: a missing security header, a cookie without `Secure`, a
   domain with no DMARC record.
2. **Finding those issues normally means assembling five specialist tools** and
   reading five different specifications.
3. **The comprehensive scanners hide behind signup gates and pricing pages**, and
   the free tools each cover only one category.

So even though everyone agrees these checks should run, in practice almost nobody
runs them. AegisScan closes that gap: **one input, one report, every check, with the
fix written out for you.**

---

## 🚀 What's stronger than PostureScan

| Area | PostureScan | **AegisScan** |
|---|---|---|
| Check categories | 8 | **9** (adds a dedicated deep-CSP category + `.well-known`) |
| Email auth | DMARC | **SPF + DMARC + CAA + DNSSEC** |
| Header coverage | core set | adds **Referrer-Policy, Permissions-Policy, COOP, version-disclosure** |
| OWASP mapping | future work | **every finding maps to OWASP Top-10 2021** ✅ |
| Documented REST API | future work | **auto-generated OpenAPI/Swagger at `/docs`** ✅ |
| Scan engine | sequential | **async, concurrent probes** (`asyncio.gather`) |
| Scoring | grade shown | **published, reproducible weighted rubric** (`/api/meta`) |
| Run requirements | React + Django + Supabase + Railway + Vercel | **one `uvicorn` command, SQLite, zero managed services** |
| Reports | PDF (auth) | **JSON + HTML (public) + PDF (auth)** |
| Driver/runtime bugs | hit `psycopg2` + Sentry crashes on Py 3.13 | **ships `psycopg` v3 + Sentry ≥ 2.61**, those exact bugs pre-fixed |
| Adding a check | edit the scanner | **drop a function into a check module**, the runner picks it up |

The last three rows are deliberate: PostureScan's own slides 9–10 document the
`psycopg2`-on-Python-3.13 failure, the Sentry recursion crash, and the CORS-preview
mismatch. AegisScan pins the fixed versions and uses one regex CORS rule so those
problems never occur here.

---

## 🔄 How it works (the flow)

```
hostname ─▶ normalize ─▶ SSRF guard ─▶ probe (concurrent) ─▶ evaluate ─▶ score ─▶ store ─▶ report
                          │                │                    │           │
                          │                │                    │           └─ weighted A+→F grade
                          │                │                    └─ 20+ pure check functions read the probe
                          │                └─ HTTPS GET, HTTP GET, TLS handshake, DNS, /.well-known (in parallel)
                          └─ resolve + reject private / loopback / reserved IPs
```

1. **Normalize** the input: strip scheme, path, port, userinfo → bare hostname.
2. **Guard**: resolve it and refuse to continue if it points at a private,
   loopback, link-local or reserved address (SSRF protection).
3. **Probe once, concurrently**: a single HTTPS request (following redirects), a
   plain-HTTP request (to test the redirect-to-HTTPS), a raw TLS handshake, a batch
   of DNS lookups, and a `/.well-known/security.txt` fetch, all in parallel.
4. **Evaluate**: every check is a *pure function* that reads the shared probe data
   and returns findings. No check makes its own network call, so the engine is fast
   and deterministic to test.
5. **Score** with the published rubric → grade.
6. **Store** the full structured result and return it.

---

## 🏗️ Architecture

```
                ┌──────────────────────────────────────────────┐
   Browser ───▶ │  FastAPI app (uvicorn)                        │
   (SPA)        │   ├─ /            served single-page frontend  │
                │   ├─ /api/*       JSON REST API + JWT auth      │
                │   ├─ /docs        auto OpenAPI / Swagger UI     │
                │   └─ scan engine  async, pure check functions   │
                └───────────────┬──────────────────────────────┘
                                │ SQLAlchemy
                                ▼
                    ┌────────────────────────┐
                    │ SQLite (default)        │   swap to Postgres
                    │ or Postgres (optional)  │   with one env var
                    └────────────────────────┘

   The scan engine reaches OUT to target sites, strictly read-only, behind an
   SSRF guard that blocks private address space.
```

Unlike PostureScan's five-service production topology (React/Vercel ×2 +
Django/Railway ×2 + Supabase), AegisScan is **one process** that serves the API and
the frontend together. That is a deliberate trade: far simpler to run and reason
about for a single-team project, and it still scales out behind a load balancer
because it is stateless apart from the database.

---

## 🧰 Tech stack

| Layer | Choice | Why |
|---|---|---|
| API | **FastAPI** (Python 3.11–3.13) | async, typed, free OpenAPI docs |
| Server | **uvicorn** | ASGI, one command |
| ORM / DB | **SQLAlchemy 2** → **SQLite** default / **Postgres** optional | zero-config locally, production-ready when needed |
| Auth | **JWT** (python-jose) + **bcrypt** (passlib) | stateless guest + authenticated flows |
| Probing | **httpx** (async) + stdlib `ssl`/`socket` + **dnspython** | concurrent, no heavy deps |
| Reports | **Jinja2** (HTML) + **reportlab** (PDF) | reportlab is pure-Python, no system libraries |
| Frontend | **vanilla JS + Tailwind (CDN)** | no build step; the whole app runs from `uvicorn` |
| Monitoring | **sentry-sdk ≥ 2.61** (optional) | the version that does *not* crash on Python 3.13 |
| Tests | **pytest** | runs fully offline |
| CI | **GitHub Actions** (3.11 / 3.12 / 3.13 matrix) | catches driver/runtime breakage early |

All open source. All standard. Nothing exotic.

---

## 🔍 The checks (all nine categories)

Each finding is `pass` / `warn` / `fail` / `info`, carries a severity and a weight,
and (on failure) a concrete fix plus an OWASP Top-10 mapping.

### 1. TLS & Transport (`tls`)
- Site reachable over HTTPS
- Modern TLS protocol negotiated (TLS 1.2 / 1.3)
- Certificate is current (expiry + issuer)
- Plain HTTP redirects to HTTPS

### 2. Security Headers (`headers`)
- `Strict-Transport-Security` (HSTS) present, with a sane `max-age`
- `X-Content-Type-Options: nosniff`
- Clickjacking protection (`X-Frame-Options` **or** CSP `frame-ancestors`)
- `Referrer-Policy` set to a privacy-preserving value
- `Permissions-Policy` present
- `Cross-Origin-Opener-Policy` present
- Software version not disclosed (`Server` / `X-Powered-By`)

### 3. Content Security Policy (`csp`): *deep analysis*
- CSP header present
- No `'unsafe-inline'` in the script context
- No `'unsafe-eval'`
- A `default-src` fallback is defined
- `object-src 'none'` (plugins disabled)
- No wildcard (`*`) sources

### 4. Cookies (`cookies`)
- Every `Set-Cookie` has `Secure`, `HttpOnly`, and `SameSite`

### 5. DNS & Email Authentication (`dns_email`)
- **DMARC** policy published (and not stuck on `p=none`)
- **SPF** record published
- **CAA** record restricts certificate issuance
- **DNSSEC** enabled (advisory)

### 6. Redirects (`redirects`)
- Redirect chain length is reasonable
- No HTTPS→HTTP downgrade anywhere in the chain

### 7. Mixed Content (`mixed_content`)
- No `http://` assets referenced on an `https://` page

### 8. HTTP Protocol (`http_protocol`)
- Modern HTTP protocol (HTTP/2 or HTTP/3)

### 9. Disclosure & `.well-known` (`wellknown`)
- `security.txt` published per RFC 9116

> **Adding a check** is a one-file change: write a function that takes a
> `ProbeContext` and returns `list[Finding]`, then register it in
> `app/engine/runner.py:CATEGORIES`. No engine surgery required.

---

## 🧮 Scoring rubric

The grade is never a black box. The full rubric is also served live at
**`GET /api/meta`**.

**Status credit** (how much of a finding's weight each status earns):

| status | credit |
|---|---|
| `pass` | 100% |
| `info` | excluded from scoring (contextual only) |
| `warn` | 50% |
| `fail` | 0% |

**Category score** = `sum(weight × credit) / sum(weight)` over its findings.

**Category weights** (relative importance in the final grade):

| category | weight |
|---|---|
| `tls` | 2.0 |
| `headers` | 2.0 |
| `csp` | 1.5 |
| `dns_email` | 1.5 |
| `cookies` | 1.0 |
| `redirects` | 1.0 |
| `mixed_content` | 1.0 |
| `http_protocol` | 0.5 |
| `wellknown` | 0.5 |

**Overall score** = weighted mean of the category scores × 100.

**Grade bands:** A+ ≥ 95 · A ≥ 90 · B ≥ 80 · C ≥ 70 · D ≥ 60 · F < 60.

*Worked example:* a site that aces everything except it is missing HSTS (one
`fail`, weight 2.0, inside the `headers` category) loses part of the `headers`
score, which is then weighted at 2.0 in the mean, so a single high-value miss
visibly moves the grade, exactly as intended.

---

## ⚡ Quick start

**Prerequisites:** Python 3.11+ (3.13 supported). That's it: no Node, no database
server, no cloud accounts.

```bash
# 1. clone / enter the project
cd AegisScan

# 2. create a virtual environment
python -m venv .venv
source .venv/bin/activate        # Windows: .venv\Scripts\activate

# 3. install
pip install -r requirements.txt

# 4. (optional) copy env defaults; the app also runs with no .env at all
cp .env.example .env

# 5. run
uvicorn app.main:app --reload
```

Now open:

- **http://127.0.0.1:8000/**: the app (scan a domain)
- **http://127.0.0.1:8000/docs**: interactive API documentation
- **http://127.0.0.1:8000/api/health**: health check

Scan something from the command line:

```bash
curl -X POST http://127.0.0.1:8000/api/scans \
     -H "Content-Type: application/json" \
     -d '{"hostname": "github.com"}'
```

### Run with Docker instead

```bash
docker build -t aegisscan .
docker run -p 8000:8000 aegisscan
```

### Run against Postgres (mirrors a production setup)

```bash
docker compose up        # starts Postgres + the API wired together
```

---

## ⚙️ Configuration

Every value has a safe default; the app runs with **no `.env`**. Override via env
vars (all prefixed `AEGIS_`) or a `.env` file. See `.env.example`.

| Variable | Default | Purpose |
|---|---|---|
| `AEGIS_ENV` | `development` | `development` / `staging` / `production` |
| `AEGIS_SECRET_KEY` | dev placeholder | **change in any deployment**; signs JWTs |
| `AEGIS_DATABASE_URL` | `sqlite:///./aegisscan.db` | SQLite or `postgresql+psycopg://…` |
| `AEGIS_CORS_ALLOW_ORIGIN_REGEX` | localhost + `*.vercel.app` | one regex matches every preview host |
| `AEGIS_SCAN_TIMEOUT_SECONDS` | `10` | per-probe network timeout |
| `AEGIS_ALLOW_PRIVATE_TARGETS` | `false` | **never `true` in production** (SSRF) |
| `AEGIS_RATE_LIMIT_PER_MINUTE` | `20` | per-IP scan submissions |
| `AEGIS_PUBLIC_BENCHMARKS` | github, stripe, … | hostnames shown un-masked on the dashboard |
| `AEGIS_SENTRY_DSN` | empty | optional error monitoring |

Generate a real secret key:

```bash
python -c "import secrets; print(secrets.token_urlsafe(48))"
```

---

## 🔌 REST API reference

Full interactive docs live at **`/docs`** (Swagger) and **`/redoc`**. Summary:

| Method | Path | Auth | Description |
|---|---|---|---|
| `GET` | `/api/health` | – | liveness + version |
| `GET` | `/api/meta` | – | scoring rubric + category list |
| `POST` | `/api/auth/register` | – | create an account |
| `POST` | `/api/auth/login` | – | get a JWT (OAuth2 password form) |
| `GET` | `/api/auth/me` | ✅ | current user |
| `POST` | `/api/scans` | optional | run a scan (guest or authenticated) |
| `GET` | `/api/scans` | ✅ | your scan history |
| `GET` | `/api/scans/{id}` | – | fetch one scan (full result) |
| `GET` | `/api/scans/compare?before=&after=` | – | diff two scans of the same host |
| `GET` | `/api/scans/{id}/report.html` | – | standalone HTML report |
| `GET` | `/api/scans/{id}/report.pdf` | ✅ | PDF report (authenticated extra) |
| `GET` | `/api/dashboard` | – | public aggregate stats (masked hostnames) |
| `GET/POST/DELETE` | `/api/domains` | ✅ | track domains you care about |

Guest vs authenticated mirrors PostureScan: anyone can scan; accounts unlock
history, domain tracking, scan comparison, and PDF export.

---

## 📄 Reports

Every scan can be rendered three ways:

- **JSON**: the raw `POST /api/scans` response or `GET /api/scans/{id}`. Machine
  readable; drop it into your own CI pipeline.
- **HTML**: `GET /api/scans/{id}/report.html`. A clean standalone page.
- **PDF**: `GET /api/scans/{id}/report.pdf` (authenticated). Generated with
  reportlab, so there are **no system libraries to install** (a common pain with
  HTML-to-PDF tools).

---

## 🔒 Security model & the SSRF guard

A scanner that fetches user-supplied URLs is a classic SSRF risk. AegisScan defends
in depth (`app/guard.py`):

- The hostname is normalized and obviously-local names (`localhost`, `*.local`) are
  rejected outright.
- The host is resolved and **every** resolved IP is checked. If any is private,
  loopback, link-local, multicast, reserved or unspecified, the scan is refused.
- All probing is **read-only** `GET` traffic with a fixed, identifying User-Agent.
- Per-IP rate limiting caps abuse.

`AEGIS_ALLOW_PRIVATE_TARGETS=true` exists only for scanning your *own* lab and must
never be enabled in a public deployment.

---

## 🧪 Testing

The suite runs **fully offline**: the one scan success-path test monkeypatches the
engine, and the guard tests monkeypatch DNS resolution. No real hosts are contacted.

```bash
pytest -q
```

What's covered:

- `test_scoring.py`: grade bands, warning = half credit, info excluded, category weighting
- `test_guard.py`: normalization + SSRF blocking of private/loopback IPs
- `test_masking.py`: dashboard hostname masking + benchmark allowlist
- `test_checks.py`: individual checks against synthetic probe data
- `test_api.py`: health, meta, register/login, validation, scan persistence, auth gating, domain tracking

CI runs this matrix on Python **3.11, 3.12 and 3.13** on every push to `main` or
`staging` (`.github/workflows/ci.yml`).

---

## 🗂️ Project structure

```
AegisScan/
├── app/
│   ├── main.py            FastAPI app: CORS, routers, serves the SPA, /docs
│   ├── config.py          env-driven settings (safe defaults)
│   ├── database.py        SQLAlchemy engine/session (SQLite or Postgres)
│   ├── models.py          User, Scan, TrackedDomain
│   ├── schemas.py         pydantic request/response models
│   ├── auth.py            JWT + bcrypt, guest/auth dependencies
│   ├── guard.py           SSRF guard + hostname normalization
│   ├── scoring.py         weights, status credit, grade bands
│   ├── masking.py         privacy-aware hostname masking
│   ├── reporting.py       HTML (Jinja2) + PDF (reportlab)
│   ├── ratelimit.py       per-IP sliding window
│   ├── routers/           auth · scans · dashboard · domains
│   └── engine/
│       ├── runner.py      orchestrates guard → probe → evaluate → score
│       ├── base.py        Finding / ProbeContext types
│       └── checks_*.py    one module per category (pure functions)
├── web/                   index.html + app.js (the SPA)
├── tests/                 pytest suite (offline)
├── .github/workflows/     CI
├── Dockerfile · docker-compose.yml
├── requirements.txt · .env.example · .gitignore · LICENSE
└── README.md
```

---

## 🚢 Deployment & CI/CD

AegisScan keeps the parts of PostureScan's pipeline that worked and removes the
parts that bit them.

**Branch model (kept):** develop on `staging`, promote to `main` by
**fast-forward only**. `main` is therefore always a strict ancestor of `staging`, with
no merge commits, no divergence. CI must be green before promotion.

**Migrations (fixed):** PostureScan's migrations silently didn't run because the
Nixpacks builder ignored the Procfile release line. AegisScan creates tables on
startup for SQLite, and for Postgres you run Alembic in an explicit pre-deploy hook
(e.g. Railway `railway.json` `preDeployCommand`, or `alembic upgrade head` in your
container entrypoint), never relying on an implicit Procfile line.

**CORS (fixed):** one **regex** rule (`AEGIS_CORS_ALLOW_ORIGIN_REGEX`) matches every
ephemeral preview hostname, so preview deploys are never rejected.

**Driver/runtime (fixed):** `psycopg` v3 (Python-3.13 wheels) and `sentry-sdk`
≥ 2.61 are pinned, pre-empting the two crashes the original hit.

A typical hosted setup: container (this repo) on any platform that runs a Dockerfile
(Railway, Fly, Render, Cloud Run), a managed Postgres (Supabase/Neon/RDS), optional
Sentry. Because the frontend is served by the same process, there's no separate
frontend deployment to keep in sync.

---

## 🛣️ Roadmap

- Scheduled re-scans with email alerts when a tracked domain's grade drops
- More categories: certificate transparency, IPv6 reachability, deeper CSP nonce/hash validation
- Map findings to compliance frameworks (PCI-DSS, SOC 2) in addition to OWASP
- A browser extension showing the current site's grade as you browse
- Multi-region scanning to catch CDN/region-specific issues
- Redis-backed rate limiting + result caching for multi-instance deployments

---

## ⚖️ Responsible use

AegisScan performs **only passive, read-only inspection** of externally reachable
endpoints. Do not point it at systems you do not own or do not have explicit
permission to test. The SSRF guard blocks private address space by default; keep it
that way in any shared deployment.

---

## 📜 License

MIT. See [`LICENSE`](./LICENSE).

*AegisScan stands on the shoulders of PostureScan. Thanks to that team for a sharp
problem statement and an honest write-up of what broke; several fixes here exist
because their slides documented the failure so clearly.*
