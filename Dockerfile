FROM python:3.12-slim

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PIP_NO_CACHE_DIR=1

WORKDIR /app

# Install dependencies first for better layer caching.
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy the application.
COPY app ./app
COPY web ./web

EXPOSE 8000

# Tables are created on startup for SQLite; for Postgres run migrations via the
# pre-deploy hook (see docker-compose / README). Uvicorn serves API + SPA.
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]
