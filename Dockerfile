# Multi-stage build for AgentForge
FROM python:3.11-slim AS builder

WORKDIR /app
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PIP_NO_CACHE_DIR=1

# Install uv for the same dep resolution as local dev
RUN pip install uv==0.11.13

COPY pyproject.toml uv.lock ./
RUN uv export --format requirements-txt --no-hashes --no-emit-project --output-file=requirements.txt
RUN pip install -r requirements.txt --target=/app/deps

# ---- runtime ----
FROM python:3.11-slim AS runtime

WORKDIR /app
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PYTHONPATH=/app:/app/deps \
    PORT=8000

# Drop privileges
RUN useradd --create-home --uid 1000 agentforge

COPY --from=builder /app/deps /app/deps
COPY agentforge/ /app/agentforge/
COPY evals/ /app/evals/
COPY alembic.ini /app/alembic.ini

# Ephemeral writable dirs that the app touches at runtime. Owned by the
# unprivileged runtime user so mkdir/writes inside the container succeed
# without a PV.
RUN mkdir -p /app/vulnerability_reports /app/evals/results \
    && chown -R agentforge:agentforge /app/vulnerability_reports /app/evals/results

USER agentforge

EXPOSE 8000

# Run migrations then start the API. Railway sets $PORT at runtime.
CMD ["sh", "-c", "python -m alembic upgrade head && python -m uvicorn agentforge.main:app --host 0.0.0.0 --port ${PORT:-8000}"]
