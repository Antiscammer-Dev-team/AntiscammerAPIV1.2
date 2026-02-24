# AntiScammer API - Coolify compatible
FROM python:3.11-slim

# Create non-root user for security
RUN groupadd --gid 1000 appuser \
    && useradd --uid 1000 --gid appuser --shell /bin/bash --create-home appuser

WORKDIR /app

# Install dependencies (repo root = AntiscammerAPIV1.2)
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application
COPY . .

# Create data directory and set ownership
RUN mkdir -p data/ban_requests data/false_positive_reports \
    && chown -R appuser:appuser /app

USER appuser

# Coolify compatibility: listen on 0.0.0.0, use PORT env (default 8000)
ENV PORT=8000
EXPOSE 8000

# Health check - app exposes /ready
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD python -c "import os, urllib.request; urllib.request.urlopen(f'http://127.0.0.1:{os.environ.get(\"PORT\", 8000)}/ready')" || exit 1

# Shell form for PORT env expansion (Coolify injects PORT)
CMD uvicorn app:app --host 0.0.0.0 --port ${PORT}
