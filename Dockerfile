FROM python:3.11-slim

# Set environment variables for Python runtime and application defaults
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    LEDGER_DB_PATH=/app/data/agent.db \
    PORT=8000

# Set working directory
WORKDIR /app

# Copy dependency definition first for optimal layer caching
COPY requirements.txt /app/requirements.txt

# Install dependencies without caching wheel packages
RUN pip install --no-cache-dir -r /app/requirements.txt

# Create a non-root system user and ensure runtime data directory exists
RUN useradd -u 1000 -m -s /bin/bash appuser && \
    mkdir -p /app/data && \
    chown -R appuser:appuser /app

# Copy application source code and adjust ownership
COPY --chown=appuser:appuser . /app
RUN chown -R appuser:appuser /app

# Switch to non-privileged user for security
USER appuser

# Expose API port
EXPOSE 8000

# Container healthcheck probing root service discovery endpoint
HEALTHCHECK --interval=30s --timeout=10s --start-period=10s --retries=3 \
    CMD python -c "import os, urllib.request; urllib.request.urlopen(f'http://127.0.0.1:{os.environ.get(\"PORT\", \"8000\")}/')"

# Start ASGI application server
CMD ["sh", "-c", "uvicorn api:app --host 0.0.0.0 --port ${PORT:-8000}"]
