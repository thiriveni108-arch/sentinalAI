# Multi-stage or slim Python 3.11 image for SentinelAI FastAPI backend
FROM python:3.11-slim

# Prevent Python from writing .pyc files and enable unbuffered logging
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PYTHONPATH=/app/src \
    PORT=8000 \
    HOST=0.0.0.0 \
    SENTINEL_DATABASE_PATH=/app/data/sentinel_ai.db \
    SENTINEL_BOOTSTRAP_DEMO_DATA=true

WORKDIR /app

# Install system dependencies (libgomp1 is required for OpenMP in scikit-learn/scipy/qiskit)
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    libgomp1 \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Copy build configuration and full source tree so sentinel_ai installs correctly
COPY pyproject.toml README.md ./
COPY src/ ./src/

RUN pip install --no-cache-dir --upgrade pip && \
    pip install --no-cache-dir .

# Copy application configuration, runtime runner, and model/data assets
COPY config/ ./config/
COPY data/ ./data/
COPY artifacts/ ./artifacts/
COPY experiments/ ./experiments/
COPY run_server.py ./run_server.py

# Railway dynamically assigns $PORT at runtime
EXPOSE 8000

# Healthcheck endpoint (lightweight check without expensive model initialization)
HEALTHCHECK --interval=30s --timeout=5s --start-period=60s --retries=3 \
    CMD curl -f http://127.0.0.1:${PORT:-8000}/api/system/status || exit 1

# Start the FastAPI ASGI server using the Railway-aware runner
CMD ["python", "run_server.py"]
