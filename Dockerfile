FROM python:3.12-slim

# Prevents Python from writing .pyc, ensures logs are flushed
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1

WORKDIR /app

# System deps (kept minimal)
RUN apt-get update \
    && apt-get install -y --no-install-recommends build-essential \
    && rm -rf /var/lib/apt/lists/*

# Install Python dependencies (include gunicorn for production serving)
COPY backend/requirements.txt /app/requirements.txt
RUN pip install -r requirements.txt gunicorn==21.2.0

# Copy application source
COPY backend/ /app/

# Default runtime env
ENV PORT=5000 \
    SESSION_COOKIE_SECURE=false

EXPOSE 5000

# Use gunicorn without --factory via explicit wsgi callable
CMD ["gunicorn", "--bind", "0.0.0.0:5000", "--workers", "2", "--threads", "4", "--timeout", "60", "wsgi:app"]
