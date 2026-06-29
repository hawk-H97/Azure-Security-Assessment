FROM python:3.11-slim

LABEL maintainer="Singaram" \
      description="Azure Audit Pro v1 — Azure Security Assessment Tool" \
      version="1.0.0"

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    TERM=xterm-256color

# Install system deps
RUN apt-get update && apt-get install -y --no-install-recommends \
    curl ca-certificates && \
    rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Copy requirements first for layer caching
COPY requirements.txt .
RUN pip install --no-cache-dir --upgrade pip && \
    pip install --no-cache-dir -r requirements.txt

# Copy the entire tool
COPY . .

# Create output directory
RUN mkdir -p /app/output /app/compliance/azure

# Run the audit tool
ENTRYPOINT ["python", "main.py"]
