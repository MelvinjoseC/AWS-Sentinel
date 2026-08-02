# Stage 1: Build dependencies
FROM python:3.10-slim AS builder

WORKDIR /app

RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install --user --no-warn-script-location --no-cache-dir -r requirements.txt

# Stage 2: Final minimal image
FROM python:3.10-slim AS runner

WORKDIR /app

# Copy installed packages from builder
COPY --from=builder /root/.local /root/.local
COPY . .

# Set PATH to find user-installed scripts
ENV PATH=/root/.local/bin:$PATH
ENV PYTHONUNBUFFERED=1

ENTRYPOINT ["python", "sentinel.py"]
