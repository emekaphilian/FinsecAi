FROM python:3.11-slim

WORKDIR /app

RUN apt-get update && apt-get install -y --no-install-recommends gcc libpq-dev \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY app ./app
# Copy tests and scripts from the build context (backend/) into /app/tests
# and /app/scripts so they are available at runtime.
# Use canonical locations to avoid nested `/app/backend/...` paths.
COPY tests ./tests
COPY scripts ./scripts

EXPOSE 8000
CMD ["sh", "-c", "uvicorn app.main:app --host 0.0.0.0 --port ${PORT:-8000}"]
