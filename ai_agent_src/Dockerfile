FROM python:3.11-slim
WORKDIR /app

RUN apt-get update && apt-get install -y libpq-dev gcc curl && rm -rf /var/lib/apt/lists/*

# Never run as root inside the container
RUN addgroup --system --gid 1001 appgroup \
 && adduser  --system --uid 1001 --ingroup appgroup appuser

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .
RUN chown -R appuser:appgroup /app

USER appuser

CMD ["sh", "-c", "alembic upgrade head && uvicorn main:app --host 0.0.0.0 --port 8000"]