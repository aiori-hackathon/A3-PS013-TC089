FROM node:22-alpine AS frontend-build

WORKDIR /app/frontend
COPY frontend/package.json frontend/pnpm-lock.yaml ./
RUN npm install -g pnpm@9 && pnpm install --frozen-lockfile
COPY frontend/ ./
RUN pnpm run build


FROM python:3.11-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    DATABASE_URL=sqlite:////app/data/vigilance.db \
    EVIDENCE_STORAGE_PATH=/app/data/evidence_storage \
    REPORTS_PATH=/app/data/generated_reports \
    SAMPLE_DATA_PATH=/app/src/sample_data

WORKDIR /app

COPY src/backend/requirements.txt /app/src/backend/requirements.txt
RUN pip install --no-cache-dir -r /app/src/backend/requirements.txt

COPY src/backend /app/src/backend
COPY src/sample_data /app/src/sample_data
COPY --from=frontend-build /app/frontend/dist /app/frontend/dist

RUN mkdir -p /app/data/evidence_storage /app/data/generated_reports

WORKDIR /app/src/backend

EXPOSE 8000

CMD ["sh", "-c", "exec uvicorn app.main:app --host 0.0.0.0 --port ${PORT:-8000}"]
