FROM node:20-bookworm-slim AS frontend-build

WORKDIR /app/ai-document-forensics-react
COPY ai-document-forensics-react/package.json ai-document-forensics-react/package-lock.json ./
RUN npm ci
COPY ai-document-forensics-react/ ./
RUN npm run build

FROM python:3.11-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    FORENSAI_DATABASE_BACKEND=postgres \
    FORENSAI_STORAGE_BACKEND=s3

RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        gettext-base \
        libgl1 \
        libglib2.0-0 \
        libgomp1 \
        nginx \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY backend/requirements.txt ./backend/requirements.txt
RUN python -m pip install --upgrade pip \
    && python -m pip install -r backend/requirements.txt
COPY backend/ ./backend/
COPY start.sh ./start.sh
COPY deploy/nginx.conf.template /etc/nginx/templates/forensai.conf.template
COPY --from=frontend-build /app/ai-document-forensics-react/dist ./frontend-dist/

EXPOSE 8080
ENTRYPOINT ["bash", "/app/start.sh"]
