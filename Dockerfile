FROM python:3.12-slim
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 \
    AUDIT_DB=/app/data/audit_log.db AUDIT_KEY=/app/keys/signing.key
WORKDIR /app
COPY pyproject.toml requirements.txt README.md ./
COPY core ./core
COPY server ./server
COPY cli ./cli
COPY simulation ./simulation
RUN pip install --no-cache-dir . \
    && groupadd --gid 10001 audit \
    && useradd --uid 10001 --gid 10001 --no-create-home audit \
    && install -d -o audit -g audit -m 0700 data keys
USER audit
EXPOSE 8000
CMD ["uvicorn", "server.api:app", "--host", "0.0.0.0", "--port", "8000"]
