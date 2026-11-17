FROM python:3.12-slim
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 DATA_DIR=/app/data LOG_DIR=/app/logs
WORKDIR /app
COPY requirements.lock .
RUN pip install --no-cache-dir -r requirements.lock && useradd --uid 10001 --create-home vigia && mkdir /app/data /app/logs && chown -R vigia:vigia /app
COPY --chown=vigia:vigia app ./app
COPY --chown=vigia:vigia tools ./tools
USER 10001:10001
EXPOSE 8000
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000", "--no-proxy-headers", "--no-server-header", "--no-access-log", "--limit-concurrency", "32", "--timeout-keep-alive", "5"]
