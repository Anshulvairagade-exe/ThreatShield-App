FROM python:3.12-slim
WORKDIR /code
COPY backend/requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt \
  && useradd -m -u 10001 appuser
COPY backend/app ./app
COPY backend/alembic ./alembic
COPY backend/alembic.ini .
COPY backend/entrypoint.sh ./entrypoint.sh
COPY threat_intel ./threat_intel
COPY zero_day_model_package ./zero_day_model_package
RUN chmod +x ./entrypoint.sh && chown -R appuser:appuser /code
USER appuser
EXPOSE 8000
ENTRYPOINT ["./entrypoint.sh"]
