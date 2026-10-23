FROM python:3.11-slim

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY app ./app
COPY static ./static
COPY scripts ./scripts

# non-root execution
RUN useradd --create-home --shell /usr/sbin/nologin gxuser \
    && mkdir -p /data \
    && chown -R gxuser:gxuser /app /data
USER gxuser

ENV GX_DATA_DIR=/data
VOLUME ["/data"]
EXPOSE 8000

HEALTHCHECK --interval=30s --timeout=5s CMD python -c "import httpx; httpx.get('http://127.0.0.1:8000/api/v1/health', timeout=4).raise_for_status()"

CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]
