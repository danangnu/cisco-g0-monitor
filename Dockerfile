FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

RUN apt-get update \
 && apt-get install -y --no-install-recommends tzdata \
 && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY monitor/ ./monitor/

RUN useradd --uid 10001 --create-home monitor \
 && mkdir -p /data /config \
 && chown monitor:monitor /data
USER monitor

VOLUME ["/data"]

HEALTHCHECK --interval=60s --timeout=10s --start-period=60s --retries=3 \
  CMD python -m monitor.healthcheck

ENTRYPOINT ["python", "-m", "monitor.main"]
