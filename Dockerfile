FROM python:3.12-slim

WORKDIR /app

# Deps del sistema mínimas
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY sentinel ./sentinel
COPY tests ./tests

ENTRYPOINT ["python", "-m", "sentinel.main"]
CMD ["--help"]
