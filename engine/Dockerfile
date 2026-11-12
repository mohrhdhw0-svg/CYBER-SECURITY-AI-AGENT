FROM python:3.12-slim
RUN apt-get update && apt-get install -y --no-install-recommends nmap ca-certificates && rm -rf /var/lib/apt/lists/*
WORKDIR /srv
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY main.py .
RUN useradd --create-home --uid 10001 runner
USER runner
EXPOSE 8080
CMD ["sh", "-c", "uvicorn main:app --host 0.0.0.0 --port ${PORT:-8080}"]
