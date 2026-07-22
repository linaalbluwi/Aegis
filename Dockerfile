FROM python:3.13-slim

RUN groupadd -r aegis && useradd -r -g aegis aegis

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

RUN pip install --no-cache-dir -e .

RUN mkdir -p logs certs && chown -R aegis:aegis /app

USER aegis

EXPOSE 8443

HEALTHCHECK --interval=30s --timeout=3s \
    CMD python -c "import urllib.request; urllib.request.urlopen('http://localhost:8443/health')" || exit 1

CMD ["python", "run.py"]
