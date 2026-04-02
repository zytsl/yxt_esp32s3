FROM python:3.13-slim

WORKDIR /app
COPY scripts/local_ota_ws_server.py /app/server.py

RUN pip install --no-cache-dir aiohttp==3.13.3

EXPOSE 8780 8781

ENTRYPOINT ["python", "/app/server.py"]
