FROM python:3.12-slim
WORKDIR /app
ENV PYTHONUNBUFFERED=1 CYBERTWIN_DATA_DIR=/app/data PORT=8000
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY backend ./backend
COPY frontend ./frontend
COPY scripts ./scripts
VOLUME /app/data
EXPOSE 8000
CMD ["sh", "-c", "python -m uvicorn backend.main:app --host 0.0.0.0 --port ${PORT}"]
