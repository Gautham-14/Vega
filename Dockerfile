FROM python:3.11-slim
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY vega/ /app/vega/
COPY frontend/ /app/frontend/
COPY run_vega.py .
RUN mkdir -p /app/data/db /app/data/knowledge /app/data/workspaces /app/data/receipts /app/data/models /app/data/artifacts
EXPOSE 8000
ENV PYTHONUNBUFFERED=1
CMD ["python", "run_vega.py", "--host", "0.0.0.0", "--port", "8000"]
