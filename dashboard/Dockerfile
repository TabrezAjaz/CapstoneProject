FROM python:3.12-slim
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt && useradd --uid 10001 --create-home scanner
COPY dashboard ./dashboard
COPY reporters ./reporters
RUN mkdir -p dashboard/data && chown -R scanner:scanner /app
USER scanner
EXPOSE 5050
CMD ["python", "-m", "dashboard.app", "--host", "0.0.0.0", "--port", "5050"]