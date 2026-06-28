# ==========================================================
# Scanner image — bundles Trivy + the Python wrapper.
# Build:  docker build -t vuln-scanner -f docker/Dockerfile .
# Run:    docker run --rm \
#           -v /var/run/docker.sock:/var/run/docker.sock \
#           -v trivy-cache:/root/.cache/ \
#           vuln-scanner nginx:latest
# ==========================================================

# Stage 1 — grab the Trivy binary from the official image
FROM aquasec/trivy:latest AS trivy

# Stage 2 — Python runtime + our wrapper
FROM python:3.12-slim

# Copy the Trivy binary from stage 1
COPY --from=trivy /usr/local/bin/trivy /usr/local/bin/trivy

WORKDIR /app

# Install Python dependencies first (better layer caching)
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy the project
COPY . .

# Default entrypoint runs the scanner; pass an image name as the argument
ENTRYPOINT ["python", "-m", "scanner.trivy_scanner"]
