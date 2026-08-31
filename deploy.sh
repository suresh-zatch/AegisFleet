#!/usr/bin/env bash
# AegisFleet Cloud Run Deployment Script
# Usage: ./deploy.sh [PROJECT_ID] [REGION]

set -euo pipefail

PROJECT_ID="${1:-aegisfleet-demo}"
REGION="${2:-us-central1}"
SERVICE_NAME="aegisfleet-soc"
IMAGE_TAG="gcr.io/${PROJECT_ID}/${SERVICE_NAME}:latest"

echo "============================================"
echo "  AegisFleet SOC - Cloud Run Deployment"
echo "============================================"
echo "  Project:  ${PROJECT_ID}"
echo "  Region:   ${REGION}"
echo "  Service:  ${SERVICE_NAME}"
echo "  Image:    ${IMAGE_TAG}"
echo "============================================"

# Set the active project
echo "[1/5] Setting active GCP project..."
gcloud config set project "${PROJECT_ID}"

# Build the Docker image
echo "[2/5] Building Docker image..."
docker build -t "${IMAGE_TAG}" .

# Push to Google Container Registry
echo "[3/5] Pushing to Container Registry..."
docker push "${IMAGE_TAG}"

# Deploy to Cloud Run
echo "[4/5] Deploying to Cloud Run..."
gcloud run deploy "${SERVICE_NAME}" \
    --image "${IMAGE_TAG}" \
    --region "${REGION}" \
    --platform managed \
    --allow-unauthenticated \
    --memory 1Gi \
    --cpu 2 \
    --timeout 300 \
    --set-env-vars "AEGISFLEET_GCP_PROJECT_ID=${PROJECT_ID},AEGISFLEET_SANDBOX_MODE=true" \
    --min-instances 0 \
    --max-instances 10

# Get the service URL
echo "[5/5] Deployment complete!"
SERVICE_URL=$(gcloud run services describe "${SERVICE_NAME}" --region "${REGION}" --format 'value(status.url)')
echo ""
echo "============================================"
echo "  AegisFleet SOC is LIVE!"
echo "  URL: ${SERVICE_URL}"
echo "============================================"
