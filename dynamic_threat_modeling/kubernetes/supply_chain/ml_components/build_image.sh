#!/bin/bash
#
# Build and Push ML Inference Docker Image
#

set -e

IMAGE_NAME="npecka/ml-inference"
TAG="vulnerable"

echo "=================================="
echo "Building ML Inference Image"
echo "=================================="
echo ""

# Build image
echo "Building Docker image: ${IMAGE_NAME}:${TAG}"
docker build -t ${IMAGE_NAME}:${TAG} .

echo ""
echo "✅ Image built successfully!"
echo ""

# Optional: Push to registry (uncomment if needed)
read -p "Push image to Docker Hub? (y/n): " -n 1 -r
echo ""
if [[ $REPLY =~ ^[Yy]$ ]]; then
    echo "Pushing image to Docker Hub..."
    docker push ${IMAGE_NAME}:${TAG}
    echo "✅ Image pushed!"
else
    echo "Skipping push. Image available locally."
fi

echo ""
echo "To use this image in Kubernetes, it's already referenced in 06-ml-inference.yaml"
echo ""
echo "If running on local cluster (e.g., kind, minikube):"
echo "  kind load docker-image ${IMAGE_NAME}:${TAG}"
echo "  OR"
echo "  minikube image load ${IMAGE_NAME}:${TAG}"
echo ""
