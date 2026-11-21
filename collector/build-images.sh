#!/bin/bash
# Build and optionally publish the central-monitoring-collector NS8 module image.

set -e

REPO_OWNER="${REPO_OWNER:-${IMAGE_ORG:-bls-isp}}"
REPO_OWNER_LOWER="$(printf '%s' "${REPO_OWNER}" | tr '[:upper:]' '[:lower:]')"
REPOBASE="${REPOBASE:-${REPobase:-ghcr.io/${REPO_OWNER_LOWER}}}"
IMAGE_NAME="${IMAGE_NAME:-central-monitoring-collector}"
IMAGE_TAG="${IMAGE_TAG:-${IMAGETAG:-${TAG:-latest}}}"
CONTAINER_ENGINE="${CONTAINER_ENGINE:-auto}"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

cd "${SCRIPT_DIR}"

if [[ ! -f "ui/dist/index.html" ]]; then
    echo "Building Collector Cockpit UI bundle..."
    npm --prefix ui ci
    npm --prefix ui run build
fi

FULL_IMAGE="${REPOBASE}/${IMAGE_NAME}:${IMAGE_TAG}"

if [[ "${CONTAINER_ENGINE}" == "docker" ]] && command -v docker >/dev/null 2>&1; then
    docker build -f Containerfile -t "${FULL_IMAGE}" .
    if [[ "${PUSH_IMAGE:-0}" == "1" ]]; then
        docker push "${FULL_IMAGE}"
    fi
elif command -v buildah >/dev/null 2>&1; then
    buildah bud -f Containerfile -t "${FULL_IMAGE}" .
    if [[ "${PUSH_IMAGE:-0}" == "1" ]]; then
        buildah push "${FULL_IMAGE}" "docker://${FULL_IMAGE}"
    fi
else
    docker build -f Containerfile -t "${FULL_IMAGE}" .
    if [[ "${PUSH_IMAGE:-0}" == "1" ]]; then
        docker push "${FULL_IMAGE}"
    fi
fi

if [[ -n "${GITHUB_OUTPUT:-}" ]]; then
    printf 'images=%s\n' "${FULL_IMAGE}" >> "${GITHUB_OUTPUT}"
fi
