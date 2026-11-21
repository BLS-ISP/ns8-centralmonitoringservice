#!/usr/bin/env bash
# Build central-monitoring-hub-gateway and central-monitoring-hub OCI images

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"

RAW_OWNER="${REPO_OWNER:-${IMAGE_ORG:-bls-isp}}"
OWNER="${RAW_OWNER,,}"
REPOBASE="${REPOBASE:-ghcr.io/${OWNER}}"
IMAGE_TAG="${IMAGE_TAG:-${IMAGETAG:-${TAG:-latest}}}"
CONTAINER_ENGINE="${CONTAINER_ENGINE:-auto}"

GATEWAY_IMAGE="${GATEWAY_IMAGE:-${REPOBASE}/central-monitoring-hub-gateway:${IMAGE_TAG}}"
HUB_IMAGE="${HUB_IMAGE:-${REPOBASE}/central-monitoring-hub:${IMAGE_TAG}}"

# Build Hub Cockpit UI bundle if not already compiled
if [[ ! -f "${REPO_ROOT}/hub/ui/dist/index.html" ]]; then
    if [[ -f "${REPO_ROOT}/hub/ui/package.json" ]] && command -v npm >/dev/null 2>&1; then
        echo "Building Hub Cockpit UI (hub/ui/dist)..."
        if [[ -f "${REPO_ROOT}/hub/ui/package-lock.json" ]]; then
            npm --prefix "${REPO_ROOT}/hub/ui" ci
        else
            npm --prefix "${REPO_ROOT}/hub/ui" install
        fi
        npm --prefix "${REPO_ROOT}/hub/ui" run build
    else
        mkdir -p "${REPO_ROOT}/hub/ui/dist"
        printf '<!DOCTYPE html><html><head><title>Central Monitoring Hub</title></head><body></body></html>\n' > "${REPO_ROOT}/hub/ui/dist/index.html"
    fi
fi

run_container_build() {
    local tag="$1"
    local containerfile="$2"
    local context_dir="$3"
    shift 3

    if [[ "${CONTAINER_ENGINE}" == "docker" ]] && command -v docker >/dev/null 2>&1; then
        docker build -t "${tag}" -f "${containerfile}" "$@" "${context_dir}"
    elif [[ "${CONTAINER_ENGINE}" == "podman" ]] && command -v podman >/dev/null 2>&1; then
        podman build --format oci -t "${tag}" -f "${containerfile}" "$@" "${context_dir}"
    elif command -v buildah >/dev/null 2>&1; then
        buildah bud --format oci -t "${tag}" -f "${containerfile}" "$@" "${context_dir}"
    elif command -v podman >/dev/null 2>&1; then
        podman build --format oci -t "${tag}" -f "${containerfile}" "$@" "${context_dir}"
    elif command -v docker >/dev/null 2>&1; then
        docker build -t "${tag}" -f "${containerfile}" "$@" "${context_dir}"
    else
        echo "Error: Neither buildah, podman, nor docker is installed." >&2
        exit 1
    fi
}

echo "1/2 Building Hub Auth-Gateway image: ${GATEWAY_IMAGE}"
run_container_build \
    "${GATEWAY_IMAGE}" \
    "${REPO_ROOT}/hub/gateway/Containerfile" \
    "${REPO_ROOT}/hub/gateway"

STAGE_DIR="$(mktemp -d)"
cleanup() {
    rm -rf "${STAGE_DIR}"
}
trap cleanup EXIT

mkdir -p "${STAGE_DIR}/hub/ui" "${STAGE_DIR}/shared"
cp -a "${REPO_ROOT}/hub/imageroot" "${STAGE_DIR}/hub/imageroot"
cp -a "${REPO_ROOT}/hub/ui/dist" "${STAGE_DIR}/hub/ui/dist"
cp -a "${REPO_ROOT}/shared/rules" "${STAGE_DIR}/shared/rules"
cp -a "${REPO_ROOT}/shared/dashboards" "${STAGE_DIR}/shared/dashboards"
cp -a "${REPO_ROOT}/shared/alloy-templates" "${STAGE_DIR}/shared/alloy-templates"

# Ensure staged defaults.env matches custom REPO_OWNER / IMAGE_ORG namespace
sed -i "s|^CENTRAL_MONITORING_HUB_GATEWAY_IMAGE=.*|CENTRAL_MONITORING_HUB_GATEWAY_IMAGE=${GATEWAY_IMAGE}|" \
    "${STAGE_DIR}/hub/imageroot/etc/defaults.env"

echo "2/2 Building NS8 Hub Module image: ${HUB_IMAGE}"
run_container_build \
    "${HUB_IMAGE}" \
    "${REPO_ROOT}/hub/Containerfile" \
    "${STAGE_DIR}" \
    --build-arg "GATEWAY_IMAGE=${GATEWAY_IMAGE}"

if [[ -n "${GITHUB_OUTPUT:-}" ]]; then
    printf 'images=%s %s\n' "${GATEWAY_IMAGE}" "${HUB_IMAGE}" >> "${GITHUB_OUTPUT}"
fi

echo "Successfully built:"
echo "  - ${GATEWAY_IMAGE}"
echo "  - ${HUB_IMAGE}"
