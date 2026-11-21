#!/usr/bin/env bash
# Execute NethServer 8 Robot Framework integration tests against a live NS8 leader node
# Usage: bash hub/test-module.sh <LEADER_NODE> [IMAGE_URL]

set -euo pipefail

LEADER_NODE="${1:-}"
IMAGE_URL="${2:-ghcr.io/nethserver/central-monitoring-hub:latest}"
SSH_KEYFILE="${SSH_KEYFILE:-${HOME}/.ssh/id_rsa}"

if [[ -z "${LEADER_NODE}" ]]; then
    echo "Usage: $0 <LEADER_NODE> [IMAGE_URL]" >&2
    exit 1
fi

if [[ ! -f "${SSH_KEYFILE}" ]]; then
    echo "SSH keyfile not found: ${SSH_KEYFILE}" >&2
    exit 1
fi

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
OUTPUT_DIR="${SCRIPT_DIR}/test-outputs"
mkdir -p "${OUTPUT_DIR}"

CONTAINER_ENGINE="podman"
if ! command -v podman >/dev/null 2>&1; then
    CONTAINER_ENGINE="docker"
fi

"${CONTAINER_ENGINE}" run --rm \
    --network=host \
    --volume "${SSH_KEYFILE}:/id_rsa:ro,Z" \
    --volume "${SCRIPT_DIR}/tests:/home/pwuser/ns8-module/tests:ro,Z" \
    --volume "${OUTPUT_DIR}:/home/pwuser/outputs:Z" \
    ghcr.io/nethserver/robotframework:latest \
    robot \
        -v "NODE_ADDR:${LEADER_NODE}" \
        -v "IMAGE_URL:${IMAGE_URL}" \
        -v "SSH_KEYFILE:/id_rsa" \
        --name central-monitoring-hub \
        --outputdir /home/pwuser/outputs \
        /home/pwuser/ns8-module/tests
