#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
DATA_DIR="${MINI_SANDBOX_DATA_DIR:-/var/lib/mini-sandbox}"
ROOTFS="${MINI_SANDBOX_ROOTFS:-$DATA_DIR/rootfs}"
if [[ -e "$ROOTFS" ]]; then
    echo "Refusing to overwrite existing rootfs: $ROOTFS" >&2
    exit 1
fi
docker build -f rootfs/Dockerfile -t mini-sandbox-rootfs:local .
container_id="$(docker create mini-sandbox-rootfs:local)"
trap 'docker rm -f "$container_id" >/dev/null 2>&1 || true' EXIT
mkdir -p "$ROOTFS"
docker export "$container_id" | tar -x -C "$ROOTFS" --numeric-owner
echo "Rootfs ready at $ROOTFS"
echo "Verify /usr/bin/python3, /usr/bin/node and /usr/local/bin/mini-sandbox."
