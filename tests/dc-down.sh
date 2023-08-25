#!/bin/bash
set -Eeuo pipefail
cd "$(dirname "$0")"

docker compose -f kpx/docker-compose.yaml down --timeout 0
