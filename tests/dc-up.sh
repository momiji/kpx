#!/bin/bash
set -Eeuo pipefail
cd "$(dirname "$0")"

( cd .. && make fast )
docker compose -f kpx/docker-compose.yaml up --build --force-recreate --timeout 0 "$@"
