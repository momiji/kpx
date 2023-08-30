#!/bin/bash
set -Eeuo pipefail
cd "$(dirname "$0")"

cd ..
make
docker compose -f ./tests/kpx/docker-compose.yaml restart client -t 0

max=2
while (( $max > 0 )) ; do
  nc 127.0.0.1 8888 -vz &> /dev/null && break
  sleep 0.5
done

exit 0
