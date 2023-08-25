#!/bin/bash
set -Eeuo pipefail
cd "$(dirname "$0")"

( cd .. && make )

# restart docker containers
./dc-up.sh -d

# wait for proxy
while true ; do
  nc 127.0.0.1 8888 -vz 2> /dev/null && break ||:
  sleep 0.1
done

# run all it tests
./tests-basic.sh ||:
./tests-pac.sh ||:
./tests-rewrite.sh ||:

# stop docker containers
./dc-down.sh
