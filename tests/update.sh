#!/bin/bash
set -Eeuo pipefail
cd "$(dirname "$0")"

( cd .. && make )
./dc-up.sh -d client
