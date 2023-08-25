#!/bin/bash
cd "$(dirname "$0")"

CURL="curl -x 127.0.0.1:8888"

check() {
  echo -n "$1 - check $2/$3 on proxy $4: "
  r=$( $CURL $2/$3 -kv 2>&1 | tr -d '\r' )
  ok=1
  # ensure =X= is present
  [ "$4" != "none" ] && { echo "$r" | grep -q "^=$3=$" || ok=0 ; }
  [ "$4" = "none" ] && { echo "$r" | grep -q "400 Bad Request" || ok=0 ; }
  # ensure kpx-proxy value
  [ -n "$4" -a "$4" != "none" ] && { echo "$r" | grep -q "^< kpx-proxy: $4$" || ok=0 ; }
  # ensure kpx-host value
  [ -n "$5" ] && { echo "$r" | grep -q "^< kpx-host: $5$" || ok=0 ; }
  # result
  [ $ok = 1 ] && echo -e "\e[32msuccess\e[0m" || echo -e "\e[31merror\e[0m"
}

double_check() {
  check "$1 (1)" $2 $3 $4 $5
  check "$1 (2)" $2 $3 $4 $5
}

double_check "simple proxy" http://web1 1 "anon"
double_check "simple proxy" http://web2 2 "basic"
double_check "simple proxy" http://web3 3 "kdc"
double_check "simple proxy" http://web4 4 "socksa"
#double_check "simple proxy" http://web5 5 "socksp"
double_check "direct dns" http://webZ-dns 1 "direct"
double_check "multiple proxy" http://web6 1 "invalid+>basic"
double_check "multiple hosts" http://web7 1 "mbasic" "127.0.0.1:3129"
double_check "none proxy" http://none 1 "none"
