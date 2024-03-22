#!/bin/bash
cd "$(dirname "$0")"

( cd .. && make )

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

# http
CURL="curl -x 127.0.0.1:8888"

double_check "simple proxy" http://web1.example.com 1 "anon"
double_check "simple proxy" http://web2.example.com 2 "basic"
double_check "simple proxy" http://web3.example.com 3 "kdc"
double_check "simple proxy" http://web4.example.com 4 "socksa"
#double_check "simple proxy" http://web5.example.com 5 "socksp"
double_check "direct dns" http://webZ-dns.example.com 9 "direct"
double_check "multiple proxy" http://web6.example.com 6 "invalid+>basic"
double_check "multiple hosts" http://web7.example.com 7 "mbasic" "127.0.0.1:3129"
double_check "none proxy" http://none.example.com 1 "none"

# https
CURL="curl -x 127.0.0.1:8888 --cacert ./certs/ca.pem"

double_check "simple proxy" https://web1s.example.com 1 "anon"
double_check "simple proxy" https://web2s.example.com 2 "basic"
double_check "simple proxy" https://web3s.example.com 3 "kdc"
double_check "simple proxy" https://web4s.example.com 4 "socksa"
#double_check "simple proxy" https://web5.example.com 5 "socksp"
double_check "direct dns" https://webZs-dns.example.com 9 "direct"
double_check "multiple proxy" https://web6s.example.com 6 "invalid+>basic"
double_check "multiple hosts" https://web7s.example.com 7 "mbasic" "127.0.0.1:3129"
double_check "none proxy" https://nones.example.com 0 "none"

# native kerberos
CURL="curl -x 127.0.0.1:8888"
double_check "native kerberos" http://web3.example.com 3 "kdc"
CURL="curl -x 127.0.0.1:8888 --cacert ./certs/ca.pem"
double_check "native kerberos" https://web3s.example.com 3 "kdc"
