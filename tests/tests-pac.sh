#!/bin/bash
cd "$(dirname "$0")"

( cd .. && make )

ok=1
echo -n "pac javascript - check localhost:8888/proxy.pac: "
curl localhost:8888/proxy.pac 2>&1 | grep -q "^var FindProxyForURL = " || ok=0
[ $ok = 1 ] && echo -e "\e[32msuccess\e[0m" || echo -e "\e[31merror\e[0m"
