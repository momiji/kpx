#!/bin/bash
cd "$(dirname "$0")"

check() {
  echo -n "rewrite ($1) $*: "
  shift
  r=$( curl "$@" 2>&1 | tr -d '\r' )
  ok=1
  # ensure result
  echo "$r" | grep -q "^StoreDir:" || ok=0
  [ $ok = 1 ] && echo -e "\e[32msuccess\e[0m" || echo -e "\e[31merror\e[0m"
}

double_check() {
  check 1 "$@"
  check 2 "$@"
}

double_check http://127.0.0.1:8888/nix-cache-info -H "Host: http/cache.nixos.org"
double_check http://127.0.0.1:8888/nix-cache-info -H "Host: http/cache.nixos.org:80"
double_check http://127.0.0.1:8888/nix-cache-info -H "Host: https/cache.nixos.org"
double_check http://127.0.0.1:8888/nix-cache-info -H "Host: https/cache.nixos.org:443"

double_check http://127.0.0.1:8888/~/http/cache.nixos.org/nix-cache-info
double_check http://127.0.0.1:8888/~/https/cache.nixos.org/nix-cache-info
