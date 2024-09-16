#!/bin/bash
cd "$(dirname "$0")"

( cd .. && make )

check() {
  title=$1
  res=$2
  shift 2
  echo -n "$title - curl $*: "
  r=$( "$@" 2>&1 | tr -d '\r' )
  ok=1
  # ensure result
  echo "$r" | grep -q "^=$res=$" || ok=0
  [ $ok = 1 ] && echo -e "\e[32msuccess\e[0m" || echo -e "\e[31merror\e[0m"
}

check "socks server anon" 4 curl -x socks5h://127.0.0.1:1080 http://web4.example.com/4
check "socks server pass" 5 curl -x socks5h://socks:sockspassword@127.0.0.1:1081 http://web5.example.com/5

check "socks proxy anon" 4 curl -x socks5h://127.0.0.1:8890 http://web4.example.com/4
check "socks proxy pass" 5 curl -x socks5h://127.0.0.1:8890 http://web5.example.com/5

check "socks proxy dns" 1 curl -x socks5h://127.0.0.1:8890 http://web1.example.com/1

rc=1
curl -x socks5h://127.0.0.1:8890 http://google.com -v 2>&1 | sed -n "/^<.Location:/p" | tail -1 | grep -q google.com || rc=0
check "socks proxy direct" $rc echo =1=
