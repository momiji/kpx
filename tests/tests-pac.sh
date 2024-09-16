#!/bin/bash
cd "$(dirname "$0")"

( cd .. && make )

pac=$( cat <<\EOF

var FindProxyForURL = function(profiles) {
  return function(url, host) {
    "use strict";
    var index = 0, result = null, direct = null;
    do {
      result = profiles[index++];
      if (typeof result === "function") {
        result = result(url, host);
        if (result === "CONTINUE") { direct = result; result = null; }
      }
    } while (typeof result !== "string" && index < profiles.length);
    if (result != null) return result;
    if (direct != null) return "DIRECT";
    return "PROXY 127.0.0.1:1";
  }
}([
function(url, host) {
  "use strict";
  if (/^web1.*$/.test(host)) return "PROXY 127.0.0.1:3128";
  if (/^web2.*$/.test(host)) return "PROXY 127.0.0.1:8888";
  if (/^web3.*$/.test(host)) return "PROXY 127.0.0.1:8888";
  if (/^web4.*$/.test(host)) return "SOCKS 127.0.0.1:1080";
  if (/^web5.*$/.test(host)) return "PROXY 127.0.0.1:8888";
  if (/^web6.*$/.test(host)) return "PROXY 127.0.0.1:8888";
  if (/^web7.*$/.test(host)) return "PROXY 127.0.0.1:8888";
  if (/^none.*$/.test(host)) return "PROXY 127.0.0.1:8888";
  if (/^cache\.nixos\.org$/.test(host)) return "PROXY 127.0.0.1:3128";
  if (/^.*$/.test(host)) return "PROXY 127.0.0.1:8888";
  return null;
},
null
]);
EOF
)
sha=$( echo "$pac" | sha256sum )

ok=1
echo -n "pac javascript - check 127.0.0.1:8888/proxy.pac: "
curl 127.0.0.1:8888/proxy.pac -s | sha256sum 2>&1 | grep -q "^$sha$" || ok=0
[ $ok = 1 ] && echo -e "\e[32msuccess\e[0m" || echo -e "\e[31merror\e[0m"
