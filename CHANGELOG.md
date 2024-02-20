
## [1.7.1](https://github.com/momiji/kpx/compare/v1.7.0...v1.7.1) (2024-02-20)

* Merge remote-tracking branch 'origin/main' [e001a8c1](https://github.com/momiji/kpx/commit/e001a8c1e6cfcaea4642bb56e45f41456324fece)
* fix: add missing NoKerberos for non supported OS [a307dcbd](https://github.com/momiji/kpx/commit/a307dcbd9a9e2bc2ee38d2bbca077268f0d90236)


## [1.7.0](https://github.com/momiji/kpx/compare/v1.6.1...v1.7.0) (2024-02-20)

* fix: upgrade dependencies [5dbc89de](https://github.com/momiji/kpx/commit/5dbc89dee678ed7f485486b0a46009598e1785a9)
* feat: add native kerberos for windows/linux [fb9613b7](https://github.com/momiji/kpx/commit/fb9613b7c931a05bbf6e59492b520624ab661e90)
* fix: flush async logs before asing for login/password [d4b51680](https://github.com/momiji/kpx/commit/d4b51680ae3fc1210f91881d857c70e5996632b1)
* fix: errors messages [ec0a45b2](https://github.com/momiji/kpx/commit/ec0a45b23ba6ea819ee150e01e561215482d3d5b)


## [1.6.1](https://github.com/momiji/kpx/compare/v1.6.0...v1.6.1) (2024-01-30)



## [1.6.0](https://github.com/momiji/kpx/compare/v1.5.5...v1.6.0) (2024-01-30)

* feat: experimental connection-pools and hosts-cache [4bbd1caa](https://github.com/momiji/kpx/commit/4bbd1caabd234103f29e3419e733284344de2ba9)


## [1.5.5](https://github.com/momiji/kpx/compare/v1.5.4...v1.5.5) (2023-11-22)

* fix: invalid build script [49910222](https://github.com/momiji/kpx/commit/49910222995f12e068c7a70fa9fe02b4f55ba220)


## [1.5.4](https://github.com/momiji/kpx/compare/v1.5.3...v1.5.4) (2023-11-22)

* fix: allow multiple pac encoding [b18c99f9](https://github.com/momiji/kpx/commit/b18c99f9230413710134d1084bd06e176dbfc4f3)


## [1.5.3](https://github.com/momiji/kpx/compare/v1.5.2...v1.5.3) (2023-08-30)

* fix: add missing log flush [5e1d5551](https://github.com/momiji/kpx/commit/5e1d55514a2ee9ac2561f49829407d59fa8fe5ba)


## [1.5.2](https://github.com/momiji/kpx/compare/v1.5.1...v1.5.2) (2023-08-30)

* fix: disable auto-update for versions 'dev*' instead of 'dev' [0bf6d7c1](https://github.com/momiji/kpx/commit/0bf6d7c173ee278d3430c4f5505a05d49759576a)


## [1.5.1](https://github.com/momiji/kpx/compare/v1.5.0...v1.5.1) (2023-08-29)

* fix: vacuum for connection pool and closed connection detection [18a5bc7e](https://github.com/momiji/kpx/commit/18a5bc7e04f56df56d9bca929607efb64a690257)
* fix: directToConnect connections (https rewrite) cannot be reused [0f521dd9](https://github.com/momiji/kpx/commit/0f521dd9ad2ff8c64d427df7919a3c0b7b81fb3e)


## [1.5.0](https://github.com/momiji/kpx/compare/v1.4.9...v1.5.0) (2023-08-25)

* initial commit in github [f943114c](https://github.com/momiji/kpx/commit/f943114ccec51bf77e875da9c47ce0668059ca27)
* Initial commit [56cf03bb](https://github.com/momiji/kpx/commit/56cf03bb64a49b131463ee438455c9deaa9e5b7b)



---

## [1.4.9](https://github.com/momiji/kpx/compare/v1.4.8...v1.4.9) (2023-08-11)

* fix: change error message on logger creation failure ([df4f4a6](https://github.com/momiji/kpx/commit/df4f4a6b43cd2796b6758e6501c0c450304f9503))
* fix: change log to async go-logging ([f214b9d](https://github.com/momiji/kpx/commit/f214b9d682f87d7e1278946ec75d67b6133a0cfc))
* fix: limit conn reuse to same host to prevent authenticationrequired ([966d82f](https://github.com/momiji/kpx/commit/966d82fa9363415143e13fe862332ca1ad203ffe))
* fix: refactor conn reuse for http to fix issues on Windows (http2demo) ([70ab0a9](https://github.com/momiji/kpx/commit/70ab0a910156cefb01fd9d2b04e5d51fa58668e6))


## [1.4.8](https://github.com/momiji/kpx/compare/v1.4.7...v1.4.8) (2023-07-07)

* fix: disable auto-update with interactive user/pass ([f6004f1](https://github.com/momiji/kpx/commit/f6004f1e2a4606cb1c6764df571fa408a6e5c2ea))


## [1.4.7](https://github.com/momiji/kpx/compare/v1.4.6...v1.4.7) (2023-07-07)

* fix: use relative url with socks proxy ([0b45f78](https://github.com/momiji/kpx/commit/0b45f786ca3baa3bd4f56b41282a2c3a1dba5fad))


## [1.4.6](https://github.com/momiji/kpx/compare/v1.4.5...v1.4.6) (2023-07-06)

* fix: missing proxy auth on resued connections (keep-alive) ([e78d12e](https://github.com/momiji/kpx/commit/e78d12e4bd3e72d6572d36738366626d72fb25fa))


## [1.4.5](https://github.com/momiji/kpx/compare/v1.4.4...v1.4.5) (2023-06-30)

* fix: missing return and "no update" message ([480057c](https://github.com/momiji/kpx/commit/480057c3e21bd70708012da9c0185e944124d744))


## [1.4.4](https://github.com/momiji/kpx/compare/v1.4.3...v1.4.4) (2023-06-28)

* fix: add config file watcher ([93b27a0](https://github.com/momiji/kpx/commit/93b27a0176101c1745c5eec08e9f8e3dae8c6436))


## [1.4.3](https://github.com/momiji/kpx/compare/v1.4.2...v1.4.3) (2023-06-27)

* fix: refactor usage, help and version ([a643289](https://github.com/momiji/kpx/commit/a643289dd78fce4e2d990377dadc23bd8fc63b88))


## [1.4.2](https://github.com/momiji/kpx/compare/v1.4.1...v1.4.2) (2023-06-27)

* fix: close connections on forever pipes, preventing client waiting while target is closed ([26c76b3](https://github.com/momiji/kpx/commit/26c76b3371593ec7d43cc18cbe7971205fad52b9))
* fix: refactor trace logs ([3259984](https://github.com/momiji/kpx/commit/32599845a6c629ef46ff3e3a34550a15b2f682f4))


## [1.4.1](https://github.com/momiji/kpx/compare/v1.4.0...v1.4.1) (2023-06-26)

* fix: change update messages ([ad423fb](https://github.com/momiji/kpx/commit/ad423fb8391395cbbc61d4e29926941af09e4a9f))


## [1.4.0](https://github.com/momiji/kpx/compare/v1.3.6...v1.4.0) (2023-06-26)

* feat: refactor update mechanism ([80f5550](https://github.com/momiji/kpx/commit/80f5550fb396ad0c2dc0758304b6fd77557be1d4))


## [1.3.6](https://github.com/momiji/kpx/compare/v1.3.5...v1.3.6) (2023-06-26)

* fix: disable auto-update for "dev" version ([2844f85](https://github.com/momiji/kpx/commit/2844f856eb5aeb593d55ece610b4aed9a39a51e7))
* fix: manager decrypt password error ([02e8b04](https://github.com/momiji/kpx/commit/02e8b048910e63cb797c4bf5abc5ddd700b8eb7a))
* fix: refactor multiple proxies/hosts ([d31bed6](https://github.com/momiji/kpx/commit/d31bed6232a69699bdc07ef0e97510ec31f0cbf6))


## [1.3.5](https://github.com/momiji/kpx/compare/v1.3.4...v1.3.5) (2023-06-08)

* fix: restart exit code = 200 ([5fab66c](https://github.com/momiji/kpx/commit/5fab66cae18cb458022033bdad822c390e87475c))


## [1.3.4](https://github.com/momiji/kpx/compare/v1.3.3...v1.3.4) (2023-06-08)

* fix: delete old updates ([b9149c3](https://github.com/momiji/kpx/commit/b9149c3852789bcb75a05bdec3d5fcc2196d2d5f))


## [1.3.3](https://github.com/momiji/kpx/compare/v1.3.2...v1.3.3) (2023-06-08)

* fix: delete old updates ([3850fdf](https://github.com/momiji/kpx/commit/3850fdf2d476076483c16e70f6eeb028b05df31f))


## [1.3.2](https://github.com/momiji/kpx/compare/v1.3.1...v1.3.2) (2023-06-08)

* fix: typos ([d2dc716](https://github.com/momiji/kpx/commit/d2dc716ba0194147e13dd0a7e701d43a3c773b3a))


## [1.3.1](https://github.com/momiji/kpx/compare/v1.3.0...v1.3.1) (2023-06-08)

* fix: automatic update ([b627b17](https://github.com/momiji/kpx/commit/b627b17431590f0cf83cf559a813637e5b843e40))


## [1.3.0](https://github.com/momiji/kpx/compare/v1.2.0...v1.3.0) (2023-06-08)

* feat: add automatic update ([4571a5f](https://github.com/momiji/kpx/commit/4571a5fac1b334d61125348771d9a21f280bace5))


## [1.2.0](https://github.com/momiji/kpx/compare/v1.1.0...v1.2.0) (2023-06-07)

* fix: add gencerts to config ([f943783](https://github.com/momiji/kpx/commit/f9437833cc39af01a761dec3649d931c047847cc))
* fix: add mitm option ([3f21aa1](https://github.com/momiji/kpx/commit/3f21aa1dca16a8822767bd3ee9e6f8c19f958e3b))
* fix: typos ([35e8d18](https://github.com/momiji/kpx/commit/35e8d189f24ca9e31e7a52c9afab3792d9080cac))
* feat: add mitm option ([60d9114](https://github.com/momiji/kpx/commit/60d9114eaaac2de31a630ca5bb114206c09f7a10))


## [1.1.0](https://github.com/momiji/kpx/compare/v1.0.2...v1.1.0) (2023-05-03)

* feat: allow cross-domain to work by fixing krb5 library ([6bcf175](https://github.com/momiji/kpx/commit/6bcf175173b9a303de3278bc02cd5d8d3bee21db))


## [1.0.2](https://github.com/momiji/kpx/compare/v1.0.1...v1.0.2) (2023-03-14)

* fix: fix semantic-release config ([6a4f03f](https://github.com/momiji/kpx/commit/6a4f03f0d923e8f0c7d2cc51ab61b1d0982cd4d2))


## [1.0.1](https://github.com/momiji/kpx/compare/v1.0.0...v1.0.1) (2023-03-14)

* fix: update go dependencies ([321b14a](https://github.com/momiji/kpx/commit/321b14a42400e47ae14fcc72d39dbee464e911b9))
* fix: update help config sample to use new PAC url ([a28b105](https://github.com/momiji/kpx/commit/a28b10558cfc2eb4bb132b783a9e021a442bd5fd))


## [1.0.0]() (2023-03-14)

- REFACTOR: moving to sgithub


---

## 2023-01-10 - rework direct access with altered host (release candidate)

- FEAT: new direct access with `Host: proto/host[:port]` header or `/~/proto/host[:port]/...` url
- FIX: swap << and >> in logs
- FIX: better Now using proxy/host log for multiple proxies/hosts
- FEAT: add automatic tests


## 2022-11-30 - fix header logs

- FIX: header logs issue - slice bounds out of range \[:35\] with length 31


## 2022-11-07 - fix logs with %s formats

- FIX: logs containing formats were evaluated instead of printed


## 2022-09-20 - fix HTTP/1.1 keep-alive for WSUS

- FIX: close connection on HTTP/1.1 when proxy does not send keep-alive, for Windows Update through mutiple proxies


## 2022-09-19 - add direct access with altered host

- FIX: correct url when used in direct (not as a proxy) with url other than /proxy.pac, using Host header


## 2022-09-09 - upgrade go version/deps

- BUILD: update dependencies and build with go 1.18.5


## 2022-08-24 - automatic kill and verbose on CLI

- FEAT: automatic verbose (-v) when used without configuration file
- FEAT: automatic timeout after 1h (or --timeout) when used without configuration file
- BUILD: update dependencies and build with go 1.17.6


## 2022-02-02 - fix long running connections

- FIX: change request timeout to 0 for long running downloads
- FEAT: add HA support in proxy rules and hosts
- BUILD: update dependencies and build with go 1.16.2


## 2021-06-28 - multiple hosts HA

- FEAT: add HA support in rules - experimental
- BUILD: update dependencies and build with go 1.16.2


## 2020-11-04 - fix missing krb realm

- FIX: missing proxy auth realm
- BUILD: update dependencies and build with go 1.16.2


## 2020-05-25 - pac and encrypted password

- FEAT: publish proxy pac as /proxy.pac
- FEAT: add proxy pac support
- FEAT: add encrypted password to configuration file
- BUILD: update dependencies and build with go 1.16.2


## 2020-05-08 - initial port from java

First version, port from actual java code.

