## Test kerberos integration in squid

Certs can be generated using this command:

```shell
$ docker run --rm -it -e CA_EXPIRE=36000 -e SSL_EXPIRE=36000 -e SSL_DNS="*.example.com" -v $PWD/certs:/certs paulczar/omgwtfssl
...

$ openssl x509 -text -noout -in ./certs/cert.pem | grep DNS:
                DNS:*.example.com, DNS:example.com
```

This must be run from inside squid container:

```shell
$ docker exec -it kpx-krb-1 bash
```

Then:

```shell
# login to kerberos server
$ kinit kadmin/admin

# generate a token 
$ /usr/lib/squid/negotiate_kerberos_auth_test 127.0.0.1
Token: YII...

# test the token
$ /usr/lib/squid/negotiate_kerberos_auth -k /etc/squid/HTTP.keytab -s HTTP/127.0.0.1@EXAMPLE.COM -d
YR YII
2023/08/24 21:46:20| negotiate_kerberos_auth: ERROR: krb5_pac_get_buffer: No such file or directory
OK token=oRQwEqADCgEAoQsGCSqGSIb3EgECAg== user=kadmin/admin@EXAMPLE.COM group=
```
