#!/bin/bash
REALM=${REALM:-EXAMPLE.COM}
KADMIN_PRINCIPAL=${KADMIN_PRINCIPAL:-kadmin/admin}
KADMIN_PASSWORD=${KADMIN_PASSWORD:-adminpassword}
PROXY_NAME=${PROXY_NAME:-127.0.0.1}
USER_PRINCIPAL=${USER_PRINCIPAL:-user}
USER_PASSWORD=${USER_PASSWORD:-userpassword}
MODE=${MODE:-anon}

[ "$MODE" = "anon" ] && {
  cat > /etc/squid/conf.d/proxy.conf <<EOF
http_access allow all
EOF
}

[ "$MODE" = "basic" ] && {
  htpasswd -Bbc /etc/squid/users $USER_PRINCIPAL $USER_PASSWORD
  cat > /etc/squid/conf.d/proxy.conf <<EOF
auth_param basic program /usr/lib/squid/basic_ncsa_auth /etc/squid/users
auth_param basic realm proxy-basic
acl authenticated proxy_auth REQUIRED
http_access allow all authenticated
EOF
}

[ "$MODE" = "krb" ] && {
  cat > /etc/krb5.conf <<EOF
[libdefaults]
default_realm = $REALM
# The following krb5.conf variables are only for MIT Kerberos.
kdc_timesync = 1
ccache_type = 4
forwardable = true
proxiable = true
rdns = false
# The following libdefaults parameters are only for Heimdal Kerberos.
fcc-mit-ticketflags = true

[realms]
$REALM = {
  kdc = kdc
  admin_server = kdc
}

[domain_realm]
.${REALM,,} = $REALM
${REALM,,} = $REALM

[logging]
kdc = FILE:/var/log/kdc.log
admin_server = FILE:/var/log/kadmin.log
default = FILE:/var/log/krb5lib.log
EOF
  while true ; do
    echo "waiting for kdc..."
    nc kdc 88 -vz && break
    sleep 1
  done
  while [ ! -f /etc/squid/HTTP.keytab ]; do
    kadmin -w $KADMIN_PASSWORD -p $KADMIN_PRINCIPAL@$REALM -q "ktadd -k /etc/squid/HTTP.keytab HTTP/$PROXY_NAME@$REALM" || sleep 1
  done
  chmod 644 /etc/squid/HTTP.keytab
  klist -k /etc/squid/HTTP.keytab
  cat > /etc/squid/conf.d/proxy.conf <<EOF
auth_param negotiate program /usr/lib/squid/negotiate_kerberos_auth -k /etc/squid/HTTP.keytab -s HTTP/$PROXY_NAME@$REALM
auth_param negotiate realm proxy-basic
acl authenticated proxy_auth REQUIRED
http_access allow all authenticated
#debug_options ALL,1
EOF
}

[ "$MODE" = "client" ] && {
  cat > /etc/krb5.conf <<EOF
[libdefaults]
default_realm = $REALM
# The following krb5.conf variables are only for MIT Kerberos.
kdc_timesync = 1
ccache_type = 4
forwardable = true
proxiable = true
rdns = false
# The following libdefaults parameters are only for Heimdal Kerberos.
fcc-mit-ticketflags = true

[realms]
$REALM = {
  kdc = kdc
  admin_server = kdc
}

[domain_realm]
.${REALM,,} = $REALM
${REALM,,} = $REALM

[logging]
kdc = FILE:/var/log/kdc.log
admin_server = FILE:/var/log/kadmin.log
default = FILE:/var/log/krb5lib.log
EOF
  while true ; do
    echo "waiting for kdc..."
    nc kdc 88 -vz && break
    sleep 1
  done
  while [ ! -f /etc/krb5.keytab ]; do
    kadmin -w $KADMIN_PASSWORD -p $KADMIN_PRINCIPAL@$REALM -q "ktadd -k /etc/krb5.keytab user" || sleep 1
  done
  kinit -k user
  exit 0
}

echo "Starting squid..."
squid --foreground # -X -d 1
