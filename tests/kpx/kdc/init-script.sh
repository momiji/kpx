#!/bin/bash
REALM=${REALM:-EXAMPLE.COM}
SUPPORTED_ENCRYPTION_TYPES=${SUPPORTED_ENCRYPTION_TYPES:-aes256-cts-hmac-sha1-96:normal}
KADMIN_PRINCIPAL=${KADMIN_PRINCIPAL:-kadmin/admin}
KADMIN_PASSWORD=${KADMIN_PASSWORD:-adminpassword}
MASTER_PASSWORD=${MASTER_PASSWORD:-masterpassword}
USER_PRINCIPAL=${USER_PRINCIPAL:-user}
USER_PASSWORD=${USER_PASSWORD:-userpassword}
PROXY_NAME=${PROXY_NAME:-127.0.0.1}

echo "==================================================================================="
echo "==== Kerberos KDC and Kadmin ======================================================"
echo "==================================================================================="
KADMIN_PRINCIPAL_FULL=$KADMIN_PRINCIPAL@$REALM

echo "REALM: $REALM"
echo "KADMIN_PRINCIPAL_FULL: $KADMIN_PRINCIPAL_FULL"
echo "KADMIN_PASSWORD: $KADMIN_PASSWORD"
echo ""

echo "==================================================================================="
echo "==== /etc/krb5.conf ==============================================================="
echo "==================================================================================="
KDC_KADMIN_SERVER=$(hostname -f)
tee /etc/krb5.conf <<EOF
[libdefaults]
default_realm = $REALM

[realms]
$REALM = {
  kdc_ports = 88,750
  kadmind_port = 749
  kdc = $KDC_KADMIN_SERVER
  admin_server = $KDC_KADMIN_SERVER
}
EOF
echo ""

echo "==================================================================================="
echo "==== /etc/krb5kdc/kdc.conf ========================================================"
echo "==================================================================================="
tee /etc/krb5kdc/kdc.conf <<EOF
[realms]
$REALM = {
  acl_file = /etc/krb5kdc/kadm5.acl
  max_renewable_life = 7d 0h 0m 0s
  supported_enctypes = $SUPPORTED_ENCRYPTION_TYPES
  default_principal_flags = +preauth
}
EOF
echo ""

echo "==================================================================================="
echo "==== /etc/krb5kdc/kadm5.acl ======================================================="
echo "==================================================================================="
tee /etc/krb5kdc/kadm5.acl <<EOF
$KADMIN_PRINCIPAL_FULL *
noPermissions@$REALM X
EOF
echo ""

echo "==================================================================================="
echo "==== Creating realm ==============================================================="
echo "==================================================================================="
# This command also starts the krb5-kdc and krb5-admin-server services
krb5_newrealm <<EOF
$MASTER_PASSWORD
$MASTER_PASSWORD
EOF
echo ""

echo "==================================================================================="
echo "==== Creating default principals in the acl ======================================="
echo "==================================================================================="
echo "Adding $KADMIN_PRINCIPAL principal"
kadmin.local -q "delete_principal -force $KADMIN_PRINCIPAL_FULL"
echo ""
kadmin.local -q "addprinc -pw $KADMIN_PASSWORD $KADMIN_PRINCIPAL_FULL"
echo ""

echo "Adding noPermissions principal"
kadmin.local -q "delete_principal -force noPermissions@$REALM"
echo ""
kadmin.local -q "addprinc -pw $KADMIN_PASSWORD noPermissions@$REALM"
echo ""

echo "Adding $USER_PRINCIPAL principal"
kadmin.local -q "delete_principal -force $USER_PRINCIPAL"
echo ""
kadmin.local -q "addprinc -pw $USER_PASSWORD $USER_PRINCIPAL"
echo ""

echo "Adding HTTP/$PROXY_NAME principal"
kadmin.local -q "delete_principal -force HTTP/$PROXY_NAME@$REALM"
echo ""
kadmin.local -q "addprinc -randkey HTTP/$PROXY_NAME@$REALM"
echo ""

krb5kdc
kadmind -nofork
