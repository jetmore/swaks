#!/bin/bash

USAGE="Usage: $0 [ --signed | --nosigned ] <domain>"
CAFILE=ca

SIGNED=$1
DOMAIN=$2
if [ "x$SIGNED" == "x" ] ; then
    echo $USAGE >&2
    exit 1
fi
if [ "x$DOMAIN" == "x" ] ; then
    DOMAIN=$SIGNED
    SIGNED="--unsigned"
elif [ "$SIGNED" != "--signed" -a "$SIGNED" != "--unsigned" ] ; then
    echo $USAGE >&2
    exit 1
fi

openssl genrsa -out $DOMAIN.key 2048

cat >$DOMAIN.ext << EOM
authorityKeyIdentifier=keyid,issuer
basicConstraints=CA:FALSE
keyUsage = digitalSignature, nonRepudiation, keyEncipherment, dataEncipherment
subjectAltName = @alt_names
[alt_names]
DNS.1 = $DOMAIN
EOM

openssl req -new -key $DOMAIN.key -out $DOMAIN.csr \
    -subj "/C=US/ST=Indiana/O=Swaks Development/CN=$DOMAIN/emailAddress=proj-swaks@jetmore.net"

if [ $SIGNED == "--nosign" ] ; then
    openssl x509 -req -days 3600 -sha256 \
        -in $DOMAIN.csr \
        -out $DOMAIN.crt \
        -signkey $DOMAIN.key \
        -extfile $DOMAIN.ext
else
    openssl x509 -req -days 3600 -sha256 \
        -CA $CAFILE.pem -CAkey $CAFILE.key -CAcreateserial \
        -in $DOMAIN.csr \
        -out $DOMAIN.crt \
        -extfile $DOMAIN.ext
fi

/bin/rm $DOMAIN.ext $DOMAIN.csr

