#!/bin/bash

   # 60 --tls-verify-ca   FAIL (bad  ca, bad  host)
   # 61 --tls-verify-ca   FAIL (bad  ca, good host)
   # 62 --tls-verify-ca   PASS (good ca, bad  host)
   # 63 --tls-verify-ca   PASS (good ca, good host)
   # 64 --tls-verify-host FAIL (bad  ca, bad  host)
   # 65 --tls-verify-host PASS (bad  ca, good host)
   # 66 --tls-verify-host FAIL (good ca, bad  host)
   # 67 --tls-verify-host PASS (good ca, good host)
   # 68 --tls-verify      FAIL (bad  ca, bad  host)
   # 69 --tls-verify      FAIL (bad  ca, good host)
   # 70 --tls-verify      FAIL (good ca, bad  host)
   # 71 --tls-verify      PASS (good ca, good host)

VERIFY=$1      # like "" / --tls-verify / --tls-verify-ca / --tls-verify-host
CA=$2          # like "" / ../certs/ca.pem / ../certs/ca-other.pem
TARGET=$3      # like "" / node.example.com / signed.example.com / etc
SERVER_CERT=$4 # like node.example.com / signed.example.com / etc

if [ "X" != "X$CA" ] ; then
  CA="--tls-ca-path $CA"
fi
if [ "X" != "X$TARGET" ] ; then
  TARGET="--tls-verify-target $TARGET"
fi


SILENT_SERVER="--silent"
SILENT_CLIENT="--silent"

# VERIFY="--tls-verify-ca"
# CA="--tls-ca-path ../certs/ca-other.pem"
# TARGET=signed.example.com
# SERVER_CERT=node.example.com
# echo "#### 60 --tls-verify-ca   FAIL (bad  ca, bad  host)"
# echo "#### EXPECT: server certificate did not match target host signed.example.com, server certificate not signed by known CA"
../../swaks $SILENT_CLIENT --to user@host1.nodns.test.swaks.net --from recip@host1.nodns.test.swaks.net --helo hserver \
  --tls --quit tls \
  $VERIFY \
  $CA \
  $TARGET \
  --pipe "../server/smtp-server.pl $SILENT_SERVER --domain pipe \
    --cert ../certs/$SERVER_CERT.crt --key ../certs/$SERVER_CERT.key \
    part-0000-connect-standard.txt \
    part-0101-ehlo-all.txt \
    part-0200-starttls-basic.txt \
    part-3000-shutdown-accept.txt \
  "
echo
