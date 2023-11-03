#!/bin/sh

#CERT=signed.example.com
#CERT=san-only.example.com

CERT=$1
if [ "X" != "X$2" ] ; then
  CA="--tls-ca-path ../certs/ca.pem"
fi

SILENT_SERVER="--silent"
SILENT_CLIENT="--silent 3"

# echo "#### inet / $CERT / $CA"
# ../server/smtp-server.pl $SILENT_SERVER -p 8126 -i 127.0.0.1 -d inet \
#   --cert ../certs/$CERT.crt \
#   --key ../certs/$CERT.key \
#   part-0000-connect-standard.txt part-0101-ehlo-all.txt part-0200-starttls-basic.txt part-3000-shutdown-accept.txt &

# ../../swaks $SILENT_CLIENT --to user@host1.nodns.test.swaks.net --from recip@host1.nodns.test.swaks.net --helo hserver \
#   --server 127.0.0.1:8126 \
#   --tls --quit tls \
#   --tls-verify-target $CERT $CA

# echo "#### unix / $CERT / $CA"
# ../server/smtp-server.pl $SILENT_SERVER --domain unix --interface _exec-transactions/out-dyn/00254.sock \
#   --cert ../certs/$CERT.crt \
#   --key ../certs/$CERT.key \
#   part-0000-connect-standard.txt part-0101-ehlo-all.txt part-0200-starttls-basic.txt part-3000-shutdown-accept.txt &

# ../../swaks $SILENT_CLIENT --to user@host1.nodns.test.swaks.net --from recip@host1.nodns.test.swaks.net --helo hserver \
#   --socket _exec-transactions/out-dyn/00254.sock \
#   --tls --quit tls \
#   --tls-verify-target $CERT $CA

echo "#### pipe / $CERT / $CA"
../../swaks $SILENT_CLIENT --to user@host1.nodns.test.swaks.net --from recip@host1.nodns.test.swaks.net --helo hserver \
  --tls --quit tls \
  --tls-verify-target $CERT $CA \
  --pipe "../server/smtp-server.pl $SILENT_SERVER --domain pipe \
    --cert ../certs/$CERT.crt --key ../certs/$CERT.key \
    part-0000-connect-standard.txt \
    part-0101-ehlo-all.txt \
    part-0200-starttls-basic.txt \
    part-3000-shutdown-accept.txt \
  "
