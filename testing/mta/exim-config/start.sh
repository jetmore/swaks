#!/bin/bash

# can pass args directly through to exim, like:
# ./start.sh -DPROXY=true

# Turn proxy on:
# -DPROXY=true

# turn on tls-on-connect
# -tls-on-connect

# turn on required verification of client certs
# -DVERIFY_CLIENT_CERT=true -DVERIFICATION_CERT=/home/jetmore/Documents/git/swaks/testing/certs/ca.pem
# for chain verification


sudo /home/jetmore/Documents/git/swaks/testing/mta/exim-install/bin/exim -d -bd -oX 1025 $*
