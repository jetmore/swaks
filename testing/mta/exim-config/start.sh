#!/bin/bash

# can pass args directly through to exim, like:
# ./start.sh -DPROXY=true

# Turn proxy on:
# -DPROXY=true

# turn on tls-on-connect
# -tls-on-connect

sudo /home/jetmore/Documents/git/swaks/testing/mta/exim-install/bin/exim -d -bd -oX 1025 $*
