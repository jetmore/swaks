#!/bin/bash

# test server can use tls if we provide the keys.  This cert isn't special in any way, but don't check it in to git on general principal

openssl genrsa -des3 -passout pass:x -out test.pass.key 2048
openssl rsa -passin pass:x -in test.pass.key -out test.key
/bin/rm test.pass.key
openssl req -new -key test.key -out test.csr -subj /CN=node.example.com
openssl x509 -req -sha256 -days 365 -in test.csr -signkey test.key -out test.crt
/bin/rm test.csr
