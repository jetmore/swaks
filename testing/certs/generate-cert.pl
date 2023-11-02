#!/usr/bin/env perl

use strict;
use Getopt::Long;

my $opts = {};
GetOptions($opts, 'signed!', 'expires=i', 'exclude-cn!', 'san:s@') || die "Couldn't understand options\n";
# --signed - sign the cert with our CA.  By default the generated cert will be self-signed
# --expires - number of days from today to expire (DEFAULT: 3600)
# --exclude-cn - don't include the cn in the subject.  By default CN=$domain will be included in the subject
# --san - set argument as subject alternate name
#    - can be provided more than once
#    - by default, SAN will be set to the <domain>.  If --san is provided with no arg, no SAN will be created

my $domain   = shift || die "No domain specified\n";
my $filename = shift || $domain;


my $cafile    = 'ca';
my $signed    = $opts->{signed} || 0;
my $expires   = $opts->{expires} || 3600;
my $includeCn = $opts->{'exclude-cn'} ? 0 : 1;
my @san       = (exists($opts->{san}) && ref($opts->{san})) ? @{$opts->{san}} : ($domain);
@san          = () if (scalar(grep /^$/, @san));

# print "Domain: $domain\n",
#       "Out File: $filename.*\n",
#       "Signed:   $signed\n",
#       "Expires:  $expires\n",
#       "Include CN: $includeCn\n",
#       "SAN:        ", join(', ', @san), "\n";

system(
	'openssl', 'genrsa',
	'-out', "$filename.key",
	'2048'
);

open(O, ">$filename.ext") || die "Couldn't open $filename.ext to write: $!\n";
print O "authorityKeyIdentifier=keyid,issuer\n",
        "basicConstraints=CA:FALSE\n",
        "keyUsage = digitalSignature, nonRepudiation, keyEncipherment, dataEncipherment\n";
if (scalar(@san)) {
	print O "subjectAltName = \@alt_names\n",
	        "[alt_names]\n";

	my $ipCounter  = 1;
	my $dnsCounter = 1;
	foreach my $record (@san) {
		if ($record =~ /:/ || $record =~ /^\d+\.\d+\.\d+\.\d+$/) {
			print O "IP.$ipCounter = $record\n";
			$ipCounter++;
		}
		else {
			print O "DNS.$dnsCounter = $record\n";
			$dnsCounter++;
		}
	}
}
close(O);

my $subject = sprintf("/C=%s/ST=%s/O=%s%s/emailAddress=%s",
                      "US", "Indiana",
                      sprintf("Swaks Development (%s, %sSAN)", $domain, (scalar(@san) ? 'with-' : 'without-')),
                      ($includeCn ? "/CN=$domain" : ''),
                      "proj-swaks\@jetmore.net");

system(
	'openssl', 'req',
	'-new',
	'-key', "$filename.key",
	'-out', "$filename.csr",
	'-subj', $subject
);

my @certArgs = (
	'openssl', 'x509',
	'-req',
	'-days', $expires,
	'-sha256',
	'-in', "$filename.csr",
	'-out', "$filename.crt",
	'-extfile', "$filename.ext"
);

if ($signed) {
	push(@certArgs,
		'-CA', "$cafile.pem",
		'-CAkey', "$cafile.key",
		'-CAcreateserial'
	);
}
else {
	push(@certArgs,
		'-signkey', "$filename.key"
	);
}

system(@certArgs);

unlink("$filename.ext", "$filename.csr");

open(P, "openssl x509 -text -in $filename.crt |") || die "Can't run openssl: $!";
print "    # Signed: ", $signed ? "$cafile.pem" : "NO", "\n";
print "    # Files: $filename.key, $filename.crt\n";
while (my $line = <P>) {
	chomp($line);
	if ($line =~ s/^\s*(Subject:|Not After|X509v3 Subject Alternative Name:|DNS:|IP Address:)/$1/) {
		print "    # $line\n";
	}
	# print "$line\n";
}

__DATA__

#!/bin/bash

USAGE="Usage: $0 [ --signed | --unsigned ] <domain>"
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

if [ $SIGNED == "--unsigned" ] ; then
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

