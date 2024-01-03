#!/usr/bin/env perl

my $canary = '## STUB CANARY ##';

use FindBin qw($Bin);

open(I, "<$Bin/swaks") || die "Can't open $Bin/swaks: $!\n";
my $swaks = join('', <I>);
close(I);

if ($swaks =~ /$canary/) {
	die "Aborting out of apparent recursive situation\n";
}

eval $swaks;
