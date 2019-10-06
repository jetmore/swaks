#!/usr/bin/perl

# run all defined tests in headless mode

# - example usage:
#  - TEST_SWAKS=../../swaks bin/run-all.pl


use strict;
use FindBin qw($Bin);

my $home     = "$Bin/..";
my $runTests = "$home/bin/run-tests.pl";

opendir(D, $home) || die "Couldn't opendir $home: $!\n";
my @tests = grep /^_/, readdir(D);
closedir(D);

foreach my $test (sort @tests) {
	system($runTests, '-h', $test);
}
