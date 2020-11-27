#!/usr/bin/env perl

# run all defined tests in headless mode

# - example usage (run all tests.  Print them to STDOUT without prompting for user action. Save to state file):
#  - TEST_SWAKS=../../swaks bin/run-all.pl
# - example usage (only run tests that failed during the last run-all.pl execution):
#  - TEST_SWAKS=../../swaks bin/run-all.pl --errors

# this leaves var/results.* files laying around, should prune them periodically

use strict;
use FindBin qw($Bin);
use Getopt::Long;

my $opts = {};
GetOptions($opts, 'errors|e!', 'winnow|w!') || die "Couldn't understand options\n";

my $pattern = shift || '^_';

my $home     = "$Bin/..";
my $runTests = "$home/bin/run-tests.pl";

opendir(D, $home) || die "Couldn't opendir $home: $!\n";
my @tests = grep /$pattern/, readdir(D);
closedir(D);

my $vard = "$home/var";
if (!-d $vard) {
	mkdir($vard) || die "Couldn't make $vard: $!\n";
}

my $nextfile = "$vard/results." . time();
my $prevfile;

if ($opts->{errors} || $opts->{winnow}) {
	opendir(DIR, "$home/var") || die "Couldn't opendir $home/var\n";
	my $file = (sort(grep(/^results./, readdir(DIR))))[-1]; # get the newest file
	closedir(DIR);

	if ($file) {
		$prevfile = "$home/var/$file";
	}
	else {
		die "Unable to find a var/results.* file to use for previous errors\n";
	}
}

my %runResults = ();
foreach my $test (sort @tests) {
	my @testCmd = ();
	if ($opts->{errors}) {
		@testCmd = ('--errors', '--infile', $prevfile);
	}
	elsif ($opts->{winnow}) {
		@testCmd = ('--errors', '--infile', $prevfile, '--headless', '--outfile', $nextfile);
	}
	else {
		@testCmd = (                                   '--headless', '--outfile', $nextfile);
	}
	@testCmd = ($runTests, @testCmd, $test);
	system(@testCmd);
	$runResults{$test} = $? >> 8;
}

if (!$opts->{errors}) {
	my $testCount = 0;
	my $results   = {};

	open(I, "<$nextfile") || die "Couldn't read $nextfile: $!\n";
	while (my $line = <I>) {
		$testCount++;
		if ($line =~ /^\S+: ([A-Za-z]+)/) {
			$results->{$1}++;
		}
		else {
			print "no match: $line";
		}
	}

	print "\n";
	print "===============\n";
	my $testSuiteFailures = join(', ', grep { $runResults{$_} != 0; } (keys(%runResults)));
	if ($testSuiteFailures) {
		print "TEST SUITE FAILURES (likely not recorded below): $testSuiteFailures\n";
		print "===============\n";
	}
	foreach my $type (sort keys %$results) {
		printf "%5s: %d\n", $type, $results->{$type};
	}
	print "Total: $testCount\n";
}

