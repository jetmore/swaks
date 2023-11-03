#!/usr/bin/env perl

# run all defined tests in headless mode

# - example usage (run all tests.  Print them to STDOUT without prompting for user action. Save to state file):
#  - SWAKS_TEST_SWAKS=../../swaks bin/run-all.pl
# - example usage (only run tests that failed during the last run-all.pl execution):
#  - SWAKS_TEST_SWAKS=../../swaks bin/run-all.pl --errors
# - run just the tests in _exec-transactions
#  - bin/runenv bin/run-all.pl _exec-transactions

# this leaves var/results.* files laying around, should prune them periodically

use strict;
use Cwd qw(realpath);
use FindBin qw($Bin);
use Getopt::Long;

my $opts = {};
GetOptions($opts, 'errors|e!', 'winnow|w!') || die "Couldn't understand options\n";

my $pattern = shift || '^_';

my $home     = realpath("$Bin/..");
my $runTests = "$home/bin/run-tests.pl";

opendir(D, $home) || die "Couldn't opendir $home: $!\n";
my @tests = grep /$pattern/, readdir(D);
closedir(D);

if (!scalar(@tests)) {
	die "No test suites matching pattern $pattern\n";
}

my $vard = "$home/var";
if (!-d $vard) {
	mkdir($vard) || die "Couldn't make $vard: $!\n";
}

my $nextfile = "$vard/results." . time();
my $prevfile;

if ($opts->{errors} || $opts->{winnow}) {
	opendir(DIR, "$vard") || die "Couldn't opendir $home/var\n";
	my $file = (sort(grep(/^results./, readdir(DIR))))[-1]; # get the newest file
	closedir(DIR);

	if ($file) {
		$prevfile = "$vard/$file";
		#print "Using previous results file $prevfile\n";
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
		open(O, ">>$nextfile"); close(O); # ensure the next file will exist even if the test run doesn't create it
	}
	else {
		@testCmd = (                                   '--headless', '--outfile', $nextfile);
		open(O, ">>$nextfile"); close(O); # ensure the next file will exist even if the test run doesn't create it
	}
	@testCmd = ($runTests, @testCmd, $test);
	#print "executing ", join(' ', @testCmd), "\n";
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
	print "results: $nextfile\n";
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

