#!/usr/bin/env perl

# The idea is that if we make a very large breaking change, we might want to bulk-accept all the diffs.  It would work something like this:
# 1) run `run-tests.pl --errors` to get a status on every test (will generate a file var/results.\d+
# 2) manually consider all the changes and verify that only changes we expected were present
# 3) run `bulk-update.pl results.EPOCH`, which will "accept" every change that happened during the results.EPOCH test run

use strict;
use File::Copy;
use File::Spec::Functions qw(:ALL);
use FindBin qw($Bin);

my $file = shift;
my $re   = shift;
my $base = catfile($Bin, '..');

open(I, "<$file") || die "Couldn't read $file: $!\n";
while (my $line = <I>) {
	chomp($line);
	#_exec-output-dump/0302: FAIL (; _exec-output-dump/out-dyn/0302.stdout.diff; _exec-output-dump/out-dyn/0302.exits.diff)
	if ($line !~ /^(\S+): FAIL \((.*)\)$/) {
		next;
	}
	my $test = $1;
	my $errors = $2;
	my @errors = grep { /./ && /$re/ } (split(/; /, $errors));
	# map { print "$_\n"; } (@errors);

	foreach my $dynFile (@errors) {
		$dynFile =~ s/\.diff$//;
		my $refFile = $dynFile;
		if ($refFile !~ s/out-dyn/out-ref/) {
			print STDERR "error accepting $dynFile, doesn't appear ot be in out-dyn\n";
			next;
		}

		print "accepting $dynFile\n";
		if (!copy($dynFile, $refFile)) {
			print STDERR "error accepting $dynFile to $refFile: $!\n";
			next;
		}
	}
}
close(I);
