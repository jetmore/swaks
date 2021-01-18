#!/usr/bin/env perl

use strict;
use Getopt::Long;

# --delete - in addition to displaying orphaned files, also delete them
my $opts = {};
GetOptions($opts, 'delete!') || die "Couldn't understand options\n";


if (!scalar(@ARGV)) {
	die "must pass one or more test directories to evaluate\n";
}

foreach my $dir (@ARGV) {
	my %tests = ();
	opendir(D, $dir) || die "couldn't opendir $dir: $!\n";
	foreach my $testfile (grep /^\d+\.test/, readdir(D)) {
		if ($testfile =~ /^(\d+)\.test$/) {
			$tests{$1} = 1;
		}
	}
	closedir(D);

	opendir(D, "$dir/out-ref") || die "Couldn't opendir $dir/out-ref: $!\n";
	foreach my $reffile (grep /\d{4,}/, readdir(D)) {
		if ($reffile =~ /(\d{4,})/) {
			if (!$tests{$1}) {
				if ($opts->{delete}) {
					print "deleting orphaned reference file $dir/out-ref/$reffile\n";
					unlink("$dir/out-ref/$reffile");
				}
				else {
					print "found orphaned reference file $dir/out-ref/$reffile\n";
				}
			}
		}
	}
	closedir(D);
}
