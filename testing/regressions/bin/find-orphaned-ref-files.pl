#!/usr/bin/env perl

foreach my $dir (@ARGV) {
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
				print "Couldn't find test file for ref file $dir/out-ref/$reffile\n";
			}
		}
	}
	closedir(D);
}
