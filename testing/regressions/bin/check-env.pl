#!/usr/bin/env perl

if (length($ENV{'PAGER'}) && findpath($ENV{'PAGER'})) {
	print "ok  PAGER ($ENV{'PAGER'})\n";
}
else {
	print "NOK Your PAGER environment variable is empty or doesn't point to a valid command.  Setting it to a valid pager is not required but can make viewing diffs much easier\n";
}

if (my $perl = findpath('perl')) {
	print "ok  perl ($perl)\n";
}
else {
	print "NOK perl must be installed and in your path\n";
}

my $swaksScript;
if (length($ENV{'TEST_SWAKS'})) {
	if (my $swaks = findpath($ENV{'TEST_SWAKS'})) {
		print "ok  swaks (TEST_SWAKS -> $swaks)\n";
		$swaksScript = $swaks;
	}
	else {
		print "NOK Tests will use $ENV{'TEST_SWAKS'} from TEST_SWAKS, but that is not valid\n";
	}
}
elsif (my $swaks = findpath('swaks')) {
	print "ok  swaks (PATH -> $swaks) (NOTE: this is found via PATH, consider setting TEST_SWAKS to be more explicit for testing\n";
	$swaksScript = $swaks;
}
else {
	print "NOK swaks not found in either TEST_SWAKS or PATH\n";
}

if (my $expect = findpath('expect')) {
	print "ok  expect ($expect)\n";
}
else {
	print "NOK expect must be installed and in your path\n";
}

if (my $perldoc = findpath('perldoc')) {
	print "ok  perldoc ($perldoc)\n";
}
else {
	print "NOK perldoc must be installed and in your path\n";
}

if ($swaksScript) {
	my $support = `$swaksScript --support 2>&1`;
	if ($support =~ /not available/) {
		print "NOK swaks must have all optional modules installed to run test script (see $swaksScript --support)\n";
		if ($support =~ /requires Authen::NTLM/) {
			print "    (note that Authen::NTLM support can be faked by setting PERL5LIB to lib/authen-ntlm-local)\n";
		}
	}
	else {
		print "ok  swaks optional modules\n";
	}
}
else {
	print "NOK Can't check swaks --support since no valid swaks was found\n";
}



exit;

sub findpath {
	my $find = shift;
	return $find if ($find =~ m|/| && -f $find && -x _);

	foreach my $dir ((split(':', $ENV{PATH}))) {
		$dir =~ s|/$||g;
		return "$dir/$find" if (-f "$dir/$find" && -x _);
	}

	return '';
}

