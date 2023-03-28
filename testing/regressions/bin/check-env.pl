#!/usr/bin/env perl

use strict;

my @paths = ();
my $pathVarDelim = ':';
my $filePathDelim = '/';
my $filePathDelimRe = quotemeta($filePathDelim);
if ($ENV{PATH} =~ /^[A-Z]:\\/) {
	$pathVarDelim = ';';
	$filePathDelim = '\\';
	$filePathDelimRe = quotemeta($filePathDelim);
}
foreach my $dir ((split(/$pathVarDelim/, $ENV{PATH}))) {
	$dir =~ s|$filePathDelimRe$||g;
	push(@paths, $dir);
}

if ($^O ne 'MSWin32') {
	my $found = 0;
	foreach my $var ('SWAKS_TEST_PAGER', 'PAGER') {
		if (length($ENV{$var}) && findpath($ENV{$var})) {
			print "ok  pager -> $var ($ENV{$var})\n";
			$found = 1;
		}
	}
	if (!$found) {
		print "NOK Could not identify a pager via SWAKS_TEST_PAGER or PAGER.  Setting one of these to a valid pager is not required but can make viewing large diffs much easier\n";
	}
}

if (my $perl = findpath('perl')) {
	print "ok  perl ($perl)\n";
}
else {
	print "NOK perl must be installed and in your path\n";
}

foreach my $module ('Capture::Tiny', 'Text::Diff', 'Proc::Background') {
	if (checkmod($module)) {
		print "ok  $module\n";
	}
	else {
		print "NOK $module perl module must be installed\n";
	}
}

my $swaksScript;
if (length($ENV{'SWAKS_TEST_SWAKS'})) {
	if (my $swaks = findpath($ENV{'SWAKS_TEST_SWAKS'})) {
		print "ok  swaks (SWAKS_TEST_SWAKS -> $swaks)\n";
		$swaksScript = $swaks;
	}
	else {
		print "NOK Tests will use $ENV{'SWAKS_TEST_SWAKS'} from SWAKS_TEST_SWAKS, but that is not valid\n";
	}
}
elsif (my $swaks = findpath('swaks')) {
	print "ok  swaks (PATH -> $swaks) (NOTE: this is found via PATH, consider setting SWAKS_TEST_SWAKS to be more explicit for testing\n";
	$swaksScript = $swaks;
}
else {
	print "NOK swaks not found in either SWAKS_TEST_SWAKS or PATH\n";
}

# I believe this is no longer needed after switch to Pod::Usage
# if (my $perldoc = findpath('perldoc')) {
# 	print "ok  perldoc ($perldoc)\n";
# }
# else {
# 	print "NOK perldoc must be installed and in your path\n";
# }

if ($swaksScript) {
	my $support = `$swaksScript --support 2>&1`;
	if ($support =~ /not available/) {
		print "NOK swaks must have all optional modules installed to run test script (see $swaksScript --support)\n";
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

	foreach my $dir (@paths) {
		foreach my $suff ('', '.pl', '.exe', '.bat') {
			if ($find =~ '/' && $filePathDelim ne '/') {
				$find =~ s|/|$filePathDelim|g;
			}

			my $candidate = $find . $suff;
			return $candidate if ($candidate =~ m|$filePathDelimRe| && -f $candidate);

			$candidate = $dir . $filePathDelim . $candidate;
			return "$candidate" if (-f $candidate && -x _);
		}
	}

	return '';
}

sub checkmod {
	my $module = shift;

	open(P, "|perl") || die "checkmod can't open pipe to perl: $!\n";
	print P "eval(\"use $module;\");\n";
	print P 'if ($@) { exit 1; } else { exit 0; }', "\n";
	if (!close(P)) {
		return(0);
	}

	return(1);
}
