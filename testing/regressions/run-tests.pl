#!/usr/bin/perl

use strict;
use Text::ParseWords;

my $testDir =  shift || die "Please provide the path to the test directory\n";
$testDir    =~ s|/+$||;
my $testRe  =  shift || '.'; # pattern to match test IDs against. Allows to run subset of tests by specifying, eg, '005.'
my $outDir  =  "$testDir/out";

my $tokens = {
	'global' => {
		'%SWAKS%' => 'swaks',
		'%TESTDIR%' => $testDir,
		'%OUTDIR%' => $outDir,
	},
	'local' => {},
};
if ($ENV{TEST_SWAKS}) {
	$tokens->{'global'}{'%SWAKS%'} = $ENV{TEST_SWAKS};
}

if (!-d $outDir) {
	mkdir($outDir) || die "Can't mkdir($outDir): $!\n";
	open(O, ">$outDir/.gitignore") || die "Can't open $outDir/.gitignore for writing: $!\n";
	print O "*\n";
	close(O);
}

opendir(D, $testDir) || die "Couldn't opendir($testDir): $!\n";
my(@testDefs) = grep(/^\d+\.test/, readdir(D));
closedir(D);

my $testIDs = {};
foreach my $testFile (sort @testDefs) {
	my $testObj = readTestFile("$testDir/$testFile");
	if ($testIDs->{$testObj->{id}}) {
		die "saw test id $testObj->{id} more than once\n";
	}
	$testIDs->{$testObj->{id}} = 1;

	next if ($testObj->{id} !~ /$testRe/);

	runTest($testDir, $outDir, $testObj);
}

exit;

sub runTest {
	my $testDir   = shift;
	my $outDir    = shift;
	my $obj       = shift;
	my $allTokens = {};

	# set local tokens (currently only %TESTID% can be set)
	$tokens->{'local'} = { '%TESTID%' => $obj->{'id'} }; # reset the local tokens and set id to the test ID

	# merge tokens into a single hash.  process global before local so that local will win if there are duplicates
	foreach my $tokenType ('global', 'local') {
		foreach my $token (keys(%{$tokens->{$tokenType}})) {
			$allTokens->{$token} = $tokens->{$tokenType}{$token};
		}
	}

	if ($obj->{'pre action'}) {
		foreach my $action (@{$obj->{'pre action'}}) {
			runAction($allTokens, $action);
		}
	}
	if ($obj->{'test action'}) {
		foreach my $action (@{$obj->{'test action'}}) {
			runAction($allTokens, $action);
		}
	}

	# long term I'd like to be able to chain results together. For now, just handle one at a time
	if ($obj->{'test result'}) {
		foreach my $result (@{$obj->{'test result'}}) {
			my $failed = runResult($allTokens, $result);
			if ($failed) {
				print "$testDir/$obj->{id}: FAIL ($failed)\n";
			}
			else {
				print "$testDir/$obj->{id}: PASS\n";
			}
		}
	}
}

sub runResult {
	my $tokens = shift;
	my $test   = shift;

	my($verb, @args) = shellwords(replaceTokens($tokens, $test));

	if ($verb eq 'COMPARE_FILE') {
		if (-f $args[0] && -f $args[1]) {
			open(P, "diff -u $args[0] $args[1] |") || die "Can't run diff: $!\n";
			my $diff = join('', <P>);
			close(P);

			if ($diff) {
				my $diffFile = $tokens->{'%OUTDIR%'} . '/' . $tokens->{'%TESTID%'} . '.diff';
				open(O, ">$diffFile") || die "Can't write to $diffFile: $!\n";
				print O $diff;
				close(O);
				return($diffFile);
			}
			else {
				return(0);
			}
		}
		else {
			return("Can't COMPARE_FILE($args[0], $args[1]), one or both files don't exist");
		}
	}
	else {
		die "Unknown result verb $verb\n";
	}
}

sub runAction {
	my $tokens = shift;
	my $action = shift;

	my($verb, @args) = shellwords(replaceTokens($tokens, $action));

	if ($verb eq 'REMOVE_FILE') {
		unlink(@args);
	}
	elsif ($verb eq 'CMD') {
		system(@args);
	}
	elsif ($verb eq 'MUNGE') {
		if ($args[0] =~ /^file:(.*)$/) {
			my $file  = $1;
			shift(@args);

			my @lines = ();
			open(I, "<$file") || die "Can't open munge file $file\n";
			@lines = <I>;
			close(I);

			foreach my $munge (@args) {
				my($function,@fArgs) = split(',', $munge);
				unshift(@fArgs, '\@lines');
				my $functionCall = "$function(" . join(', ', @fArgs) . ");";
				eval $functionCall;
				if ($@) {
					die "Couldn't run $munge: $@\n";
				}
			}
			munge_general(\@lines, '.?', $tokens->{'%SWAKS%'}, '%SWAKS_COMMAND%');

			open(O, ">$file") || die "Couldn't write to $file\n";
			print O join('', @lines);
			close(O);
		}
		else {
			die "MUNGE verb seen but no associated file\n";
		}
	}
	else {
		die "Unknown action verb $verb\n";
	}
}

sub replaceTokens {
	my $tokens = shift;
	my $action = shift;

	foreach my $token (keys %$tokens) {
		$action =~ s/$token/$tokens->{$token}/g
	}

	return($action);
}

sub readTestFile {
	my $file = shift;
	my $obj  = {};

	open(I, "<$file") || die "Couldn't open $file: $!\n";
	while (defined(my $line = <I>)) {
		chomp();
		if ($line =~ /^([^:]+):\s+(.*)$/) {
			my $testKey = $1;
			my $testArg = $2;
			if ($testKey eq 'id' || $testKey eq 'title') {
				$obj->{$testKey} = $testArg;
			}
			elsif ($testKey eq 'pre action' || $testKey eq 'test action' || $testKey eq 'test result') {
				push(@{$obj->{$testKey}}, $testArg);
			}
			else {
				die "Unknown test key in $file: $testKey\n";
			}
		}
		elsif ($line !~ /^\s*$/ && $line !~ /^\s*#/) {
			die "Unknown line format in $file: $line\n";
		}
	}
	if (!$obj->{id}) {
		if ($file =~ m%([^/]+)\.[^/]+$%) {
			$obj->{id} = $1;
		}
		else {
			die "Couldn't find test id in $file\n";
		}
	}

	return($obj);
}

sub munge_general {
	my $lines    = shift;
	my $consider = shift;
	my $find     = shift;
	my $replace  = shift;

	foreach my $line (@$lines) {
		if ($line =~ /$consider/) {
			$line =~ s/$find/$replace/g;
		}
	}
}

sub munge_globs {
	my $lines    = shift;
	my $consider = shift || '.?';

	munge_general($lines, $consider, 'GLOB\(0x[^\)]+\)', 'GLOB(0xdeadbeef)');
}

sub munge_dates {
	my $lines    = shift;
	my $consider = shift || '.?';

	my $find = '(Sun|Mon|Tue|Wed|Thu|Fri|Sat), '
	         . '\d\d '
	         . '(Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec) '
	         . '\d\d\d\d '
	         . '\d\d:\d\d:\d\d '
	         . '[+-]\d\d\d\d';

	munge_general($lines, $consider, $find, 'Wed, 03 Nov 1999 11:24:29 -0500');
}

sub munge_message_ids {
	my $lines    = shift;
	my $consider = shift || '.?';

	munge_general($lines, $consider, '<\S+@\S+>', '<19991103112429.047942@localhost>');
}
